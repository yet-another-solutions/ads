"""Two-leg HTTP/1.1 request owner, with authorization before upstream bytes.

The connector receives only the immutable original destination. For HTTPS it
returns the SAME inspected origin TLS leg, never a fresh uninspected connection.
Full Upgrade/WebSocket handlers remain a separate explicit implementation.
"""

from __future__ import annotations

import asyncio
import logging
import math
from collections.abc import Awaitable, Callable

import h11

from ads_sandbox_egress.framing import Headers, forwarding_headers, validate_headers
from ads_sandbox_egress.http1 import HTTP1Channel
from ads_sandbox_egress.policy import RequestDenied
from ads_sandbox_egress.request_authorization import (
    ConnectionTarget,
    RequestAuthorizer,
    RequestHead,
)
from ads_sandbox_egress.streams import OwnedStream

_LOG = logging.getLogger(__name__)


def serialized_headers(headers: Headers, *, status: int | None = None) -> Headers:
    fields = validate_headers(headers)
    if (
        status is not None
        and (status < 200 or status == 204)
        and any(name in (b"content-length", b"transfer-encoding") for name, _ in fields)
    ):
        raise RequestDenied("invalid_bodyless_response_framing")
    result = forwarding_headers(fields)
    # h11 owns chunk serialization. Removing TE without restoring the validated
    # coding would incorrectly turn an unknown-length request into a zero body.
    if any(name == b"transfer-encoding" for name, _ in fields):
        result += ((b"transfer-encoding", b"chunked"),)
    return result


class HTTP1Proxy:
    def __init__(
        self,
        frontend: OwnedStream,
        authorizer: RequestAuthorizer,
        connect: Callable[[ConnectionTarget], Awaitable[OwnedStream]],
        *,
        idle_timeout: float = 30,
        authorization_timeout: float = 10,
    ) -> None:
        if not all(
            math.isfinite(value) and 0 < value <= 120
            for value in (idle_timeout, authorization_timeout)
        ):
            raise ValueError("bounded HTTP/1 deadlines required")
        self.frontend, self.authorizer, self.connect = frontend, authorizer, connect
        self.idle_timeout, self.authorization_timeout = idle_timeout, authorization_timeout
        self.upstream: OwnedStream | None = None
        self._running = False

    async def _exchange(
        self, front: HTTP1Channel, origin: HTTP1Channel, *, expects_continue: bool
    ) -> bool:
        early = False
        upload_ended = False

        async def upload() -> None:
            nonlocal upload_ended
            while True:
                event = await front.receive()
                if not isinstance(event, (h11.Data, h11.EndOfMessage)):
                    raise RequestDenied("unexpected_request_body_event")
                if isinstance(event, h11.EndOfMessage):
                    upload_ended = True
                await origin.send(event)
                if isinstance(event, h11.EndOfMessage):
                    return

        async def response() -> None:
            nonlocal early
            final = False
            continued = False
            informational = 0
            while True:
                event = await origin.receive()
                if isinstance(event, h11.InformationalResponse):
                    informational += 1
                    if final or event.status_code == 101 or informational > 16:
                        raise RequestDenied("unexpected_response_transition")
                    if event.status_code == 100:
                        continued = True
                    await front.send(
                        h11.InformationalResponse(
                            status_code=event.status_code,
                            headers=list(
                                serialized_headers(tuple(event.headers), status=event.status_code)
                            ),
                            reason=event.reason,
                        )
                    )
                elif isinstance(event, h11.Response):
                    if final:
                        raise RequestDenied("duplicate_final_response")
                    final = True
                    if not upload_ended and expects_continue and not continued:
                        early = True
                        upload_task.cancel()
                    await front.send(
                        h11.Response(
                            status_code=event.status_code,
                            headers=list(
                                serialized_headers(tuple(event.headers), status=event.status_code)
                            ),
                            reason=event.reason,
                        )
                    )
                elif isinstance(event, (h11.Data, h11.EndOfMessage)) and final:
                    await front.send(event)
                    if isinstance(event, h11.EndOfMessage):
                        if not upload_ended:
                            early = True
                            upload_task.cancel()
                        return
                else:
                    raise RequestDenied("unexpected_response_event")

        async with asyncio.TaskGroup() as tasks:
            upload_task = tasks.create_task(upload())
            tasks.create_task(response())
        return early

    async def run(self) -> None:
        if self._running:
            raise RuntimeError("HTTP/1 stream owner cannot be reused")
        self._running = True
        front = HTTP1Channel(
            self.frontend.reader, self.frontend.writer, client=False, idle_timeout=self.idle_timeout
        )
        origin: HTTP1Channel | None = None
        clean = False
        try:
            while True:
                request = await front.receive()
                if isinstance(request, h11.ConnectionClosed):
                    clean = True
                    return
                if not isinstance(request, h11.Request):
                    raise RequestDenied("request_headers_required")
                head = RequestHead.http1(request, self.authorizer.connection)
                if head.upgrade is not None:
                    # Explicit incomplete feature, not an opaque forwarding
                    # fallback or a claimed supported transition.
                    raise RequestDenied("http1_transition_owner_not_implemented")
                async with asyncio.timeout(self.authorization_timeout):
                    await self.authorizer.authorize(head)
                    if origin is None:
                        self.upstream = await self.connect(self.authorizer.connection)
                        origin = HTTP1Channel(
                            self.upstream.reader,
                            self.upstream.writer,
                            client=True,
                            idle_timeout=self.idle_timeout,
                        )
                await origin.send(
                    h11.Request(
                        method=head.method,
                        target=head.target,
                        headers=list(serialized_headers(head.headers)),
                    )
                )
                early = await self._exchange(
                    front,
                    origin,
                    expects_continue=any(
                        name == b"expect" and value.lower() == b"100-continue"
                        for name, value in head.headers
                    ),
                )
                if early:
                    # Relay the complete genuine origin response. Do not drain
                    # the denied upload, manufacture 100, or reuse its stream.
                    assert self.upstream is not None
                    self.upstream.abort()
                    self.upstream = None
                    clean = True
                    return
                if front.connection.our_state is not h11.DONE:
                    clean = True
                    return
                if (
                    origin.connection.our_state is h11.DONE
                    and origin.connection.their_state is h11.DONE
                ):
                    origin.next_cycle()
                else:
                    assert self.upstream is not None
                    await self.upstream.finish()
                    self.upstream, origin = None, None
                front.next_cycle()
        except asyncio.CancelledError:
            raise
        except Exception:
            # Do not expose URLs, credentials, upstream exception text or an
            # HTTP denial response. Both legs are reset by the custody finally.
            try:
                _LOG.warning("http1_exchange_reset reason=request_or_upstream")
            except Exception:
                pass
        finally:
            if not clean:
                self.frontend.abort()
                if self.upstream is not None:
                    self.upstream.abort()
            else:
                try:
                    if self.upstream is not None:
                        await self.upstream.finish()
                    await self.frontend.finish()
                except BaseException:
                    self.frontend.abort()
                    if self.upstream is not None:
                        self.upstream.abort()
                    raise
