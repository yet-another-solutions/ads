from __future__ import annotations

from html import escape
from typing import Any

from litestar import MediaType, Request, Response
from litestar.types import ExceptionHandlersMap

from ads_commons.security import AccessDenied, AuthenticationRequired


class NotFound(Exception):
    """No row matches both the id and the bound user."""

    def __init__(self, detail: str = "not found") -> None:
        super().__init__(detail)
        self.detail = detail


class Conflict(Exception):
    """A run is already in flight for this session."""

    def __init__(self, detail: str = "a run is already in flight") -> None:
        super().__init__(detail)
        self.detail = detail


class SessionForbidden(Exception):
    """The row belongs to another user."""

    def __init__(self, detail: str = "forbidden") -> None:
        super().__init__(detail)
        self.detail = detail


class InvalidInput(Exception):
    """A dialog form failed a non-msgspec rule."""

    def __init__(self, detail: str = "invalid input") -> None:
        super().__init__(detail)
        self.detail = detail


class ComposerRejected(Exception):
    """The composer POST is invalid: warning text, no transcript row, no Kafka."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message
        self.detail = message


class ProducerFailed(Exception):
    """Kafka produce failed. The pending run stays for the watchdog."""

    def __init__(self, detail: str = "engine request could not be produced") -> None:
        super().__init__(detail)
        self.detail = detail


def handle_authentication_required(
    request: Request[Any, Any, Any], exc: Exception
) -> Response[Any]:
    del request
    detail = exc.detail if isinstance(exc, AuthenticationRequired) else "authentication required"
    return Response(content={"status_code": 401, "detail": detail}, status_code=401)


def handle_access_denied(request: Request[Any, Any, Any], exc: Exception) -> Response[Any]:
    del request
    detail = exc.detail if isinstance(exc, AccessDenied) else "access denied"
    return Response(content={"status_code": 403, "detail": detail}, status_code=403)


def handle_session_forbidden(request: Request[Any, Any, Any], exc: Exception) -> Response[Any]:
    del request
    detail = exc.detail if isinstance(exc, SessionForbidden) else "forbidden"
    return Response(content={"status_code": 403, "detail": detail}, status_code=403)


def handle_not_found(request: Request[Any, Any, Any], exc: Exception) -> Response[Any]:
    del request
    detail = exc.detail if isinstance(exc, NotFound) else "not found"
    return Response(content={"status_code": 404, "detail": detail}, status_code=404)


def handle_invalid_input(request: Request[Any, Any, Any], exc: Exception) -> Response[Any]:
    del request
    detail = exc.detail if isinstance(exc, InvalidInput) else "invalid input"
    return Response(content={"status_code": 400, "detail": detail}, status_code=400)


def handle_conflict(request: Request[Any, Any, Any], exc: Exception) -> Response[Any]:
    del request
    detail = exc.detail if isinstance(exc, Conflict) else "conflict"
    return Response(content={"status_code": 409, "detail": detail}, status_code=409)


def handle_producer_failed(request: Request[Any, Any, Any], exc: Exception) -> Response[Any]:
    del request
    detail = exc.detail if isinstance(exc, ProducerFailed) else "engine unavailable"
    return Response(content={"status_code": 502, "detail": detail}, status_code=502)


def handle_composer_rejected(request: Request[Any, Any, Any], exc: Exception) -> Response[Any]:
    """400 with the warning fragment only. HTMX 400 stays off globally."""
    del request
    message = exc.message if isinstance(exc, ComposerRejected) else "invalid message"
    body = f'<p id="composer-warn" class="composer-warn">{escape(message)}</p>'
    return Response(content=body, status_code=400, media_type=MediaType.HTML)


EXCEPTION_HANDLERS: ExceptionHandlersMap = {
    AuthenticationRequired: handle_authentication_required,
    AccessDenied: handle_access_denied,
    SessionForbidden: handle_session_forbidden,
    NotFound: handle_not_found,
    Conflict: handle_conflict,
    InvalidInput: handle_invalid_input,
    ComposerRejected: handle_composer_rejected,
    ProducerFailed: handle_producer_failed,
}
