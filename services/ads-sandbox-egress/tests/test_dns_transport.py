import asyncio
import json
import logging
from uuid import uuid4

import dns.asyncquery
import dns.flags
import dns.message
import dns.rrset
import pytest

from ads_sandbox_egress.dns_transport import DNSLimits, DNSTransport
from ads_sandbox_egress.policy import RequestDenied


class View:
    """External DNSSEC/synthesis boundary, explicitly not its proof."""

    def __init__(self, *, deny=False, delay=0, large=False):
        self.calls = 0
        self.deny, self.delay, self.large = deny, delay, large

    async def answer(self, query, *, deadline):
        self.calls += 1
        await asyncio.sleep(self.delay)
        if self.deny:
            raise RequestDenied("prohibited_address")
        response = dns.message.make_response(query)
        name = query.question[0].name
        response.answer.append(dns.rrset.from_text(name, 10, "IN", "A", "8.8.8.8"))
        if self.large:
            for i in range(8):
                response.additional.append(
                    dns.rrset.from_text(f"x{i}.example.", 10, "IN", "TXT", '"' + "x" * 200 + '"')
                )
        return response


def transport(view, **kwargs):
    return DNSTransport(
        view,
        sandbox_id=uuid4(),
        instance_id=uuid4(),
        classifier_version="test-only",
        safe_udp_payload=1232,
        **kwargs,
    )


def test_real_udp_tcp_and_no_edns_truncation():
    async def run():
        view = View(large=True)
        service = transport(view)
        host, port = await service.start("127.0.0.1", 0)
        try:
            query = dns.message.make_query("example.com", "A")
            udp = await dns.asyncquery.udp(query, host, port=port, timeout=2)
            assert udp.flags & dns.flags.TC
            assert len(udp.to_wire()) <= 512
            tcp = await dns.asyncquery.tcp(query, host, port=port, timeout=2)
            assert not tcp.flags & dns.flags.TC
            assert len(tcp.additional) == 8
            assert view.calls == 2
        finally:
            await service.close()
        assert service._accepted == service._connections == 0
        assert not service._tasks

    asyncio.run(run())


def test_actual_tcp_policy_reset_and_udp_silent_drop(caplog):
    caplog.set_level(logging.WARNING)

    async def run():
        service = transport(View(deny=True))
        host, port = await service.start("127.0.0.1", 0)
        query = dns.message.make_query("example.com", "A")
        try:
            with pytest.raises(dns.exception.Timeout):
                await dns.asyncquery.udp(query, host, port=port, timeout=0.1)
            reader, writer = await asyncio.open_connection(host, port)
            wire = query.to_wire()
            writer.write(len(wire).to_bytes(2, "big") + wire)
            await writer.drain()
            with pytest.raises(ConnectionResetError):
                await reader.read(1)
            writer.close()
            with pytest.raises(ConnectionResetError):
                await writer.wait_closed()
        finally:
            await service.close()

    asyncio.run(run())
    events = [json.loads(record.message) for record in caplog.records]
    assert len(events) == 2
    assert {event["action"] for event in events} == {"drop", "reset"}
    assert all(event["reason"] == "prohibited_address" for event in events)
    assert all(event["query"]["name"] == "example.com." for event in events)


def test_duplicate_outstanding_id_resets_whole_tcp_connection(caplog):
    async def run():
        service = transport(View(delay=0.2))
        host, port = await service.start("127.0.0.1", 0)
        try:
            reader, writer = await asyncio.open_connection(host, port)
            wire = dns.message.make_query("example.com", "A").to_wire()
            frame = len(wire).to_bytes(2, "big") + wire
            writer.write(frame + frame)
            await writer.drain()
            with pytest.raises(ConnectionResetError):
                await reader.read(1)
            writer.close()
            with pytest.raises(ConnectionResetError):
                await writer.wait_closed()
        finally:
            await service.close()
        assert service._accepted == service._connections == 0

    asyncio.run(run())
    assert any("duplicate_outstanding_id" in record.message for record in caplog.records)


def test_frame_deadline_not_extended_by_partial_bytes(caplog):
    async def run():
        service = transport(View(), limits=DNSLimits(frame_deadline=0.03))
        host, port = await service.start("127.0.0.1", 0)
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.write(b"\0")
            await writer.drain()
            with pytest.raises(ConnectionResetError):
                await asyncio.wait_for(reader.read(1), 1)
            writer.close()
            with pytest.raises(ConnectionResetError):
                await writer.wait_closed()
        finally:
            await service.close()

    asyncio.run(run())
    assert any("frame_or_idle_deadline" in record.message for record in caplog.records)


def test_udp_tcp_share_accepted_queue_and_queue_deadline(caplog):
    async def run():
        service = transport(View(delay=1), limits=DNSLimits(accepted=2, executing=1, deadline=0.06))
        host, port = await service.start("127.0.0.1", 0)
        try:
            first = asyncio.create_task(
                dns.asyncquery.udp(
                    dns.message.make_query("one.example", "A"), host, port=port, timeout=0.15
                )
            )
            second = asyncio.create_task(
                dns.asyncquery.tcp(
                    dns.message.make_query("two.example", "A"), host, port=port, timeout=0.15
                )
            )
            for _ in range(100):
                if service._accepted == 2:
                    break
                await asyncio.sleep(0.0001)
            assert service._accepted == 2
            with pytest.raises(dns.exception.Timeout):
                await dns.asyncquery.udp(
                    dns.message.make_query("three.example", "A"), host, port=port, timeout=0.08
                )
            results = await asyncio.gather(first, second, return_exceptions=True)
            assert all(isinstance(result, Exception) for result in results)
            assert service.view.calls == 1
        finally:
            await service.close()
        assert service._accepted == 0

    asyncio.run(run())
    reasons = [json.loads(record.message)["reason"] for record in caplog.records]
    assert reasons.count("query_capacity") == 1
    assert reasons.count("resolution_deadline") == 2


def test_close_cancels_running_and_queued_queries_without_accounting_leak():
    async def run():
        service = transport(View(delay=10), limits=DNSLimits(executing=1))
        host, port = await service.start("127.0.0.1", 0)
        reader, writer = await asyncio.open_connection(host, port)
        frames = []
        for i in range(4):
            query = dns.message.make_query(f"x{i}.example", "A")
            query.id = i
            wire = query.to_wire()
            frames.append(len(wire).to_bytes(2, "big") + wire)
        writer.write(b"".join(frames))
        await writer.drain()
        for _ in range(100):
            if service._accepted == 4:
                break
            await asyncio.sleep(0.0001)
        assert service._accepted == 4
        await asyncio.wait_for(service.close(), 0.5)
        await service.close()
        assert service._accepted == service._connections == 0
        assert not service._tasks and not service._writers
        with pytest.raises(ConnectionResetError):
            await reader.read(1)
        writer.close()
        with pytest.raises(ConnectionResetError):
            await writer.wait_closed()

    asyncio.run(run())


@pytest.mark.parametrize(
    "wire",
    [
        b"",
        b"x" * 1233,
        dns.message.make_query("example.com", "AXFR").to_wire(),
        dns.message.make_response(dns.message.make_query("example.com", "A")).to_wire(),
    ],
)
def test_malformed_and_unsupported_queries_never_reach_view(wire):
    service = transport(View())
    with pytest.raises(RequestDenied):
        service._query(wire, udp=True)
    assert service.view.calls == 0
