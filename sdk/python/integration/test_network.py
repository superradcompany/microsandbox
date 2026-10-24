"""Network configuration integration tests."""

from __future__ import annotations

import asyncio
import json

import pytest

from integration.helpers import free_tcp_port
from microsandbox import (
    Action,
    DestGroup,
    Destination,
    Network,
    NetworkPolicy,
    PortBinding,
    Protocol,
    Rule,
    Sandbox,
)


@pytest.mark.asyncio
async def test_network_policy_and_port_config_create(sandbox_factory):
    host_port = free_tcp_port()
    sandbox = await sandbox_factory(
        "py-sdk-network",
        network=Network(
            policy=NetworkPolicy(
                default_egress=Action.ALLOW,
                rules=(Rule.deny(protocol=Protocol.TCP, port=9, destination="public"),),
            ),
            ports=(PortBinding.tcp(host_port, 7777),),
            max_tcp_connections=128,
        ),
    )

    out = await sandbox.shell("true")
    assert out.success is True


@pytest.mark.parametrize(
    ("label", "destination"),
    [
        ("typed-ip", Destination.ip("1.1.1.1")),
        ("string-ip", "1.1.1.1"),
    ],
)
@pytest.mark.asyncio
async def test_ip_destination_allows_specific_egress(label, destination, sandbox_factory):
    sandbox = await sandbox_factory(
        f"py-sdk-network-{label}",
        network=Network(
            policy=NetworkPolicy(
                default_egress=Action.DENY,
                default_ingress=Action.DENY,
                rules=(
                    Rule.allow(
                        destination=destination,
                        protocol=Protocol.TCP,
                        port=443,
                    ),
                    Rule.allow(
                        destination=Destination.group(DestGroup.LINK_LOCAL),
                        protocol=Protocol.TCP,
                        port=80,
                    ),
                ),
            ),
        ),
    )

    out = await sandbox.shell(
        "nc -zv -w 5 1.1.1.1 443 >/dev/null 2>&1 || echo cloudflare-failed; "
        "nc -zv -w 5 8.8.8.8 443 >/dev/null 2>&1 || echo google-failed"
    )
    combined = out.stdout_text + out.stderr_text

    assert "cloudflare-failed" not in combined
    assert "google-failed" in combined

    handle = await Sandbox.get(await sandbox.name)
    config = json.loads(handle.config_json)
    destinations = [rule["destination"] for rule in config["network"]["policy"]["rules"]]
    assert {"group": "link_local"} in destinations


async def _host_service() -> tuple[asyncio.Server, int]:
    async def answer(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(answer, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def _reaches_host(sandbox, port: int) -> bool:
    out = await sandbox.shell(f"wget -qO- --timeout=5 http://host.microsandbox.internal:{port}/")
    return out.stdout_text.strip() == "ok"


@pytest.mark.asyncio
async def test_a_running_sandbox_loses_the_network_when_its_policy_is_closed(sandbox_factory):
    server, port = await _host_service()
    async with server:
        sandbox = await sandbox_factory(
            "py-sdk-live-close", network=Network(policy=NetworkPolicy.allow_all())
        )
        assert await _reaches_host(sandbox, port), "the open policy refused the host"

        await sandbox.set_network_policy(NetworkPolicy.none())

        assert not await _reaches_host(sandbox, port), "the guest reached the host after its policy closed"


@pytest.mark.asyncio
async def test_set_network_policy_refuses_anything_but_a_network_policy(sandbox_factory):
    sandbox = await sandbox_factory("py-sdk-live-type", network=Network(policy=NetworkPolicy.allow_all()))

    with pytest.raises(TypeError):
        await sandbox.set_network_policy(Network.none())
