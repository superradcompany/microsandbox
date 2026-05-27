"""Network configuration integration tests."""

from __future__ import annotations

import pytest

from integration.helpers import free_tcp_port
from microsandbox import Destination, Network, NetworkPolicy, PortBinding, Protocol, Rule


@pytest.mark.asyncio
async def test_network_policy_and_port_config_create(sandbox_factory):
    host_port = free_tcp_port()
    sandbox = await sandbox_factory(
        "py-sdk-network",
        network=Network(
            policy=NetworkPolicy(
                default_egress="allow",
                rules=(Rule.deny(protocol=Protocol.TCP, port=9, destination="public"),),
            ),
            ports=(PortBinding.tcp(host_port, 7777),),
            max_connections=128,
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
                default_egress="deny",
                default_ingress="deny",
                rules=(
                    Rule.allow(
                        destination=destination,
                        protocol=Protocol.TCP,
                        port=443,
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
