"""Network configuration integration tests."""

from __future__ import annotations

import pytest

from integration.helpers import free_tcp_port
from microsandbox import Network, NetworkPolicy, PortBinding, Protocol, Rule


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
