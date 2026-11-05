"""Reject malformed options before they reach a VM or loosen a network policy."""

import math

import pytest

from microsandbox import Network, NetworkPolicy, Protocol, Rule, Sandbox


@pytest.mark.parametrize("port", ["typo", "", "9000-8000", "1-2-3", -1, 65536, 1.5])
def test_create_rejects_invalid_policy_ports(port):
    network = Network(
        policy=NetworkPolicy(rules=(Rule.allow(protocol=Protocol.TCP, port=port),)),
    )
    error_type = TypeError if isinstance(port, float) else ValueError
    with pytest.raises(error_type, match="port"):
        Sandbox.create("invalid-port", image="alpine", network=network)


@pytest.mark.parametrize("port", ["typo", "", "9000-8000", -1, 65536])
def test_restore_rejects_invalid_policy_ports(port):
    policy = NetworkPolicy(rules=(Rule.allow(protocol=Protocol.TCP, port=port),))
    with pytest.raises(ValueError, match="port"):
        Sandbox.restore("missing", name="invalid-port", network_policy=policy)


@pytest.mark.parametrize("option", ["max_duration", "idle_timeout", "replace_with_timeout"])
@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf, -1, 1e300])
def test_create_rejects_invalid_durations(option, value):
    with pytest.raises(ValueError):
        Sandbox.create("invalid-duration", image="alpine", **{option: value})
