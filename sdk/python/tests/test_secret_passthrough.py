"""Unit tests for secret placeholder passthrough configuration."""

from __future__ import annotations

from microsandbox import Network, Secret, ViolationAction


def test_violation_action_includes_passthrough() -> None:
    assert ViolationAction.PASSTHROUGH == "passthrough"


def test_secret_passthrough_hosts_serialize() -> None:
    secret = Secret.env(
        "API_KEY",
        value="sk-abc",
        allow_hosts=("api.github.com",),
        passthrough_hosts=("api.anthropic.com",),
        passthrough_host_patterns=("*.anthropic.com",),
    )

    assert secret._to_dict() == {
        "env_var": "API_KEY",
        "value": "sk-abc",
        "allow_hosts": ["api.github.com"],
        "passthrough_hosts": ["api.anthropic.com"],
        "passthrough_host_patterns": ["*.anthropic.com"],
    }


def test_network_secret_passthrough_hosts_serialize() -> None:
    network = Network(
        on_secret_violation=ViolationAction.PASSTHROUGH,
        secret_passthrough_hosts=("api.anthropic.com",),
        secret_passthrough_host_patterns=("*.anthropic.com",),
    )

    assert network._to_dict() == {
        "on_secret_violation": "passthrough",
        "secret_passthrough_hosts": ["api.anthropic.com"],
        "secret_passthrough_host_patterns": ["*.anthropic.com"],
    }
