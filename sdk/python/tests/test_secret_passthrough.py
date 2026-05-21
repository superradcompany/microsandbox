"""Unit tests for secret placeholder passthrough configuration."""

from __future__ import annotations

from microsandbox import Network, Secret, ViolationAction, ViolationPolicy


def test_violation_action_includes_passthrough() -> None:
    assert ViolationAction.PASSTHROUGH == "passthrough"


def test_secret_passthrough_hosts_serialize() -> None:
    secret = Secret.env(
        "API_KEY",
        value="sk-abc",
        allow_hosts=("api.github.com",),
        on_violation=ViolationPolicy.passthrough(
            hosts=("api.anthropic.com",),
            host_patterns=("*.anthropic.com",),
            fallback=ViolationAction.BLOCK_AND_TERMINATE,
        ),
    )

    assert secret._to_dict() == {
        "env_var": "API_KEY",
        "value": "sk-abc",
        "allow_hosts": ["api.github.com"],
        "on_violation": {
            "passthrough": {
                "fallback": "block-and-terminate",
                "hosts": ["api.anthropic.com"],
                "host_patterns": ["*.anthropic.com"],
            }
        },
    }


def test_network_secret_passthrough_hosts_serialize() -> None:
    network = Network(
        on_secret_violation=ViolationPolicy.passthrough(all_hosts=True),
    )

    assert network._to_dict() == {
        "on_secret_violation": {
            "passthrough": {
                "fallback": "block-and-log",
                "all_hosts": True,
            }
        },
    }
