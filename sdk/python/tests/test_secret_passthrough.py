"""Unit tests for secret substitution and placeholder passthrough policy."""

from __future__ import annotations

from microsandbox import Network, Secret, SecretSubstitution, ViolationAction


def test_secret_policy_serializes_independent_controls() -> None:
    secret = Secret.env(
        "API_KEY",
        value="sk-abc",
        allow=("api.github.com",),
        passthrough=("api.anthropic.com", "*.anthropic.com"),
        substitution=SecretSubstitution(headers=False, query=True, body=True),
        violation_action=ViolationAction.BLOCK_AND_TERMINATE,
    )

    assert secret._to_dict() == {
        "env_var": "API_KEY",
        "value": "sk-abc",
        "allow": ["api.github.com"],
        "passthrough": ["api.anthropic.com", "*.anthropic.com"],
        "substitution": {"headers": False, "query": True, "body": True},
        "violation_action": "block-and-terminate",
    }


def test_network_secret_violation_action_serializes() -> None:
    network = Network(secret_violation_action=ViolationAction.BLOCK)

    assert network._to_dict()["secret_violation_action"] == "block"
