"""Unit tests for secret substitution and placeholder passthrough policy."""

from __future__ import annotations

import pytest

from microsandbox import Network, Secret, SecretSubstitution, ViolationAction


@pytest.mark.parametrize("legacy", [False, True])
def test_secret_policy_serializes_independent_controls(legacy: bool) -> None:
    kwargs = {
        "value": "sk-abc",
        "allow": ("api.github.com",),
        "passthrough" if legacy else "allow_placeholder_for": (
            "api.anthropic.com",
            "*.anthropic.com",
        ),
        "substitution": SecretSubstitution(headers=False, query=True, body=True),
        "violation_action": ViolationAction.BLOCK_AND_TERMINATE,
    }
    if legacy:
        with pytest.warns(DeprecationWarning, match="allow_placeholder_for"):
            secret = Secret.env("API_KEY", **kwargs)
    else:
        secret = Secret.env("API_KEY", **kwargs)

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


def test_placeholder_permission_aliases_are_additive() -> None:
    with pytest.warns(DeprecationWarning, match="allow_placeholder_for"):
        secret = Secret.env(
            "KEY",
            value="secret",
            allow_placeholder_for=("new.example",),
            passthrough=("legacy.example",),
        )
    assert secret._to_dict()["passthrough"] == ["new.example", "legacy.example"]
