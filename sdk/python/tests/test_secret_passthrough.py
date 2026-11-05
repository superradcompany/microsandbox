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


def test_secret_substitution_header_fields_serialize() -> None:
    secret = Secret.env(
        "API_KEY",
        value="sk-abc",
        allow=("api.github.com",),
        substitution=SecretSubstitution(
            header_fields=("authorization", "x-api-key")
        ),
    )

    assert secret._to_dict()["substitution"] == {
        "header_fields": ["authorization", "x-api-key"]
    }


def test_secret_substitution_header_fields_is_keyword_only() -> None:
    # ``header_fields`` is keyword-only, so the historical positional order
    # (headers, query, body) is unchanged: ``SecretSubstitution(False, True)``
    # still means headers disabled and query substitution enabled.
    substitution = SecretSubstitution(False, True)
    assert substitution.headers is False
    assert substitution.query is True
    assert substitution.body is False
    assert substitution.header_fields == ()
    with pytest.raises(TypeError):
        SecretSubstitution(True, False, False, ("authorization",))

    scoped = SecretSubstitution(headers=True, header_fields=("authorization",))
    assert scoped._to_dict() == {
        "header_fields": ["authorization"],
    }

    # An allowlist cannot be combined with a disabled header scope: it would be
    # inert, so reject it instead of silently dropping the restriction.
    with pytest.raises(ValueError, match="header_fields requires headers"):
        SecretSubstitution(headers=False, header_fields=("authorization",))._to_dict()
