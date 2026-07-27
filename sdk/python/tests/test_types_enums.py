"""Unit tests for the typed enum string semantics.

These pin the `enum.StrEnum` behavior that the Python 3.10 backport in
`microsandbox.types` must match: members compare equal to their values
and stringify to their values under both `str()` and `format()`.
"""

from __future__ import annotations

from microsandbox import (
    LogLevel,
    PullPolicy,
    Secret,
    SecretExactHeader,
    SecretInjection,
)


def test_enum_members_compare_equal_to_values() -> None:
    assert PullPolicy.IF_MISSING == "if-missing"
    assert LogLevel.INFO == "info"


def test_enum_members_stringify_to_values() -> None:
    assert str(PullPolicy.IF_MISSING) == "if-missing"
    assert f"{PullPolicy.IF_MISSING}" == "if-missing"
    assert format(LogLevel.WARN) == "warn"


def test_exact_header_secret_is_provider_neutral() -> None:
    entry = Secret.exact_header(
        "API_KEY",
        value="synthetic-token",
        header="Proxy-Authorization",
        scheme="Token",
        allow_hosts=("api.example.com",),
    )

    assert entry.injection == SecretInjection(
        headers=False,
        basic_auth=False,
        exact_headers=(
            SecretExactHeader(name="Proxy-Authorization", scheme="Token"),
        ),
    )
    assert entry._to_dict()["injection"] == {
        "headers": False,
        "basic_auth": False,
        "exact_headers": [
            {"name": "Proxy-Authorization", "scheme": "Token"},
        ],
    }


def test_secret_injection_preserves_legacy_positional_arguments() -> None:
    injection = SecretInjection(False, True, True, True)

    assert injection.headers is False
    assert injection.basic_auth is True
    assert injection.query_params is True
    assert injection.body is True
    assert injection.exact_headers == ()
