"""Tests for outbound proxy configuration."""

import pytest

from microsandbox import OutboundProxy, Sandbox, SecretSource


def test_socks5_proxy_serializes_as_structured_config() -> None:
    proxy = OutboundProxy.socks5("127.0.0.1:1080")

    assert proxy._to_dict() == {
        "protocol": "socks5",
        "address": "127.0.0.1:1080",
    }


def test_socks5_proxy_serializes_environment_backed_credentials() -> None:
    proxy = OutboundProxy.socks5("127.0.0.1:1080").credentials(
        "sandbox", SecretSource.env("SOCKS5_PASSWORD")
    )

    assert proxy._to_dict() == {
        "protocol": "socks5",
        "address": "127.0.0.1:1080",
        "credentials": {
            "username": "sandbox",
            "password": {
                "kind": "env",
                "var": "SOCKS5_PASSWORD",
            },
        },
    }


def test_http_connect_proxy_serializes_environment_backed_credentials() -> None:
    proxy = OutboundProxy.http_connect("127.0.0.1:3128").credentials(
        "sandbox", SecretSource.env("HTTP_CONNECT_PASSWORD")
    )

    assert proxy._to_dict() == {
        "protocol": "http_connect",
        "address": "127.0.0.1:3128",
        "credentials": {
            "username": "sandbox",
            "password": {
                "kind": "env",
                "var": "HTTP_CONNECT_PASSWORD",
            },
        },
    }


def test_http_connect_proxy_allows_an_empty_username() -> None:
    proxy = OutboundProxy.http_connect("127.0.0.1:3128").credentials(
        "", SecretSource.env("HTTP_CONNECT_PASSWORD")
    )

    assert proxy._to_dict()["credentials"]["username"] == ""


def test_proxy_credentials_require_username_and_password() -> None:
    with pytest.raises(ValueError, match="provided together"):
        OutboundProxy(
            protocol="http_connect",
            address="127.0.0.1:3128",
            username="sandbox",
        )


def test_socks4_proxy_serializes_optional_user_id() -> None:
    assert OutboundProxy.socks4("127.0.0.1:1080")._to_dict() == {
        "protocol": "socks4",
        "address": "127.0.0.1:1080",
    }
    assert OutboundProxy.socks4(
        "127.0.0.1:1080", user_id="sandbox"
    )._to_dict() == {
        "protocol": "socks4",
        "address": "127.0.0.1:1080",
        "user_id": "sandbox",
    }


def test_socks5_proxy_rejects_socks4_user_id() -> None:
    with pytest.raises(ValueError, match="only supported for SOCKS4"):
        OutboundProxy(protocol="socks5", address="127.0.0.1:1080", user_id="sandbox")


def test_socks4_proxy_rejects_credentials() -> None:
    with pytest.raises(ValueError, match="only supported for SOCKS5 and HTTP CONNECT"):
        OutboundProxy.socks4("127.0.0.1:1080").credentials(
            "sandbox", SecretSource.env("SOCKS5_PASSWORD")
        )


def _native_create_error(**kwargs: object) -> Exception:
    try:
        Sandbox.create("proxy-parse-probe", image="alpine", **kwargs)
    except Exception as exc:
        return exc
    raise AssertionError("expected Sandbox.create to raise outside an event loop")


class _StorePassword:
    """Password source shape Python does not expose yet, used to probe the parser."""

    def _to_dict(self) -> dict:
        return {"kind": "store", "var": "PROXY_PASSWORD"}


def test_native_create_parses_nested_http_connect_credentials() -> None:
    # `Sandbox.create` parses kwargs synchronously, before it needs an event loop, so
    # a source only the backend can reject proves the nested credentials arrived.
    proxy = OutboundProxy.http_connect("127.0.0.1:3128").credentials(
        "sandbox", _StorePassword()
    )

    with pytest.raises(ValueError, match="unsupported proxy password source"):
        Sandbox.create("proxy-parse-probe", image="alpine", proxy=proxy)


def test_native_create_accepts_top_level_proxy() -> None:
    baseline = _native_create_error()
    error = _native_create_error(proxy=OutboundProxy.socks5("127.0.0.1:1080"))

    assert type(error) is type(baseline), f"top-level proxy rejected: {error!r}"


def test_native_create_accepts_socks4_proxy() -> None:
    baseline = _native_create_error()
    error = _native_create_error(
        proxy=OutboundProxy.socks4("127.0.0.1:1080", user_id="sandbox")
    )

    assert type(error) is type(baseline), f"top-level SOCKS4 proxy rejected: {error!r}"


def test_native_create_accepts_socks5_credentials() -> None:
    baseline = _native_create_error()
    error = _native_create_error(
        proxy=OutboundProxy.socks5("127.0.0.1:1080").credentials(
            "sandbox", SecretSource.env("SOCKS5_PASSWORD")
        )
    )

    assert type(error) is type(baseline), f"SOCKS5 credentials rejected: {error!r}"


def test_native_create_accepts_http_connect_credentials() -> None:
    # These two cases compare exception types because `Sandbox.create` cannot reach the
    # builder outside an event loop. The applied value and the backend validation are
    # asserted in `sdk/python/src/helpers.rs`
    # (`http_connect_proxy_credentials_reach_the_builder`).
    baseline = _native_create_error()
    error = _native_create_error(
        proxy=OutboundProxy.http_connect("127.0.0.1:3128").credentials(
            "sandbox", SecretSource.env("HTTP_CONNECT_PASSWORD")
        )
    )

    assert type(error) is type(baseline), f"HTTP CONNECT credentials rejected: {error!r}"
