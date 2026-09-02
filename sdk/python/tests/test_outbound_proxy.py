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


def test_socks4_proxy_rejects_socks5_credentials() -> None:
    with pytest.raises(ValueError, match="only supported for SOCKS5"):
        OutboundProxy.socks4("127.0.0.1:1080").credentials(
            "sandbox", SecretSource.env("SOCKS5_PASSWORD")
        )


def _native_create_error(**kwargs: object) -> Exception:
    try:
        Sandbox.create("proxy-parse-probe", image="alpine", **kwargs)
    except Exception as exc:
        return exc
    raise AssertionError("expected Sandbox.create to raise outside an event loop")


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
