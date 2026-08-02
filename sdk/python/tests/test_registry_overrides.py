"""Unit tests for the registry override kwargs of ``Sandbox.create``."""

from __future__ import annotations

from pathlib import Path

import pytest

from microsandbox import InvalidConfigError, RegistryAuth, Sandbox

PEM = b"-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"

# `Sandbox.create` never touches a sandbox: an image that cannot exist keeps the
# awaitable inert even if something ever awaits it by accident.
MISSING_IMAGE = "/__microsandbox_missing_rootfs__"


def assert_kwargs_accepted(name: str, **kwargs: object) -> None:
    """Assert that ``Sandbox.create`` accepts ``kwargs``.

    Kwargs are validated synchronously, before the awaitable is built, so a
    rejected kwarg raises right here. Building the awaitable is the next step
    and needs a running event loop — reaching *that* failure from a sync test
    means validation passed and no creation work was ever spawned.
    """
    with pytest.raises(RuntimeError, match="no running event loop"):
        Sandbox.create(name, image=MISSING_IMAGE, **kwargs)


def test_accepts_insecure_and_ca_certs_in_every_entry_form(tmp_path: Path) -> None:
    cert_file = tmp_path / "ca.pem"
    cert_file.write_bytes(PEM)

    assert_kwargs_accepted(
        "registry-overrides",
        registry_insecure=True,
        registry_ca_certs=[PEM, bytearray(PEM), str(cert_file), cert_file],
    )


def test_accepts_auth_alongside_insecure_and_ca_certs(tmp_path: Path) -> None:
    cert_file = tmp_path / "ca.pem"
    cert_file.write_bytes(PEM)

    # All three overrides share a single `.registry()` call in the bridge; the
    # core builder overwrites insecure/ca_certs on every call, so combining
    # them must not drop any of the three.
    assert_kwargs_accepted(
        "registry-overrides-with-auth",
        registry_auth=RegistryAuth.basic("user", "pass"),
        registry_insecure=True,
        registry_ca_certs=[cert_file],
    )


@pytest.mark.asyncio
async def test_overrides_survive_config_materialization() -> None:
    session = Sandbox.create_with_progress(
        "registry-overrides-materialize",
        image=MISSING_IMAGE,
        registry_insecure=True,
        registry_ca_certs=[PEM],
    )

    async with session:
        assert [event async for event in session.progress] == []
        # Only the bogus rootfs fails — the registry overrides make it through.
        with pytest.raises(InvalidConfigError, match="rootfs bind path does not exist"):
            await session.result()


def test_rejects_non_bool_insecure() -> None:
    with pytest.raises(TypeError, match="registry_insecure must be a bool"):
        Sandbox.create("bad-insecure", image=MISSING_IMAGE, registry_insecure="yes")


def test_rejects_raw_registry_auth_mapping() -> None:
    with pytest.raises(TypeError, match="RegistryAuth"):
        Sandbox.create(
            "bad-registry-auth",
            image=MISSING_IMAGE,
            registry_auth={"username": "user", "password": "pass"},
        )


def test_rejects_non_list_ca_certs() -> None:
    with pytest.raises(TypeError):
        Sandbox.create("bad-ca-certs", image=MISSING_IMAGE, registry_ca_certs="not-a-list")


def test_rejects_ca_cert_entry_that_is_neither_bytes_nor_path() -> None:
    with pytest.raises(TypeError, match=r"registry_ca_certs\[0\] must be PEM bytes or a path"):
        Sandbox.create("bad-ca-cert-entry", image=MISSING_IMAGE, registry_ca_certs=[123])


def test_rejects_unreadable_ca_cert_path() -> None:
    missing = "/nonexistent/xyz.pem"

    with pytest.raises(OSError, match=missing):
        Sandbox.create("missing-ca-cert", image=MISSING_IMAGE, registry_ca_certs=[missing])


def test_still_rejects_unknown_registry_kwarg() -> None:
    with pytest.raises(TypeError, match="unexpected keyword argument 'registry_bogus'"):
        Sandbox.create("unknown-kwarg", image=MISSING_IMAGE, registry_bogus=1)
