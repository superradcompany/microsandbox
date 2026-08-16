"""Unit tests for virtio-vsock create configuration."""

from __future__ import annotations

from types import MappingProxyType

import pytest

from microsandbox import Sandbox, VsockRoute, VsockSocketType


def test_vsock_route_factories_serialize_stable_socket_types() -> None:
    stream = VsockRoute.stream("/run/host-api.sock", 5000)
    dgram = VsockRoute.dgram("/run/events.sock", 5001)

    assert stream._to_dict() == {
        "host_socket": "/run/host-api.sock",
        "port": 5000,
        "socket_type": "stream",
    }
    assert dgram.socket_type is VsockSocketType.DGRAM
    assert dgram._to_dict()["socket_type"] == "dgram"


def test_sandbox_create_accepts_vsock_mapping_and_typed_routes() -> None:
    with pytest.raises(RuntimeError) as baseline:
        Sandbox.create("vsock-baseline", image="alpine")

    for routes in (
        MappingProxyType({"/run/host-api.sock": 5000}),
        (
            VsockRoute.stream("/run/host-api.sock", 5000),
            VsockRoute.dgram("/run/events.sock", 5001),
        ),
    ):
        with pytest.raises(type(baseline.value)) as accepted:
            Sandbox.create("vsock-config", image="alpine", vsock=routes)
        assert str(accepted.value) == str(baseline.value)


def test_sandbox_create_rejects_unknown_vsock_socket_type() -> None:
    route = VsockRoute("/run/host-api.sock", 5000, "seqpacket")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match=r"VsockRoute\.socket_type"):
        Sandbox.create("bad-vsock", image="alpine", vsock=[route])
