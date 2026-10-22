"""Native-boundary coverage for the bind-mount hide_path guard (N5).

`MountConfig._to_dict` already rejects `hide_path` on non-bind mounts at the Python
boundary. These tests bypass that boundary by patching `_to_dict`, then drive
the public `Sandbox.create` entry point so the native `apply_mount` helper is
the code that must reject the mount. No sandbox is started: `Sandbox.create`
runs `sandbox_builder_from_args` synchronously and raises before the async
create task is scheduled.
"""

from __future__ import annotations

import pytest

from microsandbox import MountConfig, MountKind, Sandbox


@pytest.mark.parametrize(
    "mount",
    [
        {"named": "vol", "hide_path": [".env"]},
        {"owned": "dir", "hide_path": [".env"]},
    ],
)
async def test_native_apply_mount_rejects_hide_path_on_non_bind(monkeypatch, mount: dict) -> None:
    monkeypatch.setattr(MountConfig, "_to_dict", lambda self: dict(mount))

    # The rejection happens synchronously in `sandbox_builder_from_args`, before
    # the create task is scheduled, so the await is never reached.
    with pytest.raises(ValueError, match="hide_path is only valid for BIND mounts"):
        await Sandbox.create(
            "native-hide_path-guard",
            image="alpine",
            volumes={"/data": MountConfig(kind=MountKind.BIND)},
        )


async def test_native_apply_mount_accepts_hide_path_on_a_bind(monkeypatch) -> None:
    # Control: the same bypass path must not reject a legitimate bind mount.
    monkeypatch.setattr(
        MountConfig,
        "_to_dict",
        lambda self: {"bind": "/host/data", "readonly": True, "hide_path": ["sub/.env"]},
    )

    create = Sandbox.create(
        "native-hide_path-guard-ok",
        image="alpine",
        volumes={"/data": MountConfig(kind=MountKind.BIND)},
    )
    # The builder accepted the mount. Never await it: the async create task only
    # runs when polled, so no sandbox is started.
    assert create is not None
