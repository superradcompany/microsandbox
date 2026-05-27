"""Rootfs patch integration tests."""

from __future__ import annotations

import pytest

from microsandbox import Patch


@pytest.mark.asyncio
async def test_rootfs_patches_are_applied(sandbox_factory):
    sandbox = await sandbox_factory(
        "py-sdk-patch",
        patches=[
            Patch.mkdir("/opt/py-sdk"),
            Patch.text("/opt/py-sdk/config.txt", "base\n"),
            Patch.append("/opt/py-sdk/config.txt", "appended\n"),
            Patch.symlink("/opt/py-sdk/config.txt", "/opt/py-sdk/link.txt"),
        ],
    )

    out = await sandbox.shell(
        "test -d /opt/py-sdk && cat /opt/py-sdk/config.txt && cat /opt/py-sdk/link.txt"
    )
    assert out.success is True
    assert out.stdout_text == "base\nappended\nbase\nappended\n"
