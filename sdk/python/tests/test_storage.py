"""Storage report, selection, and backend capture contracts without starting a VM."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from microsandbox import Storage


@pytest.mark.parametrize("value", [True, False, 1.5, "600", []])
def test_prune_rejects_non_integer_ages_before_scheduling(value: object) -> None:
    with pytest.raises(TypeError, match="older_than_seconds must be an integer"):
        Storage.prune(dry_run=True, older_than_seconds=value)


@pytest.mark.parametrize("value", [-1, 2**64])
def test_prune_rejects_out_of_range_ages_before_scheduling(value: int) -> None:
    with pytest.raises(ValueError, match="older_than_seconds must be between"):
        Storage.prune(dry_run=True, older_than_seconds=value)


@pytest.mark.skipif(sys.platform == "win32", reason="fixture uses Unix flock ownership")
def test_reports_and_pruning_use_the_captured_backend(tmp_path: Path) -> None:
    # A fresh process avoids the SDK's process-wide backend/config cache and cannot reach the
    # user's MSB_HOME. All deletions below target only files created by this test.
    env = os.environ.copy()
    env["MSB_HOME"] = str(tmp_path)
    env["MSB_CONFIG_PATH"] = str(tmp_path / "test-config.json")
    for key in ("MSB_PROFILE", "MSB_BACKEND"):
        env.pop(key, None)
    script = textwrap.dedent(
        """
        import asyncio
        import fcntl
        import os
        from pathlib import Path
        import time
        from microsandbox import (
            BackendKind, MemoryCacheReport, Storage, StorageUsage, UnsupportedError,
            backend_scope, set_default_backend,
        )

        async def main():
            set_default_backend(BackendKind.LOCAL)
            root = Path(os.environ["MSB_HOME"]) / "cache" / "memory"
            branches = root / "branches"
            snapshots = root / "snapshots"
            branches.mkdir(parents=True)
            snapshots.mkdir()
            backing = branches / "branch_fixture-4096.ram"
            lock = backing.with_suffix(".handoff-lock")
            backing.write_bytes(b"x" * 8192)
            lock.touch()
            snapshot = snapshots / ("sha256-" + "a" * 64 + "-4096.ram")
            snapshot.write_bytes(b"y" * 4096)

            usage_call = Storage.usage()
            preview_call = Storage.prune(dry_run=True)
            with backend_scope(BackendKind.CLOUD, url="http://127.0.0.1:9", api_key="test"):
                usage = await usage_call
                preview = await preview_call
                for operation, expected in ((Storage.usage, "storage.usage()"),
                                            (Storage.prune, "storage.prune()")):
                    try:
                        operation()
                    except UnsupportedError as error:
                        assert error.operation == expected
                    else:
                        raise AssertionError("remote operation was accepted")

            assert isinstance(usage, StorageUsage)
            assert usage.branch_memory.count == 1
            assert usage.branch_memory.logical_bytes == 8192
            assert usage.snapshot_memory.logical_bytes == 4096
            assert usage.images.in_use is None
            assert isinstance(preview, MemoryCacheReport)
            assert preview.dry_run and preview.files_removed == 0
            assert preview.logical_bytes_removed == 0
            assert {entry.kind for entry in preview.entries} == {
                "branch_memory", "snapshot_memory"
            }
            assert all(entry.state == "reclaimable" for entry in preview.entries)
            assert backing.exists() and snapshot.exists()
            assert preview.physical_bytes_reclaimed is None

            with backing.open("rb") as pin:
                fcntl.flock(pin, fcntl.LOCK_SH)
                observed = await Storage.prune(dry_run=True)
                branch = next(e for e in observed.entries if e.kind == "branch_memory")
                assert branch.state == "in_use"
            aged = await Storage.prune(dry_run=True, older_than_seconds=2**64 - 1)
            assert all(entry.state == "too_young" for entry in aged.entries)
            old = time.time() - 3600
            os.utime(backing, (old, old))
            os.utime(snapshot, (old, old))
            result = await Storage.prune(older_than_seconds=600)
            assert result.files_removed == 2
            assert result.logical_bytes_removed == 12288
            assert result.physical_bytes_reclaimed is None
            assert all(entry.state == "removed" for entry in result.entries)
            assert not backing.exists() and not snapshot.exists()
            assert lock.exists()
            empty = await Storage.prune(dry_run=True)
            assert empty.entries == [] and empty.files_removed == 0

        asyncio.run(main())
        """
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
