"""Real native removal preserves exact identity and post-publication recovery details."""

import json
import os
import subprocess
import sys
from pathlib import Path


def checkpoint_fixture(tmp_path: Path) -> list[str]:
    # Metadata-only checkpoint fixtures exercise removal, not guest restoration.
    group = tmp_path / "snapshots" / "history"
    ids = [f"snap_{i:032x}" for i in (930, 931)]
    for index, identity in enumerate(ids):
        directory = group / identity
        directory.mkdir(parents=True)
        manifest = {
            "schema": "microsandbox.snapshot/1",
            "snapshot_id": identity,
            "scope": "checkpoint",
            "state": {
                "kind": "checkpoint",
                "checkpoint_id": "checkpoint_test",
                "checkpoint_root": "sha256:" + "a" * 64,
                "restore_intents": ["resume"],
                "requirements_summary": {},
            },
            "capture": {
                "created_at": "2026-09-10T00:00:00Z",
                "source_lineage": None,
                "source_checkpoint": None,
                "consistency": "crash-consistent",
            },
            "image": {
                "reference": "docker.io/library/alpine:3.20",
                "manifest_digest": "sha256:" + "b" * 64,
            },
            "root_disk": {"layout": "managed"},
            "parent": ids[0] if index else None,
            "requires": [],
            "extensions": {},
        }
        (directory / "snapshot.json").write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":"))
        )
    (group / "group.json").write_text(
        json.dumps({"schema": "microsandbox.snapshot-group/1", "head": ids[1]})
    )
    return ids


def test_native_checkpoint_removal(tmp_path: Path) -> None:
    ids = checkpoint_fixture(tmp_path)
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            r"""
import asyncio, os, sqlite3, sys
from pathlib import Path
from microsandbox import Checkpoint, Snapshot, CheckpointRemoveResult, SnapshotRemovalRecoveryError

async def main():
    home = Path(os.environ["MSB_HOME"])
    group = await Snapshot.get("history")
    child = await group.head()
    assert child is not None
    parent = await Checkpoint.open(str(home / "snapshots/history" / sys.argv[1]))
    try:
        await parent.remove()
    except Exception as error:
        assert "child" in str(error), str(error)
    else:
        raise AssertionError("removed a parent with indexed children")
    removed = await child.remove()
    assert isinstance(removed, CheckpointRemoveResult)
    assert removed.id == sys.argv[2]
    assert removed.head_update["head"] == sys.argv[1]
    assert removed.head_update["previous"] == sys.argv[2]
    assert not removed.warnings
    await group.clear_head()
    assert removed.head_update["head"] == sys.argv[1]
    try:
        await child.remove(force=True)
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("manufactured success for missing checkpoint")
    db = sqlite3.connect(home / "db/msb.db")
    db.execute(
        "CREATE TRIGGER reject_removal_cleanup BEFORE DELETE ON snapshot_index "
        "BEGIN SELECT RAISE(FAIL, 'injected cleanup failure'); END"
    )
    db.commit()
    try:
        await parent.remove()
    except SnapshotRemovalRecoveryError as error:
        assert isinstance(error.result, CheckpointRemoveResult)
        assert error.result.id == sys.argv[1]
        assert error.result.head_update["head"] is None
        assert "injected cleanup failure" in error.detail
        assert not (home / "snapshots/history" / sys.argv[1]).exists()
    else:
        raise AssertionError("lost post-publication cleanup failure")
    finally:
        db.execute("DROP TRIGGER reject_removal_cleanup")
        db.commit()
        db.close()

asyncio.run(main())
""",
            *ids,
        ],
        env={
            **os.environ,
            "MSB_HOME": str(tmp_path),
            "MSB_CONFIG_PATH": str(tmp_path / "missing.json"),
        },
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_native_group_removal(tmp_path: Path) -> None:
    ids = checkpoint_fixture(tmp_path)
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            r"""
import asyncio, os, sqlite3, sys
from pathlib import Path
from microsandbox import Snapshot, SnapshotRemoveResult, SnapshotGroupRemovalRecoveryError

async def main():
    home = Path(os.environ["MSB_HOME"])
    group = await Snapshot.get("history")
    # Index both members so a forced post-publication catalog error is observable.
    for member in sys.argv[1:]:
        await group.get_checkpoint(member)
    db = sqlite3.connect(home / "db/msb.db")
    db.execute(
        "CREATE TRIGGER reject_group_cleanup BEFORE DELETE ON snapshot_index "
        "BEGIN SELECT RAISE(FAIL, 'injected group cleanup failure'); END"
    )
    db.commit()
    try:
        await group.remove()
    except SnapshotGroupRemovalRecoveryError as error:
        assert isinstance(error.result, SnapshotRemoveResult)
        assert error.result.group == "history"
        assert error.result.removed == sys.argv[1:]
        assert error.result.head_update["previous"] == sys.argv[2]
        assert error.result.head_update["head"] is None
        assert "injected group cleanup failure" in error.detail
        assert not (home / "snapshots/history").exists()
    else:
        raise AssertionError("lost committed group removal result")
    db.execute("DROP TRIGGER reject_group_cleanup")
    db.commit()
    assert not await Snapshot.list()  # Recovery is discovered despite no surviving group.
    assert db.execute("SELECT count(*) FROM snapshot_index").fetchone()[0] == 0
    db.close()
    empty = home / "snapshots/empty"
    empty.mkdir()
    (empty / "group.json").write_text('{"schema":"microsandbox.snapshot-group/1","head":null}')
    report = await (await Snapshot.get("empty")).remove()
    assert isinstance(report, SnapshotRemoveResult)
    assert report.group == "empty" and report.removed == []
    assert report.head_update["head"] is None and not report.head_update["changed"]
    assert not empty.exists()

asyncio.run(main())
""",
            *ids,
        ],
        env={
            **os.environ,
            "MSB_HOME": str(tmp_path),
            "MSB_CONFIG_PATH": str(tmp_path / "missing.json"),
        },
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_native_group_inspection(tmp_path: Path) -> None:
    ids = checkpoint_fixture(tmp_path)
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            r"""
import asyncio, json, os, sqlite3, sys
from pathlib import Path
from microsandbox import Snapshot

async def main():
    home = Path(os.environ["MSB_HOME"])
    group = await Snapshot.get("history")
    info = await group.inspect()
    assert info["name"] == "history"
    assert info["head"] == sys.argv[2] and info["checkpoint_count"] == 2
    assert info["source"] is None
    await group.clear_head()
    assert (await group.inspect())["head"] is None
    assert info["head"] == sys.argv[2]  # No later head read overwrites this observation.
    source = home / "snapshots/history/group-source.json"
    source.write_text(json.dumps({
        "schema": "microsandbox.snapshot-group-source/1",
        "database_uuid": "12345678-1234-4234-8234-123456789012",
        "sandbox_id": 99, "name": "original",
    }))
    observed = (await group.inspect())["source"]
    assert observed["recorded_name"] == "original" and observed["sandbox_id"] == 99
    assert observed["current_name"] is None and observed["status"] == "different_catalog"
    db = sqlite3.connect(home / "db/msb.db")
    assert not db.execute(
        "SELECT name FROM sqlite_master WHERE name = 'microsandbox_catalog_identity'"
    ).fetchall()
    db.close()

asyncio.run(main())
""",
            *ids,
        ],
        env={
            **os.environ,
            "MSB_HOME": str(tmp_path),
            "MSB_CONFIG_PATH": str(tmp_path / "missing.json"),
        },
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
