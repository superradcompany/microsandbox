"""Opt-in live CoW lifecycle check using a matching runtime/kernel bundle."""

import asyncio
import os
from pathlib import Path

import pytest

from microsandbox import (
    BranchOutcome,
    Image,
    InvalidConfigError,
    Sandbox,
    SandboxNotFoundError,
    Snapshot,
)


@pytest.mark.skipif(os.environ.get("MSB_COW_LIVE") != "1", reason="requires matching live bundle")
@pytest.mark.asyncio
async def test_cow_resident_capture_and_child_isolation():
    name = f"cow8-python-{os.getpid()}"
    source = await Sandbox.create(name, image="alpine", memory=256)
    child = None
    branches = []
    try:
        await source.exec("sh", ["-c", "echo source > /dev/shm/sdk-marker"])
        await source.pause()
        paused = await Sandbox.get(name)
        assert str(paused.status) == "paused"
        branched = await paused.branch(f"{name}-paused-branch")
        branches.append(branched)
        assert (await branched.exec("cat", ["/dev/shm/sdk-marker"])).stdout_text.strip() == "source"
        snapshot = await Snapshot.create(f"{name}-full", from_sandbox=name, full=True)
        assert (Path(snapshot.path) / "snapshot.json").is_file()
        await paused.resume()
        # The returned artifact path selects the exact member in its snapshot group.
        child = await Sandbox.restore(snapshot.path, name=f"{name}-child", forked=True)
        result = await child.exec("cat", ["/dev/shm/sdk-marker"])
        assert result.stdout_text.strip() == "source"
        await child.exec("sh", ["-c", "echo child > /dev/shm/sdk-marker"])
        descendant = await child.branch(f"{name}-branch")
        branches.append(descendant)
        result = await descendant.exec("cat", ["/dev/shm/sdk-marker"])
        assert result.stdout_text.strip() == "child"
        result = await source.exec("cat", ["/dev/shm/sdk-marker"])
        assert result.stdout_text.strip() == "source"
        await child.pause()
        await child.resume()
    finally:

        async def cleanup(sandbox):
            if str((await Sandbox.get(await sandbox.name)).status) == "paused":
                await sandbox.resume()
            await sandbox.stop()

        results = await asyncio.gather(
            *(cleanup(sandbox) for sandbox in [*branches, *([child] if child else []), source]),
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, BaseException):
                raise result


@pytest.mark.skipif(
    os.environ.get("MSB_BATCH_CANCEL_LIVE") != "1", reason="requires matching live bundle"
)
@pytest.mark.asyncio
async def test_cancel_batch_releases_staging_and_preserves_completed_children():
    name = f"batch-cancel-{os.getpid()}"
    source = await Sandbox.create(
        name, image=Image.oci("mirror.gcr.io/library/alpine:3.20", root_disk=512), memory=256
    )
    names = [f"{name}-{i}" for i in range(40)]
    task = asyncio.ensure_future(source.branch_many(names))
    try:
        # Wait for an actual completed child, then cancel while later names are pending.
        for _ in range(300):
            try:
                first = await Sandbox.get(names[0])
                if str(first.status) == "running":
                    break
            except SandboxNotFoundError:
                # The batch may not have registered its first child yet. Retry after
                # the shared delay below, without hiding unrelated lookup failures.
                pass
            await asyncio.sleep(0.01)
        else:
            pytest.fail("first child did not become running")
        assert not task.done(), "batch completed before cancellation could be exercised"
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        staging = Path(os.environ["MSB_HOME"]) / "sandboxes"
        for _ in range(100):
            if not list(staging.glob(".branch-batch-*")):
                break
            await asyncio.sleep(0.05)
        assert not list(staging.glob(".branch-batch-*")), "cancelled batch retained its staging"
        assert str((await Sandbox.get(name)).status) == "running"
        assert str((await Sandbox.get(names[0])).status) == "running"
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        # Successful detached children intentionally survive cancellation. Stop every
        # requested name so an assertion cannot strand a partially completed batch.
        for child_name in names:
            try:
                child = await Sandbox.get(child_name)
            except Exception:
                continue
            if str(child.status) in {"running", "paused"}:
                await child.stop()
        await source.stop()


@pytest.mark.skipif(os.environ.get("MSB_BATCH_LIVE") != "1", reason="requires matching live bundle")
@pytest.mark.asyncio
async def test_batch_capture_and_handle_api():
    name = f"batch-python-{os.getpid()}"
    source = await Sandbox.create(
        name, image=Image.oci("mirror.gcr.io/library/alpine:3.20", root_disk=512), memory=256
    )
    children = []
    try:
        await source.exec("sh", ["-c", "echo original > /dev/shm/batch-marker"])
        for target in [source, await Sandbox.get(name)]:
            names = [f"{name}-{len(children)}-{i}" for i in range(2)]
            outcomes = await target.branch_many(names)
            children.extend(o.sandbox for o in outcomes if o.sandbox is not None)
            assert [o.name for o in outcomes] == names
            assert all(isinstance(o, BranchOutcome) and o.error is None for o in outcomes)
            for outcome in outcomes:
                assert (
                    await outcome.sandbox.exec("cat", ["/dev/shm/batch-marker"])
                ).stdout_text.strip() == "original"
        await children[0].exec("sh", ["-c", "echo private > /dev/shm/batch-marker"])
        assert (
            await children[1].exec("cat", ["/dev/shm/batch-marker"])
        ).stdout_text.strip() == "original"
        with pytest.raises(InvalidConfigError):
            await source.branch_many([name + "-duplicate", name + "-duplicate"])
        with pytest.raises(InvalidConfigError):
            await source.branch_many([])
    finally:
        results = await asyncio.gather(
            *(s.stop() for s in [*children, source]), return_exceptions=True
        )
        for result in results:
            if isinstance(result, BaseException):
                raise result
