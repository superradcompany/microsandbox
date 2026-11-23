#!/usr/bin/env python3
"""Qualify cancellation, late completion and runtime replacement in one disposable VM.

Requires the Python SDK/native binding under test and matching CLI/guest/firmware.
Only memory growth is used. No pressure, shrink or panic is induced.
"""

import argparse
import asyncio
import json
import os
from pathlib import Path
import platform
import sqlite3
import sys
import tarfile
import tempfile
import traceback

import lifecycle_evidence as history


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("binary", "agent", "firmware", "image", "output", "temp-root"):
        parser.add_argument("--" + key, type=Path, required=True)
    args = parser.parse_args()
    for key, value in vars(args).items():
        setattr(args, key, value.resolve())
    history.install_termination_handler()
    args.output.mkdir(exist_ok=False)
    home = Path(tempfile.mkdtemp(prefix="resize-cancel-", dir=args.temp_root))
    env = history.environment(args.binary, args.firmware, home, args.agent)
    os.environ.update(env)
    from microsandbox import ResourceConvergenceState, ResizeOutcome, ResizeTimeoutError, ResizeWaitError, Sandbox
    import microsandbox._microsandbox as native

    runner = history.Runner(args.binary, env, args.output / "commands")
    name = "resize-cancel"
    pids = set()
    report = {"status": "running", "host": platform.platform(), "home": str(home),
              "artifacts": {str(p): history.digest(p) for p in
                            (args.binary, args.agent, args.firmware, args.image, Path(native.__file__), Path(__file__))}}

    def rows(sql):
        database = home / "db/msb.db"
        if not database.exists():
            return []
        with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
            return db.execute(sql).fetchall()

    def identity():
        return rows("SELECT id,pid FROM run WHERE terminated_at IS NULL")

    def collect_pids():
        pids.update(pid for (_, pid) in identity() if pid)

    def guest(label, command):
        runner.run(label, "exec", name, "--", "sh", "-ec", command)

    async def cancel_wait(sandbox, operations):
        # Native async methods return Futures; ensure_future accepts both those and coroutines.
        waiter = asyncio.ensure_future(sandbox.wait_for_resize_operations(operations, timeout=None))
        await asyncio.sleep(0.15)
        assert not waiter.done(), "offline memory unexpectedly settled"
        waiter.cancel()
        try:
            await waiter
        except asyncio.CancelledError:
            pass
        else:
            raise AssertionError("cancelled wait returned completion")

    async def exercise():
        runner.run("load", "image", "load", "--input", args.image)
        with tarfile.open(args.image) as archive:
            image = json.load(archive.extractfile("manifest.json"))[0]["RepoTags"][0]
        runner.run("create", "create", image, "--name", name, "--memory", "256M", "--max-memory", "1G",
                   "--cpus", "1", "--max-cpus", "2", "--root-disk", "512M", "--max-duration", "10m", "--net", "none")
        collect_pids()
        original = identity()
        guest("marker", "echo retained >/dev/shm/cancel-marker; echo retained >/root/cancel-marker; sync")
        guest("offline", "echo offline >/sys/devices/system/memory/auto_online_blocks")
        handle = await Sandbox.get(name)
        sandbox = await handle.connect()
        accepted = await sandbox.modify_with_resize_tracking(memory=512)
        operations = accepted["resize_operations"]
        assert len(operations) == 1 and operations[0]["outcome"] is ResizeOutcome.PENDING
        await cancel_wait(sandbox, operations)
        reconnected = await Sandbox.get(name)
        current = await reconnected.resize_operations()
        assert len(current) == 1 and current[0]["id"] == operations[0]["id"]
        assert current[0]["generation"] == operations[0]["generation"]
        assert current[0]["outcome"] is ResizeOutcome.PENDING
        try:
            await reconnected.wait_for_resize_operations(operations, timeout=0.15)
        except ResizeTimeoutError as error:
            assert len(error.status) == 1 and error.status[0]["state"] is not ResourceConvergenceState.APPLIED
            report["timeout_progress"] = error.status
        else:
            raise AssertionError("offline memory falsely completed after cancellation")
        guest("online", 'for f in /sys/devices/system/memory/memory*/state; do if test "$(cat "$f")" = offline; then echo online_movable >"$f"; fi; done; echo online_movable >/sys/devices/system/memory/auto_online_blocks')
        complete = await reconnected.wait_for_resize_operations(operations, timeout=30)
        assert complete[0]["state"] is ResourceConvergenceState.APPLIED
        assert identity() == original
        guest("retained", 'test "$(cat /dev/shm/cancel-marker)" = retained')
        report.update(accepted_operation=operations, late_completion=complete, retained_identity=original)

        guest("offline-again", "echo offline >/sys/devices/system/memory/auto_online_blocks")
        interrupted = (await sandbox.modify_with_resize_tracking(memory=768))["resize_operations"]
        await cancel_wait(sandbox, interrupted)
        runner.run("stop", "stop", "--force", name)
        for phase in ("stopped", "restarted"):
            if phase == "restarted":
                runner.run("restart", "start", name)
                collect_pids()
                assert identity() != original
                guest("disk-retained", 'test "$(cat /root/cancel-marker)" = retained')
            try:
                await reconnected.wait_for_resize_operations(interrupted, timeout=2)
            except ResizeWaitError as error:
                assert error.reason == "interrupted", (phase, error.reason)
                report[phase] = {"reason": error.reason, "operation_id": error.operation_id, "status": error.status}
            else:
                raise AssertionError("old operation accepted across " + phase)
        report["status"] = "passed"

    try:
        asyncio.run(asyncio.wait_for(exercise(), timeout=180))
    except BaseException as error:
        # Preserve failure evidence on SIGTERM/KeyboardInterrupt/cancellation too.
        # These control-flow exceptions are re-raised through the cleanup finally.
        report.update(status="failed", error=str(error), traceback=traceback.format_exc())
        if not isinstance(error, Exception):
            raise
    finally:
        report["cleanup"] = {name: {}}

        def audit():
            report["remaining_sandboxes"] = len(rows("SELECT id FROM sandbox"))
            report["remaining_live_runs"] = len(identity())
            report["surviving_pids"] = []
            for pid in pids:
                try:
                    os.kill(pid, 0)
                    report["surviving_pids"].append(pid)
                except ProcessLookupError:
                    pass  # A missing PID is the successful teardown observation.
            if report["remaining_sandboxes"] or report["remaining_live_runs"] or report["surviving_pids"]:
                raise RuntimeError("cleanup left sandbox state or live processes")

        history.finish_saved_evidence(runner, report["cleanup"], report, report,
                                      args.output, audit, force=True, prepare=collect_pids)
    print(report["status"], flush=True)
    return report["status"] != "passed"


if __name__ == "__main__":
    sys.exit(main())
