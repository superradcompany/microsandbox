"""Opt-in real-provider audit with disposable resources and redacted results."""

# Each loop callback is awaited before the loop advances.
# ruff: noqa: B023

import asyncio
import json
import os
import uuid
from pathlib import Path

from microsandbox import RemoteContext, Sandbox, Snapshot, Stdin, Volume

rows = []
name = "audit-py-" + uuid.uuid4().hex[:8]
report = Path(os.environ["MSB_AUDIT_REPORT"])


def category(error):
    message = str(error)
    if "untagged enum CreateRequest" in message:
        return "config_projection"
    if "401" in message:
        return "http_401"
    if "404" in message or "not found" in message.lower():
        return "not_found"
    if any(
        s in message.lower()
        for s in ("unsupported", "not supported", "local-only", "local only")
    ):
        return "unsupported"
    return type(error).__name__


def save():
    report.write_text(json.dumps({"sdk": "python", "rows": rows}, indent=2) + "\n")


def equal(a, b):
    assert a == b, "unexpected result"


async def check(feature, operation, expect="success", timeout=60):
    try:
        value = await asyncio.wait_for(operation(), timeout)
        rows.append(
            {"feature": feature, "verdict": "PASS" if expect == "success" else "FAIL"}
        )
    except Exception as error:  # noqa: BLE001 - retain every case outcome and continue cleanup
        reason = category(error)
        rows.append(
            {
                "feature": feature,
                "verdict": "UNSUPPORTED"
                if reason == "unsupported"
                else ("PASS" if reason == expect else "FAIL"),
                "reason": reason,
            }
        )
        value = None
    print(json.dumps(rows[-1]), flush=True)
    save()
    return value


async def main():
    assert os.environ.get("MSB_REMOTE_AUDIT") == "1"
    report.with_suffix(".resources.json").write_text(
        json.dumps({"prefix": name}) + "\n"
    )
    c = RemoteContext.from_env()
    s = Sandbox.remote()
    v = Volume.remote()
    p = Snapshot.remote()
    sb = vol = snap = restored = None
    try:
        await check(
            "context_derive", lambda: c.replace(user_agent="msb-audit").sandboxes.list()
        )
        for label, collection in [("sandbox", s), ("volume", v), ("snapshot", p)]:
            await check(label + "_list", collection.list)
            await check(
                label + "_missing",
                lambda collection=collection: collection.get(name + "-missing"),
                "not_found",
            )
        await check("volume_default", v.get_default)
        vol = await check("volume_create", lambda: v.create(name))
        sb = await check(
            "sandbox_create",
            lambda: s.create(
                name,
                image="python",
                ephemeral=False,
                env={"AUDIT_ENV": "retained"},
                labels={"audit": name},
            ),
            timeout=240,
        )
        if sb is None:
            return

        async def identity():
            equal((await s.get(name)).id, sb.id)
            equal(sb.name, name)
            equal(sb.context.kind, "remote")

        await check("sandbox_identity", identity)
        for feature, method in [
            ("info", sb.info),
            ("status", sb.status),
            ("config", sb.config),
            ("failure_message", sb.last_failure_message),
            ("ensure_running", sb.ensure_running),
            ("ping", sb.ping),
            ("touch", sb.touch),
            ("metrics", sb.metrics),
            ("logs", sb.logs),
        ]:
            await check("sandbox_" + feature, method)
        await check("get_running", lambda: s.get_running(name))
        await check("filtered_list", lambda: s.list(labels={"audit": name}, limit=1))

        async def execution():
            o = await sb.exec(
                "/bin/sh",
                ["-c", 'printf "$OVERRIDE:$PWD"; printf err >&2; exit 7'],
                cwd="/tmp",
                env={"OVERRIDE": "set"},
            )
            equal(o.stdout_text, "set:/tmp")
            equal(o.stderr_text, "err")
            equal(o.exit_code, 7)

        await check("exec_options_nonzero", execution)

        async def shell():
            equal((await sb.shell('printf "$AUDIT_ENV"')).stdout_text, "retained")

        await check("shell_environment", shell)

        async def completion():
            e = await sb.shell_stream("printf out; exit 3")
            equal((await e.collect()).stdout_text, "out")
            equal((await e.wait())[0], 3)
            equal((await e.wait())[0], 3)

        await check("exec_collect_repeat_wait", completion)

        async def events():
            e = await sb.shell_stream("printf event; exit 4")
            while await e.recv() is not None:
                pass
            equal((await e.wait())[0], 4)

        await check("exec_recv_wait", events)

        async def kill():
            e = await sb.exec_stream("sleep", ["60"])
            await e.kill()
            assert (await e.wait())[0] != 0

        await check("exec_kill", kill)

        async def stdin():
            e = await sb.exec_stream("cat", stdin=Stdin.pipe())
            w = e.take_stdin()
            assert w is not None
            await w.write(b"input")
            await w.close()
            equal((await e.collect()).stdout_text, "input")

        await check("exec_stdin", stdin)
        for kind, resource, directory in [
            ("sandbox", sb, "/tmp/audit"),
            *([("volume", vol, "audit")] if vol else []),
        ]:
            fs = resource.fs
            await check(kind + "_fs_mkdir", lambda: fs.mkdir(directory))
            await check(
                kind + "_fs_write", lambda: fs.write(directory + "/a", b"hello")
            )

            async def read():
                equal(await fs.read(directory + "/a"), b"hello")
                equal(await fs.read_text(directory + "/a"), "hello")

            await check(kind + "_fs_read", read)
            await check(kind + "_fs_stat", lambda: fs.stat(directory + "/a"))
            await check(kind + "_fs_list", lambda: fs.list(directory))
            await check(
                kind + "_fs_copy", lambda: fs.copy(directory + "/a", directory + "/b")
            )
            await check(
                kind + "_fs_rename",
                lambda: fs.rename(directory + "/b", directory + "/c"),
            )

            async def exists():
                equal(await fs.exists(directory + "/c"), True)
                equal(await fs.exists(directory + "/missing"), False)

            await check(kind + "_fs_exists", exists)
            if hasattr(fs, "write_stream"):

                async def streams():
                    w = await fs.write_stream(directory + "/stream")
                    await w.write(b"stream")
                    await w.close()
                    r = await fs.read_stream(directory + "/stream")
                    equal(await r.collect(), b"stream")
                    await fs.remove(directory + "/stream")

                await check(kind + "_fs_streams", streams)

            async def remove():
                remove_file = fs.remove_file if kind == "volume" else fs.remove
                await remove_file(directory + "/a")
                await remove_file(directory + "/c")
                await fs.remove_dir(directory)

            await check(kind + "_fs_remove", remove)
        if vol:
            await check("volume_info", vol.info)
        await check("jobs_list", sb.list_jobs)
        job = await check(
            "job_create",
            lambda: sb.exec_detached("/bin/sh", ["-c", "printf job; exit 6"]),
        )
        if job:
            await check("job_wait", job.wait)
            await check("job_inspect", job.inspect)
            await check("job_logs", job.logs)
            await check("job_get", lambda: sb.get_job(job.id))
        await check(
            "modify_dry_run", lambda: sb.modify(labels={"audit": name}, dry_run=True)
        )
        await check(
            "modify_labels",
            lambda: sb.modify(labels={"audit": name, "modified": "yes"}),
        )
        await check("pause", sb.pause, "unsupported")
        await check("resume", sb.resume, "unsupported")
        await check("storage_usage", sb.storage_usage, "unsupported")
        await check("detach", sb.detach)
        await check("stop", sb.stop, timeout=420)
        await check("wait_status", lambda: sb.wait_for_status("stopped"))
        await check("wait_stopped", sb.wait_until_stopped)
        snap = await check(
            "snapshot_create", lambda: p.create(name, from_sandbox=name), timeout=240
        )
        if snap:
            await check("snapshot_get", lambda: p.get(snap.reference))
            await check("snapshot_manifest", snap.manifest)
            await check("snapshot_state", snap.state)
            await check("snapshot_verify", snap.verify, "unsupported")
            restored = await check(
                "snapshot_restore",
                lambda: s.restore(snap, name=name + "-restore"),
                timeout=240,
            )
            if restored:
                await check("restored_exec", lambda: restored.shell("printf restored"))
        sb = (
            await check(
                "start_detached", lambda: s.start(name, detached=True), timeout=240
            )
            or sb
        )
        await check("restart", sb.restart, timeout=420)
        await check("kill", sb.kill, "unsupported", timeout=420)
        await check(
            "automatic_start", lambda: sb.shell("printf restarted"), timeout=240
        )
    finally:
        for feature, obj in [
            ("restore_cleanup", restored),
            ("snapshot_cleanup", snap),
            ("sandbox_cleanup", sb),
            ("volume_cleanup", vol),
        ]:
            if obj:
                await check(feature, obj.destroy, timeout=420)
        for feature, collection, ref in [
            ("sandbox_cleanup_verified", s, name),
            ("volume_cleanup_verified", v, name),
            *([("snapshot_cleanup_verified", p, snap.reference)] if snap else []),
        ]:
            await check(
                feature,
                lambda collection=collection, ref=ref: collection.get(ref),
                "not_found",
            )
        save()


asyncio.run(main())
raise SystemExit(any(row["verdict"] == "FAIL" for row in rows))
