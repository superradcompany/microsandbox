"""Live lifecycle convergence and identity-safety example."""

import asyncio
import json
import os
import time

from microsandbox import Sandbox, SandboxReplacedError


NAME = os.environ.get("MSB_E2E_NAME", f"lifecycle-python-{os.getpid()}")
IMAGE = os.environ.get("MSB_E2E_IMAGE", "alpine:3.19")
PLATFORM = os.environ.get("MSB_E2E_PLATFORM", os.name)


async def read_marker(sandbox: Sandbox) -> str:
    output = await sandbox.shell("printf '%s' \"$LIFECYCLE_MARKER\"")
    if not output.success:
        raise RuntimeError(f"marker exec failed with code {output.code}")
    return output.stdout_text


async def cleanup() -> None:
    try:
        current = await Sandbox.get(NAME)
        await current.destroy(force=True, timeout=5.0)
    except Exception:
        # The unique example sandbox normally does not exist before or after a run.
        pass


async def main() -> None:
    timings: dict[str, float] = {}
    total = time.perf_counter()

    async def measured(label, operation):
        started = time.perf_counter()
        value = await operation()
        timings[label] = (time.perf_counter() - started) * 1_000
        return value

    await cleanup()
    try:
        created = await measured(
            "find_or_create_new",
            lambda: Sandbox.find_or_create(
                NAME,
                image=IMAGE,
                cpus=1,
                memory=256,
                env={"LIFECYCLE_MARKER": "original"},
            ),
        )
        original_id = await created.id

        reused = await measured(
            "find_or_create_existing",
            lambda: Sandbox.find_or_create(
                NAME,
                image=IMAGE,
                memory=768,
                env={"LIFECYCLE_MARKER": "ignored"},
            ),
        )
        if await reused.id != original_id:
            raise RuntimeError("find_or_create changed the persisted identity")
        if await read_marker(reused) != "original":
            raise RuntimeError("existing configuration did not win")

        handle = await Sandbox.get(NAME)
        connected = await measured("connect_or_start", handle.connect_or_start)
        if await connected.id != original_id:
            raise RuntimeError("connect_or_start changed the persisted identity")

        await measured("wait_for_running", lambda: connected.wait_for_status("running"))

        async def verify_original_marker():
            if await read_marker(connected) != "original":
                raise RuntimeError("exec observed the wrong configuration")

        await measured("exec", verify_original_marker)
        restarted = await measured("restart", connected.restart)
        if await restarted.id != original_id:
            raise RuntimeError("restart changed the persisted identity")
        if await read_marker(restarted) != "original":
            raise RuntimeError("restart lost persisted configuration")

        stale = await Sandbox.get(NAME)
        await measured("destroy_original", restarted.destroy)
        replacement = await Sandbox.find_or_create(
            NAME,
            image=IMAGE,
            cpus=1,
            memory=256,
            env={"LIFECYCLE_MARKER": "replacement"},
        )
        if await replacement.id == original_id:
            raise RuntimeError("replacement reused the destroyed identity")

        async def reject_stale_receiver():
            try:
                await stale.destroy()
            except SandboxReplacedError:
                return
            raise RuntimeError("stale receiver acted on the replacement")

        await measured("stale_identity_rejection", reject_stale_receiver)
        if await read_marker(replacement) != "replacement":
            raise RuntimeError("stale receiver harmed the replacement")
        await measured("destroy_replacement", replacement.destroy)
        timings["total"] = (time.perf_counter() - total) * 1_000

        print(
            "MSB_LIFECYCLE_METRICS "
            + json.dumps(
                {
                    "sdk": "python",
                    "platform": PLATFORM,
                    "sandbox": NAME,
                    "identity": original_id,
                    "checks": 10,
                    "timings_ms": timings,
                    "result": "pass",
                },
                sort_keys=True,
            )
        )
    except Exception:
        await cleanup()
        raise


asyncio.run(main())
