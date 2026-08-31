"""Live lifecycle convergence and identity-safety example."""

import asyncio
import json
import os
import time

from microsandbox import Sandbox, SandboxNotFoundError, SandboxReplacedError

NAME = os.environ.get("MSB_E2E_NAME", f"lifecycle-python-{os.getpid()}")
RACE_NAME = f"{NAME}-race"
IMAGE = os.environ.get("MSB_E2E_IMAGE", "alpine:3.19")
PLATFORM = os.environ.get("MSB_E2E_PLATFORM", os.name)


async def read_marker(sandbox: Sandbox) -> str:
    output = await sandbox.shell("printf '%s' \"$LIFECYCLE_MARKER\"")
    if not output.success:
        raise RuntimeError(f"marker exec failed with code {output.code}")
    return output.stdout_text


async def cleanup(name: str = NAME) -> None:
    try:
        current = await Sandbox.get(name)
        await current.destroy(force=True, timeout=5.0)
    except SandboxNotFoundError:
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

    async def run_concurrency_checks() -> None:
        await cleanup(RACE_NAME)
        candidates = ["candidate-0", "candidate-1", "candidate-2", "candidate-3"]

        async def create_candidate(marker: str) -> Sandbox:
            return await Sandbox.connect_or_create(
                RACE_NAME,
                image=IMAGE,
                cpus=1,
                memory=256,
                env={"LIFECYCLE_MARKER": marker},
            )

        raced = await measured(
            "concurrent_connect_or_create",
            lambda: asyncio.gather(*(create_candidate(marker) for marker in candidates)),
        )
        race_id = await raced[0].id
        race_ids = await asyncio.gather(*(sandbox.id for sandbox in raced))
        if any(identity != race_id for identity in race_ids):
            raise RuntimeError("concurrent connect_or_create callers selected different identities")
        marker = await read_marker(raced[0])
        if marker not in candidates:
            raise RuntimeError(f"concurrent creation persisted unexpected marker {marker!r}")

        await raced[0].stop()
        handles = await asyncio.gather(*(Sandbox.get(RACE_NAME) for _ in candidates))
        connected = await measured(
            "concurrent_connect_or_start",
            lambda: asyncio.gather(*(handle.connect_or_start() for handle in handles)),
        )
        connected_ids = await asyncio.gather(*(sandbox.id for sandbox in connected))
        if any(identity != race_id for identity in connected_ids):
            raise RuntimeError("concurrent connect_or_start callers selected different identities")
        if await read_marker(connected[0]) != marker:
            raise RuntimeError("start race lost persisted configuration")

        await connected[0].stop()
        detached = await measured(
            "connect_or_start_detached",
            lambda: handles[0].connect_or_start(detached=True),
        )
        if await detached.id != race_id or await detached.owns_lifecycle:
            raise RuntimeError(
                "detached connect_or_start changed identity or took lifecycle ownership"
            )

        forced = await measured(
            "restart_force",
            lambda: detached.restart(force=True, timeout=5.0),
        )
        if await forced.id != race_id or not await forced.owns_lifecycle:
            raise RuntimeError(
                "forced restart changed identity or failed to return an attached handle"
            )
        if await read_marker(forced) != marker:
            raise RuntimeError("forced restart lost persisted configuration")

        detached_restart = await measured(
            "restart_detached_timeout",
            lambda: forced.restart(timeout=3.0, detached=True),
        )
        if await detached_restart.id != race_id or await detached_restart.owns_lifecycle:
            raise RuntimeError("detached restart changed identity or took lifecycle ownership")
        if await read_marker(detached_restart) != marker:
            raise RuntimeError("detached restart lost persisted configuration")
        await measured(
            "destroy_force_timeout",
            lambda: detached_restart.destroy(force=True, timeout=5.0),
        )

    await cleanup()
    await cleanup(RACE_NAME)
    try:
        await run_concurrency_checks()
        created = await measured(
            "connect_or_create_new",
            lambda: Sandbox.connect_or_create(
                NAME,
                image=IMAGE,
                cpus=1,
                memory=256,
                env={"LIFECYCLE_MARKER": "original"},
            ),
        )
        original_id = await created.id

        reused = await measured(
            "connect_or_create_existing",
            lambda: Sandbox.connect_or_create(
                NAME,
                image=IMAGE,
                memory=768,
                env={"LIFECYCLE_MARKER": "ignored"},
            ),
        )
        if await reused.id != original_id:
            raise RuntimeError("connect_or_create changed the persisted identity")
        if await read_marker(reused) != "original":
            raise RuntimeError("existing configuration did not win")

        # Strict start resumes an existing stopped identity without accepting creation options.
        await reused.stop()
        resumed = await measured("start", lambda: Sandbox.start(NAME))
        if await resumed.id != original_id:
            raise RuntimeError("start changed the persisted identity")
        if await read_marker(resumed) != "original":
            raise RuntimeError("start lost persisted configuration")

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
        replacement = await Sandbox.connect_or_create(
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
                    "checks": 17,
                    "timings_ms": timings,
                    "result": "pass",
                },
                sort_keys=True,
            )
        )
    except Exception:
        await cleanup()
        await cleanup(RACE_NAME)
        raise


asyncio.run(main())
