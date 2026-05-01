"""Logs read — capture stdout/stderr to exec.log and read it back via the SDK."""

import asyncio

from microsandbox import Sandbox


async def main():
    print("Creating sandbox (image=alpine)")

    sb = await Sandbox.create(
        "logs-read",
        image="alpine",
        cpus=1,
        memory=512,
        replace=True,
    )

    # Generate some captured output across stdout and stderr.
    print("Running a small shell script to generate output")
    await sb.shell(
        "echo line one; echo line two; echo error line 1>&2; echo line three"
    )

    # Stop the sandbox so we read a closed log. exec.log persists on disk.
    await sb.stop_and_wait()

    handle = await Sandbox.get("logs-read")

    # Default sources: stdout + stderr + output (user-program output).
    entries = await handle.logs()
    print(f"\n== default sources (stdout+stderr+output): {len(entries)} entries")
    for e in entries:
        print_entry(e)

    # Include system markers + runtime/kernel diagnostics.
    with_system = await handle.logs(
        sources=["stdout", "stderr", "output", "system"]
    )
    print(
        f"\n== including system (runtime/kernel + lifecycle markers): "
        f"{len(with_system)} entries"
    )

    # Tail the last entry.
    tail = await handle.logs(tail=1)
    print(f"\n== tail=1: {len(tail)} entries")
    if tail:
        print_entry(tail[0])


def print_entry(e):
    sid = f"id={e.session_id:>3}" if e.session_id is not None else "id=---"
    print(
        f"  [{e.timestamp_ms / 1000:.3f}] {sid} {e.source}: "
        f"{e.text().rstrip()}"
    )


asyncio.run(main())
