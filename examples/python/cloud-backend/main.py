"""Cloud backend lifecycle and live-log example."""

import asyncio
import time

from microsandbox import BackendKind, LogReadSource, Sandbox, SandboxStatus, default_backend_kind


def configure_cloud_backend():
    if default_backend_kind() is not BackendKind.CLOUD:
        raise RuntimeError(
            "set MSB_BACKEND=cloud with MSB_API_KEY, or select a cloud profile"
        )


async def wait_until_stopped(name: str):
    for _ in range(30):
        handle = await Sandbox.get(name)
        if handle.status is SandboxStatus.STOPPED:
            return
        await asyncio.sleep(1)
    raise TimeoutError(f"sandbox {name} did not stop within 30s")


async def main():
    configure_cloud_backend()

    name = f"python-cloud-{int(time.time())}"
    print(f"creating {name} on the cloud backend")

    sandbox = await Sandbox.create(
        name,
        image="alpine:3.19",
        cpus=1,
        memory=512,
        entrypoint=[
            "/bin/sh",
            "-lc",
            "for i in 1 2 3; do echo python-cloud-$i; sleep 1; done",
        ],
        max_duration=60,
        replace=True,
    )

    output = await sandbox.shell("printf 'cloud exec from python\\n'; uname -m")
    print(f"exec status: {output.exit_code}")
    print(output.stdout_text, end="")

    stream = await sandbox.log_stream(
        sources=[
            LogReadSource.STDOUT,
            LogReadSource.STDERR,
            LogReadSource.SYSTEM,
        ],
        follow=True,
    )

    try:
        for _ in range(3):
            try:
                entry = await asyncio.wait_for(stream.__anext__(), timeout=20)
            except StopAsyncIteration:
                break
            except asyncio.TimeoutError:
                print("timed out waiting for another log entry")
                break
            print(f"[{entry.timestamp_ms / 1000:.3f} {entry.source}] {entry.text().rstrip()}")
    finally:
        await sandbox.stop()
        await wait_until_stopped(name)
        await Sandbox.remove(name)
        print(f"removed {name}")


asyncio.run(main())
