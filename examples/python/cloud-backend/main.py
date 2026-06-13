"""Cloud backend lifecycle and live-log example."""

import asyncio
import os
import time

from microsandbox import Sandbox, default_backend_kind, set_default_backend


def configure_cloud_backend():
    profile = os.getenv("MSB_PROFILE")
    if profile:
        set_default_backend("cloud", profile=profile)
    else:
        url = os.environ["MSB_API_URL"]
        api_key = os.environ["MSB_API_KEY"]
        set_default_backend("cloud", url=url, api_key=api_key)

    if default_backend_kind() != "cloud":
        raise RuntimeError("expected cloud backend")


async def wait_until_stopped(name: str):
    for _ in range(30):
        handle = await Sandbox.get(name)
        if handle.status == "stopped":
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
        sources=["stdout", "stderr", "system"],
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
