"""Bind root example — create a sandbox from a local directory."""

import asyncio
import os
import platform

from microsandbox import Sandbox


async def main():
    arch = platform.machine()
    if arch == "arm64":
        arch = "aarch64"
    rootfs_path = os.path.join(os.path.dirname(__file__), "rootfs-alpine", arch)
    print(f"Creating sandbox (rootfs={rootfs_path})")

    sb = await Sandbox.create(
        "bind-root",
        image=rootfs_path,
        cpus=1,
        memory=512,
        replace=True,
    )

    output = await sb.shell("echo 'Hello from microsandbox!'")
    print(f"stdout: {output.stdout_text}")
    print(f"stderr: {output.stderr_text}")
    print(f"exit code: {output.exit_code}")

    output = await sb.shell("uname -a")
    print(f"uname: {output.stdout_text}")

    output = await sb.shell("cat /etc/os-release")
    print(f"os-release:\n{output.stdout_text}")

    await sb.stop_and_wait()
    print("Sandbox stopped.")


asyncio.run(main())
