"""OCI root example — create a sandbox from an OCI image, run commands, stop."""

import asyncio

from microsandbox import LogLevel, Sandbox


async def main():
    print("Creating sandbox (image=alpine)")

    sb = await Sandbox.create(
        "oci-root",
        image="alpine",
        cpus=1,
        memory=512,
        replace=True,
        log_level=LogLevel.DEBUG,
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
