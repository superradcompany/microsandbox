"""Rootfs patch example — pre-boot filesystem modifications."""

import asyncio

from microsandbox import Patch, Sandbox


async def main():
    print("Creating sandbox with rootfs patches (image=alpine)")

    sb = await Sandbox.create(
        "rootfs-patch",
        image="alpine",
        cpus=1,
        memory=512,
        replace=True,
        patches=[
            Patch.text("/etc/greeting.txt", "Hello from a patched rootfs!\n"),
            Patch.text("/etc/motd", "Welcome to a patched microsandbox.\n", replace=True),
            Patch.mkdir("/app", mode=0o755),
            Patch.text("/app/config.json", '{"version": "1.0", "debug": true}', mode=0o644),
            Patch.append("/etc/hosts", "127.0.0.1 myapp.local\n"),
        ],
    )

    output = await sb.shell("cat /etc/greeting.txt")
    print(f"greeting: {output.stdout_text.strip()}")

    output = await sb.shell("cat /etc/motd")
    print(f"motd: {output.stdout_text.strip()}")

    output = await sb.shell("cat /app/config.json")
    print(f"config: {output.stdout_text.strip()}")

    output = await sb.shell("grep myapp.local /etc/hosts")
    print(f"hosts entry: {output.stdout_text.strip()}")

    output = await sb.shell("stat -c '%a' /app")
    print(f"/app permissions: {output.stdout_text.strip()}")

    await sb.stop_and_wait()
    print("Sandbox stopped.")


asyncio.run(main())
