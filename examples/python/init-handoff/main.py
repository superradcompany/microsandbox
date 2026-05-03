"""Init-handoff example: hand PID 1 off to systemd.

Uses jrei/systemd-debian:12 — most slim base images strip systemd.
"""

import asyncio

from microsandbox import Sandbox


async def main():
    # "auto" probes /sbin/init, /lib/systemd/systemd, /usr/lib/systemd/systemd.
    sb = await Sandbox.create(
        "init-handoff",
        image="mirror.gcr.io/jrei/systemd-debian:12",
        cpus=2,
        memory=1024,
        replace=True,
        init="auto",
    )

    comm = await sb.shell("cat /proc/1/comm")
    print(f"/proc/1/comm: {comm.stdout_text.strip()}")

    exe = await sb.shell("readlink /proc/1/exe")
    print(f"/proc/1/exe -> {exe.stdout_text.strip()}")

    status = await sb.shell("systemctl is-system-running --wait")
    print(f"systemctl is-system-running: {status.stdout_text.strip()}")

    services = await sb.shell(
        "systemctl list-units --type=service --state=running --no-legend --no-pager"
    )
    print(f"Running services:\n{services.stdout_text.rstrip()}")

    await sb.stop_and_wait()


asyncio.run(main())
