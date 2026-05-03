"""Init-handoff example — hand PID 1 inside the guest off to systemd.

Note: this uses mirror.gcr.io/jrei/systemd-debian:12, a community-built
Debian image with systemd preinstalled. Most slim base images
(debian:bookworm-slim, ubuntu:24.04, etc.) strip systemd entirely; see
docs/sandboxes/customization.mdx for image-picking guidance.
"""

import asyncio

from microsandbox import Sandbox


async def main():
    print("Creating sandbox with init handoff (image=jrei/systemd-debian:12)")

    # Boot a microVM and hand PID 1 off to systemd after agentd's setup.
    # The agent forks; the parent execve's into systemd and becomes PID 1,
    # and the child stays alive serving host requests.
    # `"auto"` asks agentd to probe /sbin/init, /lib/systemd/systemd,
    # /usr/lib/systemd/systemd and pick the first that exists. For
    # reproducible CI, pass an absolute path instead.
    sb = await Sandbox.create(
        "init-handoff",
        image="mirror.gcr.io/jrei/systemd-debian:12",
        cpus=2,
        memory=1024,
        replace=True,
        init="auto",
    )

    # Verify the handoff worked: PID 1 should now be systemd.
    comm = await sb.shell("cat /proc/1/comm")
    print(f"/proc/1/comm: {comm.stdout_text.strip()}")

    exe = await sb.shell("readlink /proc/1/exe")
    print(f"/proc/1/exe -> {exe.stdout_text.strip()}")

    # Wait for systemd to reach a steady state.
    status = await sb.shell("systemctl is-system-running --wait")
    print(f"systemctl is-system-running: {status.stdout_text.strip()}")

    # Show running services to prove systemd is actually managing the system.
    services = await sb.shell(
        "systemctl list-units --type=service --state=running --no-legend --no-pager"
    )
    print(f"Running services:\n{services.stdout_text.rstrip()}")

    # Graceful shutdown takes the signal-based path (SIGRTMIN+4 -> systemd
    # shutdown -> kernel exit).
    await sb.stop_and_wait()
    print("Sandbox stopped.")


asyncio.run(main())
