"""Interactive attach — bridge your terminal to a shell inside the sandbox.

Press Ctrl+] to detach, or type `exit` to end the session.
"""

import asyncio

from microsandbox import Sandbox


async def main():
    print("Connecting to or creating sandbox (image=alpine on first creation)")

    # An interactive workspace is useful across runs. Creation options seed only
    # the first creation; later runs preserve its files and configuration.
    sb = await Sandbox.connect_or_create(
        "attach-example",
        image="alpine",
        cpus=1,
        memory=512,
    )

    print("Attaching to shell (press Ctrl+] to detach)...")

    exit_code = await sb.attach_shell()
    print(f"Shell exited with code {exit_code}")

    await sb.stop()
    print("Sandbox stopped.")


asyncio.run(main())
