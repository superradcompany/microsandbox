"""Interactive attach — bridge your terminal to a shell inside the sandbox.

Press Ctrl+] to detach, or type `exit` to end the session.
"""

import asyncio

from microsandbox import Sandbox


async def main():
    print("Creating sandbox (image=alpine)")

    sb = await Sandbox.create(
        "attach-example",
        image="alpine",
        cpus=1,
        memory=512,
        replace=True,
    )

    print("Attaching to shell (press Ctrl+] to detach)...")

    exit_code = await sb.attach_shell()
    print(f"Shell exited with code {exit_code}")

    await sb.stop_and_wait()
    print("Sandbox stopped.")


asyncio.run(main())
