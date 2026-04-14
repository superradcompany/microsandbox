"""Named volume example — persistent storage across sandboxes."""

import asyncio

from microsandbox import Sandbox, Volume


async def main():
    # Create a named volume.
    data = await Volume.create("my-data", quota_mib=100)

    # Sandbox A writes to the volume.
    writer = await Sandbox.create(
        "writer",
        image="alpine",
        volumes={"/data": Volume.named(data.name)},
        replace=True,
    )

    await writer.shell("echo 'hello from sandbox A' > /data/message.txt")
    await writer.stop_and_wait()

    # Sandbox B reads from the same volume.
    reader = await Sandbox.create(
        "reader",
        image="alpine",
        volumes={"/data": Volume.named(data.name, readonly=True)},
        replace=True,
    )

    output = await reader.shell("cat /data/message.txt")
    print(output.stdout_text)

    await reader.stop_and_wait()

    # Clean up.
    await Sandbox.remove("writer")
    await Sandbox.remove("reader")
    await Volume.remove("my-data")


asyncio.run(main())
