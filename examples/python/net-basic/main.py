"""Basic networking — DNS resolution, HTTP fetch, and interface status."""

import asyncio

from microsandbox import Sandbox


async def main():
    sb = await Sandbox.create(
        "net-basic",
        image="alpine",
        cpus=1,
        memory=512,
        replace=True,
    )

    # DNS resolution.
    output = await sb.shell("nslookup example.com 2>&1 | head -8")
    print(f"DNS:\n{output.stdout_text}")

    # HTTP fetch.
    output = await sb.shell("wget -q -O - http://example.com 2>&1 | head -3")
    print(f"HTTP:\n{output.stdout_text}")

    # Interface status.
    output = await sb.shell("ip addr show eth0")
    print(f"Interface:\n{output.stdout_text}")

    await sb.stop_and_wait()


asyncio.run(main())
