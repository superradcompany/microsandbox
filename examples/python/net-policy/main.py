"""Network policy — public-only (default), allow-all, and no-network modes."""

import asyncio

from microsandbox import Network, Sandbox


async def main():
    # Default policy: public internet only.
    sb = await Sandbox.create(
        "net-policy-public",
        image="alpine",
        cpus=1,
        memory=512,
        replace=True,
    )
    output = await sb.shell("wget -q -O /dev/null --timeout=5 http://example.com && echo OK || echo FAIL")
    print(f"Public HTTP: {output.stdout_text.strip()}")
    await sb.stop_and_wait()

    # Allow-all: private networks reachable too.
    sb = await Sandbox.create(
        "net-policy-all",
        image="alpine",
        cpus=1,
        memory=512,
        network=Network.allow_all(),
        replace=True,
    )
    output = await sb.shell("wget -q -O /dev/null --timeout=5 http://example.com && echo OK || echo FAIL")
    print(f"Allow-all HTTP: {output.stdout_text.strip()}")
    await sb.stop_and_wait()

    # No network: all connections denied.
    sb = await Sandbox.create(
        "net-policy-none",
        image="alpine",
        cpus=1,
        memory=512,
        network=Network.none(),
        replace=True,
    )
    output = await sb.shell("wget -q -O /dev/null --timeout=3 http://example.com && echo OK || echo BLOCKED")
    print(f"No-network HTTP: {output.stdout_text.strip()}")
    await sb.stop_and_wait()

    await Sandbox.remove("net-policy-public")
    await Sandbox.remove("net-policy-all")
    await Sandbox.remove("net-policy-none")


asyncio.run(main())
