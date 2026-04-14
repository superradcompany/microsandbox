"""DNS filtering — block specific domains and suffixes."""

import asyncio

from microsandbox import Network, Sandbox


async def main():
    sb = await Sandbox.create(
        "net-dns",
        image="alpine",
        cpus=1,
        memory=512,
        network=Network(
            block_domains=("blocked.example.com",),
            block_domain_suffixes=(".evil.com",),
        ),
        replace=True,
    )

    # Allowed domain resolves normally.
    output = await sb.shell("nslookup example.com 2>&1 | grep -c Address || echo 0")
    print(f"example.com: {output.stdout_text.strip()} address(es)")

    # Exact-match blocked domain fails.
    output = await sb.shell("nslookup blocked.example.com 2>&1 && echo RESOLVED || echo BLOCKED")
    print(f"blocked.example.com: {output.stdout_text.strip().splitlines()[-1]}")

    # Suffix-match blocked domain fails.
    output = await sb.shell("nslookup anything.evil.com 2>&1 && echo RESOLVED || echo BLOCKED")
    print(f"anything.evil.com: {output.stdout_text.strip().splitlines()[-1]}")

    # Unrelated domain still works.
    output = await sb.shell("nslookup cloudflare.com 2>&1 | grep -c Address || echo 0")
    print(f"cloudflare.com: {output.stdout_text.strip()} address(es)")

    await sb.stop_and_wait()
    await Sandbox.remove("net-dns")


asyncio.run(main())
