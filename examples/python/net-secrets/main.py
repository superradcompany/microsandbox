"""Secret injection — placeholder substitution in TLS-intercepted requests."""

import asyncio

from microsandbox import Sandbox, Secret


async def main():
    # Secret configured via factory. TLS interception auto-enabled.
    sb = await Sandbox.create(
        "net-secrets",
        image="alpine",
        cpus=1,
        memory=512,
        secrets=[
            Secret.env("API_KEY", value="sk-real-secret-123", allow_hosts=["example.com"]),
        ],
        replace=True,
    )

    # 1. Env var auto-set — guest only sees the placeholder.
    output = await sb.shell("echo $API_KEY")
    placeholder = output.stdout_text.strip()
    print(f"Guest env: API_KEY={placeholder}")

    # 2. HTTPS to allowed host — proxy substitutes secret, request succeeds.
    output = await sb.shell(
        "wget -q -O /dev/null --timeout=10 https://example.com && echo OK || echo FAIL"
    )
    print(f"HTTPS to example.com (allowed): {output.stdout_text.strip()}")

    # 3. HTTPS to disallowed host WITH placeholder in header — BLOCKED.
    output = await sb.shell(
        "wget -q -O /dev/null --timeout=5 "
        "--header='Authorization: Bearer $MSB_API_KEY' "
        "https://cloudflare.com 2>&1 && echo OK || echo BLOCKED"
    )
    lines = output.stdout_text.strip().splitlines()
    print(f"HTTPS to cloudflare.com with placeholder (disallowed): {lines[-1] if lines else '?'}")

    await sb.stop_and_wait()
    await Sandbox.remove("net-secrets")


asyncio.run(main())
