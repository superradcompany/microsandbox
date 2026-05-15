"""TLS interception — MITM proxy with per-domain certificate generation."""

import asyncio

from microsandbox import Network, Sandbox, TlsConfig


async def main():
    sb = await Sandbox.create(
        "net-tls",
        image="alpine",
        cpus=1,
        memory=512,
        network=Network(tls=TlsConfig(bypass=("*.bypass-example.com",))),
        replace=True,
    )

    output = await sb.shell("ls /.msb/tls/ca.pem 2>&1 && echo FOUND || echo MISSING")
    lines = output.stdout_text.strip().splitlines()
    print(f"CA cert: {lines[-1] if lines else '?'}")

    output = await sb.shell("echo $SSL_CERT_FILE")
    print(f"SSL_CERT_FILE: {output.stdout_text.strip()}")

    output = await sb.shell("grep -c 'BEGIN CERTIFICATE' /etc/ssl/certs/ca-certificates.crt")
    print(f"Certs in bundle: {output.stdout_text.strip()}")

    # Plain HTTP is unaffected by interception.
    output = await sb.shell("wget -q -O /dev/null --timeout=5 http://example.com && echo OK || echo FAIL")
    print(f"\nHTTP: {output.stdout_text.strip()}")

    # HTTPS through the interception proxy. The guest's trust store has
    # the sandbox CA, so wget's default cert validation succeeds.
    output = await sb.shell(
        "wget -q -O /dev/null --timeout=10 https://example.com 2>&1 && echo OK || echo FAIL"
    )
    print(f"HTTPS (intercepted): {output.stdout_text.strip()}")

    # Cert-validation-disabled path exercises the TCP-only bypass.
    output = await sb.shell(
        "wget --no-check-certificate -q -O /dev/null --timeout=10 https://example.com 2>&1 && echo OK || echo FAIL"
    )
    print(f"HTTPS (no-verify): {output.stdout_text.strip()}")

    await sb.stop_and_wait()
    await Sandbox.remove("net-tls")


asyncio.run(main())
