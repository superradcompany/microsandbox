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

    # Verify CA cert was placed and installed.
    output = await sb.shell("ls /.msb/tls/ca.pem 2>&1 && echo FOUND || echo MISSING")
    lines = output.stdout_text.strip().splitlines()
    print(f"CA cert: {lines[-1] if lines else '?'}")

    # Check SSL env vars set by agentd.
    output = await sb.shell("echo $SSL_CERT_FILE")
    print(f"SSL_CERT_FILE: {output.stdout_text.strip()}")

    # Count certs in bundle (system + ours).
    output = await sb.shell("grep -c 'BEGIN CERTIFICATE' /etc/ssl/certs/ca-certificates.crt")
    print(f"Certs in bundle: {output.stdout_text.strip()}")

    # HTTP (non-TLS) still works normally.
    output = await sb.shell("wget -q -O /dev/null --timeout=5 http://example.com && echo OK || echo FAIL")
    print(f"\nHTTP: {output.stdout_text.strip()}")

    # HTTPS through the TLS interception proxy.
    output = await sb.shell(
        "wget -q -O /dev/null --timeout=10 https://example.com 2>&1 && echo OK || echo FAIL"
    )
    print(f"HTTPS (intercepted): {output.stdout_text.strip()}")

    # HTTPS with --no-check-certificate to test TCP proxy path.
    output = await sb.shell(
        "wget --no-check-certificate -q -O /dev/null --timeout=10 https://example.com 2>&1 && echo OK || echo FAIL"
    )
    print(f"HTTPS (no-verify): {output.stdout_text.strip()}")

    await sb.stop_and_wait()
    await Sandbox.remove("net-tls")


asyncio.run(main())
