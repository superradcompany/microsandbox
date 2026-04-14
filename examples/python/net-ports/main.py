"""Port publishing — expose a guest HTTP server on a host port."""

import asyncio
import urllib.request

from microsandbox import Sandbox


async def main():
    print("Creating sandbox with published port 8080 → 80")

    sb = await Sandbox.create(
        "net-ports",
        image="alpine",
        cpus=1,
        memory=512,
        ports={8080: 80},
        replace=True,
    )

    # Start a tiny HTTP responder using BusyBox nc.
    output = await sb.shell(
        "(while true; do printf 'HTTP/1.1 200 OK\\r\\nContent-Length: 24\\r\\n"
        "Connection: close\\r\\n\\r\\nHello from microsandbox!' | nc -l -p 80; done) "
        ">/tmp/net-ports.log 2>&1 & echo ok"
    )
    print(f"HTTP server started: {output.stdout_text.strip()}")

    # Fetch from the host side via the published port.
    await asyncio.sleep(1)  # give the server a moment
    try:
        with urllib.request.urlopen("http://127.0.0.1:8080/index.html", timeout=5) as resp:
            print(f"Host-side: {resp.read().decode().strip()}")
    except Exception as e:
        print(f"Host-side: could not reach guest server: {e}")

    await sb.stop_and_wait()
    print("Sandbox stopped.")


asyncio.run(main())
