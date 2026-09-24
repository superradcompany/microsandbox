"""Exercise saved v0.6.18 secret policies with real guest HTTP requests.

Run `create` using released Python SDK/runtime 0.6.18, then `restart` using the
candidate SDK and a released 0.6.18 or 0.7.2 runtime, or candidate runtime.
Set an isolated, short MSB_HOME and explicit MSB_PATH/MSB_LIBKRUNFW_PATH each
time. Keep that home between phases. No production homes or credentials are used. Restart expects the candidate
conversion to merge the old header and Basic Auth scopes. Use
--current-enforcement with v0.7 and select scopes-01/10/11: disabled-location
blocking is checked by the network tests, and scopes-00 is rejected by v0.7.
"""

import argparse
import asyncio
import base64
import shlex

from microsandbox import Sandbox

HOST = "host.microsandbox.internal"
VALUE = "synthetic-upgrade-secret"
CASES = (
    "scopes-00",
    "scopes-01",
    "scopes-10",
    "scopes-11",
    "global-pass",
    "entry-pass",
)


async def probe(sandbox, case, *, merge_header_scopes=False, include_disabled_locations=True):
    token = (await sandbox.exec("printenv", ["REPRO_TOKEN"])).stdout_text.strip()
    assert token and token != VALUE
    received = asyncio.get_running_loop().create_future()

    async def respond(reader, writer):
        try:
            request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
            for header in request.decode().split("\r\n"):
                if header.lower().startswith("content-length:"):
                    request += await asyncio.wait_for(
                        reader.readexactly(int(header.split(":", 1)[1])), 15
                    )
                    break
            if not received.done():
                received.set_result(request.decode())
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
            )
            await writer.drain()
        except Exception as error:
            if not received.done():
                received.set_exception(error)
        finally:
            writer.close()
            await writer.wait_closed()

    async with await asyncio.start_server(respond, "127.0.0.1", 0) as ipv4:
        port = ipv4.sockets[0].getsockname()[1]
        async with await asyncio.start_server(respond, "::1", port):
            basic = base64.b64encode(f"user:{token}".encode()).decode()
            request = (
                f"POST /{token}?key={token} HTTP/1.1\r\nHost: {HOST}:{port}\r\n"
                f"Authorization: Basic {basic}\r\nX-Key: {token}\r\n"
                f"Content-Length: {len(token.encode())}\r\n\r\n{token}"
            )
            if not include_disabled_locations:
                request = (f"GET / HTTP/1.1\r\nHost: {HOST}:{port}\r\n"
                           f"Authorization: Basic {basic}\r\nX-Key: {token}\r\n\r\n")
            command = f"printf %s {shlex.quote(request)} | nc -w 15 {HOST} {port}"
            result = await sandbox.exec("sh", ["-c", command])
            assert result.exit_code == 0 and "200 OK" in result.stdout_text, result
            wire = await asyncio.wait_for(received, 15)
    headers = case.startswith("scopes-") and case[-2] == "1"
    basic_auth = case.startswith("scopes-") and case[-1] == "1"
    if merge_header_scopes:
        headers = basic_auth = headers or basic_auth
    expected_basic = base64.b64encode(
        f"user:{VALUE if basic_auth else token}".encode()
    ).decode()
    assert f"Authorization: Basic {expected_basic}\r\n" in wire, case
    assert f"X-Key: {VALUE if headers else token}\r\n" in wire, case
    if include_disabled_locations:
        assert f"POST /{token}?key={token} HTTP/1.1\r\n" in wire, case
        assert wire.endswith(f"\r\n\r\n{token}"), case


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("create", "restart"))
    parser.add_argument("--case", action="append", choices=CASES)
    parser.add_argument("--current-enforcement", action="store_true")
    args = parser.parse_args()
    for case in args.case or CASES:
        name = "legacy-secret-" + case
        if args.phase == "create":
            from microsandbox import Network, Secret, SecretInjection, ViolationPolicy

            network = Network.allow_all()
            options = {}
            if case == "global-pass":
                network = Network(
                    policy=network.policy,
                    on_secret_violation=ViolationPolicy.passthrough(hosts=[HOST]),
                )
            elif case == "entry-pass":
                options["on_violation"] = ViolationPolicy.passthrough(hosts=[HOST])
            else:
                options["injection"] = SecretInjection(
                    headers=case[-2] == "1", basic_auth=case[-1] == "1"
                )
            sandbox = await Sandbox.create(
                name,
                image="mirror.gcr.io/library/alpine:3.21",
                memory=256,
                max_duration=120,
                network=network,
                detached=True,
                secrets=[
                    Secret.env(
                        "REPRO_TOKEN",
                        value=VALUE,
                        require_tls=False,
                        allow_hosts=[
                            HOST if case.startswith("scopes-") else "other.example"
                        ],
                        **options,
                    )
                ],
            )
        else:
            handle = await Sandbox.get(name)
            sandbox = await handle.start(detached=True)
        try:
            await probe(sandbox, case, merge_header_scopes=args.phase == "restart",
                        include_disabled_locations=not (args.current_enforcement and case.startswith("scopes-")))
        finally:
            await sandbox.stop()
        print(f"PASS {args.phase}: {case}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
