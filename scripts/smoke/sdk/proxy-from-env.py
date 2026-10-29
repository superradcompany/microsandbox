"""End-to-end smoke test for opt-in ambient host proxy discovery (issue #70).

Runs a live VM through the current Python SDK and a local HTTP CONNECT proxy
fixture. Every case installs a complete proxy environment of its own, and every
negative assertion is preceded by a positive control:

- the fixture origin is independent of the proxy, so "the origin accepted a
  connection" is evidence that a direct path reached it, and a proxied
  connection is counted only on the proxy side;
- the direct controls use a destination the guest can actually reach (a host
  address), so "no proxy contact" plus "the origin accepted" proves the direct
  route works, and a 407 rejection with zero origin accepts proves the runtime
  did not fall back to it.

Requirements:
- a runnable `msb` runtime and matching firmware selected with `MSB_PATH` and
  `MSB_LIBKRUNFW_PATH` (use `just build-msb` on macOS so the binary carries its
  entitlements);
- an isolated, short `MSB_HOME` (the script creates one when unset);
- a reachable image (default `alpine`).

Host firewall: every *direct* control dials `host_address():<origin port>` from
inside the guest, so the origin must be reachable on the host LAN address this
script picks. A host firewall that blocks incoming connections to the serving
process makes those cases time out even though the routing decision is correct
— on macOS the application firewall lists Homebrew Python as `Block incoming
connections` (`socketfilterfw --listapps`). Either allow the interpreter or
serve the origin from an allowed process such as a container with a published
port. The script probes this from inside a sandbox first and prints one
`WARN direct controls:` line when the address does not reach the origin; a
host-side dial of the same address proves nothing, because it is answered over
loopback even when the guest's connection is dropped.

Nothing here is a production home or a real credential. All proxy credentials
are synthetic and are never printed.
"""

import asyncio
import ipaddress
import os
import socket
import sys
import tempfile

from microsandbox import Network, OutboundProxy, Sandbox
from microsandbox.types import (
    DnsConfig,
    NetworkPolicy,
    NetworkProfile,
)

# Every spelling the runtime reads. A case sets what it needs and clears the rest,
# so neither a leftover value nor the developer's shell can influence a case.
PROXY_VARIABLES = (
    "http_proxy",
    "HTTP_PROXY",
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "no_proxy",
    "NO_PROXY",
)

# Non-local documentation addresses: only the fixture proxy can tunnel to the
# origin for these, so a direct dial cannot produce an accept.
PROXIED_DESTINATION = "198.51.100.10"
PROXIED_HOST = "excluded.test"

TIMEOUT = 60


class Fixture:
    """Minimal CONNECT proxies plus a controlled origin server.

    Two independent proxy listeners share the origin: the second one lets the
    restart case prove that a restarted sandbox re-read this process's
    environment instead of keeping the endpoint chosen at creation.
    """

    def __init__(self):
        self.connects = []
        self.alt_connects = []
        self.origin_accepts = 0
        self.reject_status = None
        self._servers = []

    async def start(self):
        self.origin = await asyncio.start_server(self._serve_origin, "0.0.0.0", 0)
        self.origin_port = self.origin.sockets[0].getsockname()[1]
        self._servers.append(self.origin)

        self.proxy_port = await self._start_proxy(self.connects)
        self.alt_proxy_port = await self._start_proxy(self.alt_connects)
        return self

    async def _start_proxy(self, connects):
        server = await asyncio.start_server(
            lambda reader, writer: self._serve_proxy(reader, writer, connects),
            "127.0.0.1",
            0,
        )
        self._servers.append(server)
        return server.sockets[0].getsockname()[1]

    async def stop(self):
        for server in self._servers:
            server.close()
        for server in self._servers:
            await server.wait_closed()

    def reset(self, reject_status=None):
        self.connects.clear()
        self.alt_connects.clear()
        self.origin_accepts = 0
        self.reject_status = reject_status

    async def _serve_origin(self, reader, writer):
        self.origin_accepts += 1
        try:
            await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), TIMEOUT)
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
            )
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    async def _serve_proxy(self, reader, writer, connects):
        try:
            request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), TIMEOUT)
            authority = request.decode("latin-1").split("\r\n")[0].split(" ")[1]
            connects.append(authority)
            if self.reject_status is not None:
                writer.write(f"HTTP/1.1 {self.reject_status} Rejected\r\n\r\n".encode())
                await writer.drain()
                return

            upstream_reader, upstream_writer = await asyncio.open_connection(
                "127.0.0.1", self.origin_port
            )
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            await asyncio.gather(
                self._pump(reader, upstream_writer),
                self._pump(upstream_reader, writer),
            )
        except Exception:
            pass
        finally:
            writer.close()

    @staticmethod
    async def _pump(source, destination):
        try:
            while data := await source.read(65536):
                destination.write(data)
                await destination.drain()
        except Exception:
            pass
        finally:
            try:
                destination.close()
            except Exception:
                pass


class DnsFixture:
    """Answer every A query with one fixed address."""

    def __init__(self, port, transport):
        self.port = port
        self._transport = transport

    def stop(self):
        self._transport.close()


async def start_dns_fixture(address):
    loop = asyncio.get_running_loop()

    class Protocol(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, data, raw_address):
            if len(data) < 12:
                return
            answer = (
                data[:2]
                + b"\x81\x80"
                + b"\x00\x01\x00\x01\x00\x00\x00\x00"
                + data[12:]
                + b"\xc0\x0c"
                + b"\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"
                + socket.inet_aton(address)
            )
            self.transport.sendto(answer, raw_address)

    transport, _ = await loop.create_datagram_endpoint(
        Protocol, local_addr=("127.0.0.1", 0)
    )
    return DnsFixture(transport.get_extra_info("sockname")[1], transport)


def _configure_runtime():
    if not os.environ.get("MSB_PATH") or not os.environ.get("MSB_LIBKRUNFW_PATH"):
        sys.exit(
            "BLOCKED: set MSB_PATH and MSB_LIBKRUNFW_PATH to a matching runtime/firmware pair"
        )
    if not os.environ.get("MSB_HOME"):
        home = tempfile.mkdtemp(prefix="msb-ambient-")
        os.environ["MSB_HOME"] = home
        os.environ["MSB_CONFIG_PATH"] = os.path.join(home, "config.json")


def host_address():
    """Return a host address the guest can reach directly, if the host has one.

    A LAN address is what a direct dial from the guest actually uses. Loopback is
    never proxied, so it cannot serve as a direct control for routing decisions.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("198.51.100.10", 80))
            address = probe.getsockname()[0]
    except OSError:
        return None
    if ipaddress.ip_address(address).is_loopback:
        return None
    return address


def set_proxy_environment(http_port=None, https_port=None, no_proxy=None):
    """Replace the whole proxy environment with exactly what this case needs."""
    for name in PROXY_VARIABLES:
        os.environ.pop(name, None)

    def install(port, *names):
        if port is None:
            return
        value = f"http://127.0.0.1:{port}"
        for name in names:
            os.environ[name] = value

    # Both spellings are set so the case cannot depend on case precedence; the
    # lowercase value wins by contract, and uppercase alone is covered by the
    # parser tests.
    install(http_port, "http_proxy", "HTTP_PROXY")
    install(https_port, "https_proxy", "HTTPS_PROXY")
    if no_proxy is not None:
        os.environ["no_proxy"] = no_proxy
        os.environ["NO_PROXY"] = no_proxy


def _network(proxy_from_env, nameserver_port=None, private=False):
    dns = (
        DnsConfig(nameservers=(f"127.0.0.1:{nameserver_port}",))
        if nameserver_port is not None
        else None
    )
    policy = (
        NetworkPolicy.from_profiles([NetworkProfile.PUBLIC, NetworkProfile.PRIVATE])
        if private
        else None
    )
    return Network(proxy_from_env=proxy_from_env, dns=dns, policy=policy)


async def guest_fetch(sandbox, host, port):
    # Busybox wget ships in the base images; it exits non-zero on connect errors.
    return await sandbox.exec("sh", ["-c", f"wget -T 10 -q -O - http://{host}:{port}/"])


async def create_sandbox(name, proxy_from_env, nameserver_port=None, private=False, **kwargs):
    return await Sandbox.create(
        name,
        image="alpine",
        memory=256,
        max_duration=120,
        network=_network(proxy_from_env, nameserver_port, private),
        **kwargs,
    )


async def stop_and_remove(sandbox, name):
    """Stop before removing: the SDK refuses to remove a running sandbox."""
    try:
        await sandbox.stop()
    except Exception:  # noqa: BLE001 - already stopped or never started
        pass
    await Sandbox.remove(name)


async def probe_direct_control(direct_address, fixture):
    """Whether the guest can reach the fixture origin on the host LAN address.

    The direct controls dial `direct_address:<origin port>` from inside the guest,
    so only a guest-side fetch can tell whether that address reaches the origin:
    a host-side dial of the same address is answered over loopback and succeeds
    even when a host firewall drops the guest's connection.

    Returns True/False, or None when the probe could not be attempted (the probe
    must never turn an environment question into a case failure).
    """
    name = f"ambient-probe-{os.getpid()}"
    set_proxy_environment()
    try:
        sandbox = await create_sandbox(name, False, private=True)
    except Exception:  # noqa: BLE001 - the cases report their own setup problems
        return None
    try:
        fixture.reset()
        result = await guest_fetch(sandbox, direct_address, fixture.origin_port)
        return result.exit_code == 0 and fixture.origin_accepts == 1
    except Exception:  # noqa: BLE001
        return None
    finally:
        try:
            await stop_and_remove(sandbox, name)
        finally:
            set_proxy_environment()


async def case_disabled_reads_nothing(fixture):
    name = f"ambient-off-{os.getpid()}"
    fixture.reset()
    set_proxy_environment(http_port=fixture.proxy_port)
    sandbox = await create_sandbox(name, False)
    try:
        result = await guest_fetch(sandbox, PROXIED_DESTINATION, 8080)
        assert result.exit_code != 0, "an explicit false must not route through the proxy"
        assert fixture.connects == [], f"proxy contacted with ambient off: {fixture.connects}"
        assert fixture.origin_accepts == 0, "origin contacted with ambient off"
    finally:
        await stop_and_remove(sandbox, name)
        set_proxy_environment()
    print("PASS explicit false: no proxy reads", flush=True)


async def case_enabled_routes_through_proxy(fixture):
    name = f"ambient-on-{os.getpid()}"
    fixture.reset()
    set_proxy_environment(http_port=fixture.proxy_port)
    sandbox = await create_sandbox(name, True)
    try:
        result = await guest_fetch(sandbox, PROXIED_DESTINATION, 8080)
        assert result.exit_code == 0, result
        assert "ok" in result.stdout_text, result.stdout_text
        assert fixture.connects == [
            f"{PROXIED_DESTINATION}:8080"
        ], fixture.connects
        assert fixture.origin_accepts == 1, fixture.origin_accepts
    finally:
        await stop_and_remove(sandbox, name)
        set_proxy_environment()
    print("PASS enabled: routed through the host proxy with numeric authority", flush=True)


async def case_https_preference_uses_the_tls_port(fixture):
    """The SYN-time classifier, not TLS itself, chooses the TLS candidate.

    Port 443 must use `https_proxy`, and an ordinary port must use `http_proxy`.
    Plain HTTP is used on both ports so no guest TLS stack is involved.
    """
    name = f"ambient-tls-port-{os.getpid()}"
    try:
        # TLS candidate only: port 443 selects `https_proxy`.
        fixture.reset()
        set_proxy_environment(http_port=1, https_port=fixture.proxy_port)
        sandbox = await create_sandbox(name, True)
        try:
            result = await guest_fetch(sandbox, PROXIED_DESTINATION, 443)
            assert result.exit_code == 0, result
            assert fixture.connects == [
                f"{PROXIED_DESTINATION}:443"
            ], fixture.connects
        finally:
            await stop_and_remove(sandbox, name)

        # Ordinary candidate only: a non-443 port selects `http_proxy`.
        fixture.reset()
        set_proxy_environment(http_port=fixture.proxy_port, https_port=1)
        sandbox = await create_sandbox(name, True)
        try:
            result = await guest_fetch(sandbox, PROXIED_DESTINATION, 8080)
            assert result.exit_code == 0, result
            assert fixture.connects == [
                f"{PROXIED_DESTINATION}:8080"
            ], fixture.connects
        finally:
            await stop_and_remove(sandbox, name)
    finally:
        set_proxy_environment()
    print("PASS endpoint preference: port 443 used HTTPS_PROXY, 8080 used HTTP_PROXY", flush=True)


async def case_explicit_proxy_wins(fixture):
    name = f"ambient-explicit-{os.getpid()}"
    fixture.reset()
    # An unreachable ambient endpoint proves the environment was never consulted.
    set_proxy_environment(http_port=1)
    sandbox = await create_sandbox(
        name,
        True,
        proxy=OutboundProxy.http_connect(f"127.0.0.1:{fixture.proxy_port}"),
    )
    try:
        result = await guest_fetch(sandbox, PROXIED_DESTINATION, 8080)
        assert result.exit_code == 0, result
        assert fixture.connects == [
            f"{PROXIED_DESTINATION}:8080"
        ], fixture.connects
    finally:
        await stop_and_remove(sandbox, name)
        set_proxy_environment()
    print("PASS explicit proxy wins without reading the environment", flush=True)


async def case_no_proxy_domain(fixture, direct_address):
    """A live matching name bypasses the proxy, and the direct route reaches the origin."""
    name = f"ambient-noproxy-{os.getpid()}"
    nameserver = await start_dns_fixture(direct_address)
    try:
        # Control: the same request is proxied when no rule matches.
        fixture.reset()
        set_proxy_environment(http_port=fixture.proxy_port)
        sandbox = await create_sandbox(name, True, nameserver.port, private=True)
        try:
            result = await guest_fetch(sandbox, PROXIED_HOST, fixture.origin_port)
            assert result.exit_code == 0, result
            assert fixture.connects, "the control request was not proxied"
        finally:
            await stop_and_remove(sandbox, name)

        # Excluded: the domain rule applies to the live DNS answer and the guest
        # dials the resolved host address directly.
        fixture.reset()
        set_proxy_environment(
            http_port=fixture.proxy_port, no_proxy=f".{PROXIED_HOST}"
        )
        sandbox = await create_sandbox(name, True, nameserver.port, private=True)
        try:
            # Resolve through the sandbox resolver so the NO_PROXY name has a live binding.
            await sandbox.exec("sh", ["-c", f"nslookup {PROXIED_HOST} || true"])
            result = await guest_fetch(sandbox, PROXIED_HOST, fixture.origin_port)
            assert result.exit_code == 0, result
            assert fixture.connects == [], f"excluded domain was proxied: {fixture.connects}"
            assert fixture.origin_accepts == 1, "the direct route did not reach the origin"
        finally:
            await stop_and_remove(sandbox, name)
    finally:
        set_proxy_environment()
        nameserver.stop()
    print("PASS NO_PROXY domain: live DNS name bypassed the proxy", flush=True)


async def _excluded_ip_case(fixture, name, rule, direct_address):
    fixture.reset()
    set_proxy_environment(http_port=fixture.proxy_port, no_proxy=rule)
    sandbox = await create_sandbox(name, True, private=True)
    try:
        result = await guest_fetch(sandbox, direct_address, fixture.origin_port)
        assert result.exit_code == 0, result
        assert fixture.connects == [], f"{rule} did not bypass: {fixture.connects}"
        assert fixture.origin_accepts == 1, "the direct route did not reach the origin"
    finally:
        await stop_and_remove(sandbox, name)


async def case_no_proxy_ip(fixture, direct_address):
    """Bare-IP and CIDR rules both bypass, and both still reach the origin directly."""
    base = f"ambient-noproxy-ip-{os.getpid()}"
    network = ipaddress.ip_network(f"{direct_address}/24", strict=False)
    set_proxy_environment()
    try:
        await _excluded_ip_case(fixture, f"{base}-bare", direct_address, direct_address)
        await _excluded_ip_case(fixture, f"{base}-cidr", str(network), direct_address)
    finally:
        set_proxy_environment()
    print("PASS NO_PROXY IP/CIDR: bare IP and network bypassed the proxy", flush=True)


async def case_failure_never_falls_back(fixture, direct_address):
    """A rejected proxy fails the connection without a direct retry.

    The destination is an address the origin is bound to, so a direct retry would
    increment the origin counter. Zero accepts therefore proves there was none.
    """
    name = f"ambient-fail-{os.getpid()}"
    set_proxy_environment(http_port=fixture.proxy_port)
    try:
        # Control: the request reaches the origin through the proxy.
        fixture.reset()
        sandbox = await create_sandbox(name, True, private=True)
        try:
            result = await guest_fetch(sandbox, direct_address, fixture.origin_port)
            assert result.exit_code == 0, result
            assert fixture.connects, "the control request was not proxied"
            assert fixture.origin_accepts == 1, fixture.origin_accepts

            # The proxy now rejects, and the same destination stays untouched.
            fixture.reset(reject_status=407)
            result = await guest_fetch(sandbox, direct_address, fixture.origin_port)
            assert result.exit_code != 0, "a rejected proxy must fail the connection"
            assert fixture.connects, "the proxy was not selected"
            assert (
                fixture.origin_accepts == 0
            ), "a rejected proxy fell back to a direct dial"
        finally:
            await stop_and_remove(sandbox, name)
    finally:
        set_proxy_environment()
    print("PASS 407: failed without a direct retry", flush=True)


async def case_restart_rereads_environment(fixture):
    """The saved boolean persists, and the next start re-reads this environment.

    The second reachable proxy makes both halves observable: a restarted sandbox
    that lost the boolean routes direct and fails on the unreachable
    documentation address, while one that kept the creator's endpoint contacts
    the first proxy. Success through the second listener can only come from a
    saved `true` combined with a fresh read of the launching environment.
    """
    name = f"ambient-restart-{os.getpid()}"
    fixture.reset()
    set_proxy_environment(http_port=fixture.proxy_port)
    sandbox = await create_sandbox(name, True)
    try:
        result = await guest_fetch(sandbox, PROXIED_DESTINATION, 8080)
        assert result.exit_code == 0 and fixture.origin_accepts == 1, result
        assert fixture.connects == [
            f"{PROXIED_DESTINATION}:8080"
        ], fixture.connects

        await sandbox.stop()
        fixture.reset()
        # The saved boolean survives, but the next network startup reads this
        # process's environment instead of the creator's.
        set_proxy_environment(http_port=fixture.alt_proxy_port)
        sandbox = await Sandbox.start(name)
        result = await guest_fetch(sandbox, PROXIED_DESTINATION, 8080)
        assert result.exit_code == 0, result
        assert fixture.alt_connects == [
            f"{PROXIED_DESTINATION}:8080"
        ], fixture.alt_connects
        assert fixture.connects == [], "the restarted sandbox kept the creator's endpoint"
        assert fixture.origin_accepts == 1, fixture.origin_accepts
    finally:
        await stop_and_remove(sandbox, name)
        set_proxy_environment()
    print("PASS restart: reread the launching environment, kept only the boolean", flush=True)


async def main():
    _configure_runtime()

    direct_address = host_address()
    if direct_address is None:
        sys.exit(
            "BLOCKED: this host has no non-loopback IPv4 address for the direct controls"
        )

    fixture = await Fixture().start()
    print(
        f"fixture: proxy 127.0.0.1:{fixture.proxy_port}, "
        f"replacement proxy 127.0.0.1:{fixture.alt_proxy_port}, origin {direct_address}",
        flush=True,
    )
    if await probe_direct_control(direct_address, fixture) is False:
        # One line, before the direct controls: their assertions cannot pass here and
        # the raw failure does not name the cause.
        print(
            f"WARN direct controls: a guest cannot reach "
            f"{direct_address}:{fixture.origin_port} directly, so the NO_PROXY bypass "
            "cases will fail even when the routing decision is correct. A host firewall "
            "that blocks incoming connections to this interpreter causes exactly this; "
            "allow the interpreter or serve the origin from a container (see the module "
            "docstring).",
            flush=True,
        )
    try:
        await case_disabled_reads_nothing(fixture)
        await case_enabled_routes_through_proxy(fixture)
        await case_https_preference_uses_the_tls_port(fixture)
        await case_explicit_proxy_wins(fixture)
        await case_no_proxy_domain(fixture, direct_address)
        await case_no_proxy_ip(fixture, direct_address)
        await case_failure_never_falls_back(fixture, direct_address)
        await case_restart_rereads_environment(fixture)
    finally:
        set_proxy_environment()
        await fixture.stop()
    print("PASS ambient proxy smoke", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
