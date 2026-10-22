#!/usr/bin/env python3
"""Qualify snapshot-backed launch with destination SOCKS, trust, mounts and command flags.

The SOCKS fixture serves a fixed HTTP response without contacting its requested target.
Use an isolated MSB_HOME and the matching CLI/agent/firmware. No external image pull is
needed: --archive supplies a self-contained native disk snapshot with an Alpine image.
"""

import argparse
from contextlib import suppress
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import sqlite3
import struct
import subprocess
import tempfile
import threading
import time


TARGET = "198.51.100.10"
TARGET_PORT = 19090
BODY = b"snapshot-destination-proxy\n"
PASSWORD_ENV = "MSB_LAUNCH_FIXTURE_PASSWORD"
DNS_NAME = "private.fixture.test"


def receive(stream, length):
    result = b""
    while len(result) < length:
        part = stream.recv(length - len(result))
        if not part:
            raise EOFError("proxy peer disconnected")
        result += part
    return result


class SocksHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        event = {"authenticated": False, "authentication": "not-attempted",
                 "target": None, "http": False}
        try:
            version, count = receive(self.request, 2)
            methods = receive(self.request, count)
            if version != 5:
                raise ValueError("unexpected SOCKS version")
            method = 2 if self.server.password is not None else 0
            self.request.sendall(bytes([5, method if method in methods else 255]))
            if method not in methods:
                return
            if method == 2:
                version, length = receive(self.request, 2)
                username = receive(self.request, length)
                password = receive(self.request, receive(self.request, 1)[0])
                if version != 1:
                    raise ValueError("unexpected SOCKS authentication version")
                accepted = username == b"fixture" and password == self.server.password
                self.request.sendall(bytes([1, 0 if accepted else 1]))
                event["authentication"] = "accepted" if accepted else "rejected"
                if not accepted:
                    return
            else:
                event["authentication"] = "not-required"
            event["authenticated"] = True
            version, command, reserved, kind = receive(self.request, 4)
            if (version, reserved, kind) != (5, 0, 1):
                raise ValueError("fixture expects an IPv4 SOCKS request")
            address = socket.inet_ntoa(receive(self.request, 4))
            port = struct.unpack("!H", receive(self.request, 2))[0]
            event["target"] = [address, port]
            if command != 1:
                self.request.sendall(b"\x05\x07\x00\x01" + b"\0" * 6)
                return
            if (address, port) != (TARGET, TARGET_PORT):
                raise ValueError("unexpected proxy target")
            self.request.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            request = b""
            while b"\r\n\r\n" not in request and len(request) < 8192:
                request += receive(self.request, 1)
            if not request.startswith(b"GET /probe HTTP/"):
                raise ValueError("unexpected HTTP request")
            event["http"] = True
            self.request.sendall(
                b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "
                + str(len(BODY)).encode() + b"\r\n\r\n" + BODY)
        except (OSError, EOFError, ValueError) as error:
            event["error"] = type(error).__name__
        finally:
            # Do not retain credentials, request headers or exception text.
            with self.server.events_lock:
                self.server.events.append(event)


class SocksFixture(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    protocol = "socks5"

    def __init__(self, password=None, *, handler=SocksHandler):
        self.password = password
        self.events = []
        self.events_lock = threading.Lock()
        self.handlers = set()
        self.handlers_done = threading.Condition(self.events_lock)
        self.closed = False
        super().__init__(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f"{self.protocol}://127.0.0.1:{self.server_address[1]}"

    def process_request(self, request, client_address):
        with self.handlers_done:
            self.handlers.add(request)
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self.handlers_done:
                self.handlers.remove(request)
                self.handlers_done.notify_all()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.handlers_done:
                self.handlers.remove(request)
                self.handlers_done.notify_all()

    def idle(self):
        with self.events_lock:
            return not self.handlers

    def close(self):
        if self.closed:
            return
        self.shutdown()
        self.thread.join(timeout=10)
        if self.thread.is_alive():
            raise RuntimeError("proxy fixture did not stop")
        # Include connections already queued by the kernel when acceptance stopped.
        self.socket.setblocking(False)
        while True:
            try:
                request, address = self.get_request()
            except BlockingIOError:
                break
            self.process_request(request, address)
        self.server_close()
        # Daemon handlers are not joined by socketserver. Stop accepting first,
        # interrupt incomplete handshakes, then wait for their final event records.
        with self.events_lock:
            pending = list(self.handlers)
        for request in pending:
            with suppress(OSError):
                request.shutdown(socket.SHUT_RDWR)
        with self.handlers_done:
            if not self.handlers_done.wait_for(lambda: not self.handlers, timeout=10):
                raise RuntimeError("proxy fixture handlers did not finish")
        self.closed = True


def read_headers(stream):
    """Bound the fixture's buffering; never retain guest/proxy header values."""
    request = b""
    while len(request) < 8192:
        request += receive(stream, 1)
        if request.endswith(b"\r\n\r\n"):
            return request
    raise ValueError("oversized fixture request")


class OtherProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        event = {"authenticated": False, "authentication": "not-attempted",
                 "target": None, "http": False}
        try:
            if self.server.protocol == "http":
                first = read_headers(self.request).split(b"\r\n", 1)[0]
                if first != f"CONNECT {TARGET}:{TARGET_PORT} HTTP/1.1".encode():
                    raise ValueError("unexpected CONNECT request")
                event["target"] = [TARGET, TARGET_PORT]
                event["authentication"] = "not-required"
                self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                version, command, port, address = struct.unpack("!BBH4s", receive(self.request, 8))
                if (version, command) != (4, 1):
                    raise ValueError("unexpected SOCKS4 request")
                user = b""
                for _ in range(256):
                    byte = receive(self.request, 1)
                    if byte == b"\0":
                        break
                    user += byte
                else:
                    raise ValueError("unterminated SOCKS4 user ID")
                event["target"] = [socket.inet_ntoa(address), port]
                if event["target"] != [TARGET, TARGET_PORT]:
                    raise ValueError("unexpected SOCKS4 target")
                accepted = user == (self.server.user_id or b"")
                event["authentication"] = "accepted" if accepted else "rejected"
                self.request.sendall(bytes([0, 90 if accepted else 91]) + struct.pack("!H4s", port, address))
                if not accepted:
                    return
            event["authenticated"] = True
            if not read_headers(self.request).startswith(b"GET /probe HTTP/"):
                raise ValueError("unexpected tunneled HTTP request")
            event["http"] = True
            # No outbound connection is made, even for malformed or rejected targets.
            self.request.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "
                                 + str(len(BODY)).encode() + b"\r\n\r\n" + BODY)
        except (OSError, EOFError, ValueError, struct.error) as error:
            event["error"] = type(error).__name__
        finally:
            with self.server.events_lock:
                self.server.events.append(event)


class HttpFixture(SocksFixture):
    protocol = "http"

    def __init__(self):
        super().__init__(handler=OtherProxyHandler)


class Socks4Fixture(SocksFixture):
    protocol = "socks4"

    def __init__(self, user_id=None):
        self.user_id = user_id
        super().__init__(handler=OtherProxyHandler)


def dns_response(packet):
    """Answer only our single fixture question; never forward to a real resolver."""
    if len(packet) < 17 or struct.unpack("!H", packet[4:6])[0] != 1:
        raise ValueError("expected one DNS question")
    cursor, labels = 12, []
    while True:
        size = packet[cursor]
        cursor += 1
        if size == 0:
            break
        if size > 63 or cursor + size >= len(packet):
            raise ValueError("invalid fixture DNS question")
        labels.append(packet[cursor:cursor + size].decode("ascii"))
        cursor += size
    kind, family = struct.unpack("!HH", packet[cursor:cursor + 4])
    question = packet[12:cursor + 4]
    if ".".join(labels).lower() != DNS_NAME or family != 1:
        raise ValueError("unexpected fixture DNS name")
    answer = b""
    if kind == 1:
        answer = b"\xc0\x0c\x00\x01\x00\x01" + struct.pack("!IH", 0, 4) + socket.inet_aton(TARGET)
    response = packet[:2] + struct.pack("!HHHHH", 0x8180, 1, int(bool(answer)), 0, 0)
    return response + question + answer, kind


class DnsHandler(socketserver.BaseRequestHandler):
    def handle(self):
        packet, transport = self.request
        try:
            response, kind = dns_response(packet)
            self.server.questions.append(kind)
            transport.sendto(response, self.client_address)
        except (ValueError, IndexError, UnicodeError, struct.error):
            self.server.invalid += 1


class DnsFixture(socketserver.UDPServer):
    def __init__(self):
        self.questions, self.invalid = [], 0
        super().__init__(("127.0.0.1", 0), DnsHandler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def address(self):
        return f"127.0.0.1:{self.server_address[1]}"

    def close(self):
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=10)
        if self.thread.is_alive():
            raise RuntimeError("DNS fixture did not stop")


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()

def install_termination_handler():
    def terminate(signum, _frame):
        # Let the first signal unwind through child/VM cleanup; a second TERM
        # must not interrupt that cleanup halfway through.
        signal.signal(signum, signal.SIG_IGN)
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, terminate)


def audit_inputs_and_catalog(report, archive, original_hash, home):
    """Record audit failures without replacing the original qualification error."""
    report["archive_unchanged"] = False
    report["sandbox_count"] = None
    try:
        report["archive_unchanged"] = digest(archive) == original_hash
    except Exception as error:
        report["cleanup"]["archive_audit"] = type(error).__name__
    try:
        # A failed first command may leave no catalog. Never create one merely
        # to audit it, and never let this secondary failure suppress report.json.
        uri = (home / "db/msb.db").resolve().as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True) as database:
            report["sandbox_count"] = database.execute("SELECT COUNT(*) FROM sandbox").fetchone()[0]
    except Exception as error:
        report["cleanup"]["catalog_audit"] = type(error).__name__
    if (any(value != 0 for value in report["cleanup"].values())
            or not report["archive_unchanged"] or report["sandbox_count"] != 0):
        report["status"] = "failed"


def sealed(group):
    # Runtime lock files can change; immutable descriptors and payloads must not.
    return {str(p.relative_to(group)): digest(p) for p in sorted(group.rglob("*"))
            if p.is_file() and p.suffix in (".json", ".ext4", ".erofs")}


class Runner:
    def __init__(self, args, home):
        self.binary, self.output = args.candidate, args.output
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("MSB_")}
        self.env.update(MSB_HOME=str(home), MSB_PATH=str(args.candidate), MSB_BACKEND="local",
                        MSB_CONFIG_PATH=str(home / "config.json"),
                        MSB_LIBKRUNFW_PATH=str(args.firmware), MSB_AGENTD_PATH=str(args.agent),
                        NO_COLOR="1")
        self.commands = []

    def run(self, label, *args, expected=0):
        command = [str(self.binary), *map(str, args)]
        with (self.output / f"{label}.stdout").open("w") as stdout, \
                (self.output / f"{label}.stderr").open("w") as stderr:
            with subprocess.Popen(command, env=self.env, stdin=subprocess.DEVNULL,
                                  stdout=stdout, stderr=stderr, start_new_session=True) as child:
                try:
                    code = child.wait(timeout=180)
                except BaseException:
                    with suppress(ProcessLookupError):
                        os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
                    raise
        self.commands.append({"label": label, "command": command, "exit": code})
        (self.output / "commands.json").write_text(json.dumps(self.commands, indent=2) + "\n")
        print(label, code, flush=True)
        if expected is not None and code != expected:
            raise RuntimeError(f"{label} exited {code}, expected {expected}; see its stderr")
        return code, (self.output / f"{label}.stdout").read_text()


def verify_network(config, proxy):
    network = config["config"]["network"]
    if network["dns"]["rebind_protection"] is not False or network["trust_host_cas"] is not True:
        raise RuntimeError("explicit DNS/trust flags were lost")
    if str(proxy.server_address[1]) not in json.dumps(network["outbound_proxy"]):
        raise RuntimeError("destination proxy was lost")


def qualify(args):
    args.output.mkdir(parents=True, exist_ok=False)
    home = Path(tempfile.mkdtemp(prefix="msb-lp-", dir=args.temp_root)).resolve()
    runner = Runner(args, home)
    original_hash = digest(args.archive)
    project = home / "project"
    project.mkdir()
    (project / "marker").write_text("destination-project\n")
    report = {"status": "running", "home": str(home), "candidate_sha256": digest(args.candidate),
              "agent_sha256": digest(args.agent), "firmware_sha256": digest(args.firmware),
              "archive_sha256": original_hash, "harness_sha256": digest(Path(__file__)),
              "cases": [], "cleanup": {}}
    names = set()
    proxies = []
    resolvers = []
    try:
        runner.run("seed", "snapshot", "load", "seed", "--file", args.archive)
        names.add("source")
        runner.run("source", "create", "--from-snapshot", "seed", "--name", "source", "--pull", "never")
        runner.run("prepare", "exec", "source", "--", "sh", "-ec",
                   "mkdir -p /home/codex; echo snapshot-source > /home/codex/marker; "
                   "chown -R 1000:1000 /home/codex; sync")
        runner.run("capture", "snapshot", "create", "baseline", "--sandbox", "source", "--integrity")
        runner.run("source-stop", "stop", "source")
        runner.run("source-remove", "rm", "source")
        names.remove("source")
        before = sealed(home / "snapshots/baseline")
        if not before:
            raise RuntimeError("no immutable source files to compare")
        fetch = f"wget -T 3 -qO- http://{TARGET}:{TARGET_PORT}/probe"
        # Request private guest IPv4 even when qualification blocks host route
        # discovery. The ephemeral published port is bound only to loopback.
        network_fixture = ["--port", "127.0.0.1:0:18080"]
        for label in ("plain", "authenticated", "http-connect", "socks4", "socks4-user"):
            authenticated = label == "authenticated"
            if label == "http-connect":
                proxy = HttpFixture()
            elif label.startswith("socks4"):
                proxy = Socks4Fixture(b"fixture-user" if label == "socks4-user" else None)
            else:
                proxy = SocksFixture(b"fixture-password" if authenticated else None)
            proxies.append(proxy)
            names.add(label)
            flags = ["--from-snapshot", "baseline", "--name", label, "--pull", "never",
                     "--cpus", "2", "--memory", "256M", "--workdir", "/home/codex",
                     "--user", "1000:1000", "--hostname", "destination",
                     "--proxy", proxy.url, "--net-rule", "allow@198.51.100.0/24",
                     "--no-dns-rebind-protection", "--trust-host-cas",
                     "--mount-dir", f"{project}:/home/codex/project:ro",
                     "--mount-named", "build-cache:/home/codex/cache:nosuid,nodev,noexec,uid=1000,gid=1000",
                     "--env", "LAUNCH=explicit", "--no-stdin", "--no-tty"]
            flags += network_fixture
            if authenticated:
                runner.env[PASSWORD_ENV] = "fixture-password"
                flags += ["--socks5-username", "fixture", "--socks5-password-env", PASSWORD_ENV]
            if label == "socks4-user":
                flags += ["--socks4-user-id", "fixture-user"]
            script = (
                'set -eu; test "$(id -u):$(id -g)" = 1000:1000; test "$PWD" = /home/codex; '
                'test "$LAUNCH" = explicit; test "$(hostname)" = destination; '
                'test "$(cat marker)" = snapshot-source; '
                'test "$(cat project/marker)" = destination-project; '
                'echo cache-write > cache/marker; '
                'test -s /.msb/tls/host-cas.pem; '
                'cmp /.msb/tls/host-cas.pem /usr/local/share/ca-certificates/microsandbox-host-cas.crt; '
                f'test "$(wget -T 5 -qO- http://{TARGET}:{TARGET_PORT}/probe)" = snapshot-destination-proxy; '
                'echo command-stdout; echo command-stderr >&2; exit 37')
            _, stdout = runner.run(label + "-run", "run", *flags, "--", "sh", "-ec", script, expected=37)
            if "command-stdout" not in stdout or "command-stderr" not in (args.output / f"{label}-run.stderr").read_text():
                raise RuntimeError("command streams were lost")
            _, inspect = runner.run(label + "-inspect", "inspect", label, "--format", "json")
            verify_network(json.loads(inspect), proxy)
            # wait() includes the received body, but allow the server's finally block to
            # record the completed connection before checking evidence.
            deadline = time.monotonic() + 5
            while not any(e["http"] for e in proxy.events) and time.monotonic() < deadline:
                time.sleep(0.01)
            if not any(e["http"] and e["authenticated"] for e in proxy.events):
                raise RuntimeError("guest success lacks an observed proxy request")
            report["cases"].append({"case": label, "status": "passed", "proxy": list(proxy.events)})
            runner.run(label + "-stop", "stop", label)
            runner.run(label + "-remove", "rm", label)
            names.remove(label)
        # Create must install the same gateway before a later exec, and retain it on cold
        # restart. This is a separate lifecycle from run's foreground command ownership.
        proxy = SocksFixture()
        proxies.append(proxy)
        names.add("created")
        runner.run("created-create", "create", "--from-snapshot", "baseline", "--name", "created",
                   "--pull", "never", "--proxy", proxy.url, "--net-rule", "allow@198.51.100.0/24",
                   "--trust-host-cas", "--no-dns-rebind-protection", *network_fixture)
        runner.run("created-fetch", "exec", "created", "--", "sh", "-ec",
                   f'test "$({fetch})" = snapshot-destination-proxy; '
                   'echo restart-marker > /home/codex/restart-marker')
        runner.run("created-stop", "stop", "created")
        runner.run("created-restart", "start", "created")
        runner.run("created-fetch-after-restart", "exec", "created", "--", "sh", "-ec",
                   'test "$(cat /home/codex/restart-marker)" = restart-marker; '
                   f'test "$({fetch})" = snapshot-destination-proxy')
        _, inspected = runner.run("created-inspect", "inspect", "created", "--format", "json")
        verify_network(json.loads(inspected), proxy)
        runner.run("created-final-stop", "stop", "created")
        runner.run("created-remove", "rm", "created")
        names.remove("created")
        if sum(e["http"] for e in proxy.events) != 2:
            raise RuntimeError("create/restart did not traverse the proxy twice")
        report["cases"].append({"case": "create-restart", "status": "passed"})

        # File defaults are intentionally opposite to the CLI overrides. A fresh target
        # prevents an existing sandbox's configuration from masquerading as file precedence.
        config = home / "launch.json"
        proxy = SocksFixture(b"file-password")
        proxies.append(proxy)
        runner.env[PASSWORD_ENV] = "file-password"
        # Persist only the environment-variable name. Its value belongs to the child
        # environment above and must never be copied into the configuration file.
        config.write_text(json.dumps({"image": {"snapshot": "baseline"}, "memory": "256M",
                                      "network": {"dns": {"rebind_protection": True},
                                                  "trust_host_cas": False,
                                                  "allow": ["198.51.100.0/24"],
                                                  "proxy": {"url": proxy.url, "username": "fixture",
                                                            "password_env": PASSWORD_ENV}}}))
        names.add("configured")
        runner.run("configured-run", "run", "--conf", config, "--name", "configured",
                   "--trust-host-cas", "--no-dns-rebind-protection", "--no-stdin", *network_fixture, "--",
                   "sh", "-ec", f'test "$({fetch})" = snapshot-destination-proxy')
        _, inspected = runner.run("configured-inspect", "inspect", "configured", "--format", "json")
        verify_network(json.loads(inspected), proxy)
        runner.run("configured-stop", "stop", "configured")
        runner.run("configured-remove", "rm", "configured")
        names.remove("configured")
        report["cases"].append({"case": "config-overrides", "status": "passed"})

        file_defaults = json.loads(config.read_text())
        file_defaults["network"]["dns"]["rebind_protection"] = False
        file_defaults["network"]["trust_host_cas"] = True
        config.write_text(json.dumps(file_defaults))
        for label in ("file-replacement", "cli-replacement", "scoped-config"):
            replacement = SocksFixture()
            proxies.append(replacement)
            names.add(label)
            # A missing old credential must not even be resolved when its endpoint is replaced.
            runner.env.pop(PASSWORD_ENV, None)
            args_for_case = ["--conf", config]
            if label == "file-replacement":
                higher = home / "higher.json"
                higher.write_text(json.dumps({"network": {"proxy": replacement.url}}))
                args_for_case += ["--conf", higher]
            elif label == "cli-replacement":
                args_for_case += ["--proxy", replacement.url]
            else:
                scoped = home / "network.json"
                scoped.write_text(json.dumps({"proxy": replacement.url}))
                args_for_case += ["--net-conf", scoped]
            runner.run(label + "-run", "run", *args_for_case, "--name", label,
                       "--no-stdin", *network_fixture, "--",
                       "sh", "-ec", f'test "$({fetch})" = snapshot-destination-proxy')
            _, inspected = runner.run(label + "-inspect", "inspect", label, "--format", "json")
            parsed = json.loads(inspected)
            verify_network(parsed, replacement)
            if parsed["config"]["network"]["outbound_proxy"].get("credentials") is not None:
                raise RuntimeError("replacement retained the old proxy credentials")
            runner.run(label + "-stop", "stop", label)
            runner.run(label + "-remove", "rm", label)
            names.remove(label)
            report["cases"].append({"case": label, "status": "passed"})

        for disabled in (False, True):
            label = "dns-rebind-disabled" if disabled else "dns-rebind-protected"
            resolver, proxy = DnsFixture(), SocksFixture()
            resolvers.append(resolver)
            proxies.append(proxy)
            names.add(label)
            flags = ["--from-snapshot", "baseline", "--name", label, "--pull", "never",
                     "--proxy", proxy.url, "--dns-nameserver", resolver.address,
                     "--net-default", "allow", "--no-stdin"]
            flags += network_fixture
            if disabled:
                flags.append("--no-dns-rebind-protection")
            request = f"wget -T 3 -qO- http://{DNS_NAME}:{TARGET_PORT}/probe"
            command = (f'test "$({request})" = snapshot-destination-proxy' if disabled
                       else f'if {request}; then exit 97; fi')
            code, _ = runner.run(label + "-run", "run", *flags, "--", "sh", "-ec", command, expected=None)
            _, inspected = runner.run(label + "-inspect", "inspect", label, "--format", "json")
            observed = json.loads(inspected)["config"]["network"]["dns"]["rebind_protection"]
            if observed != (not disabled) or code != 0:
                raise RuntimeError(f"DNS rebind case failed: protection={observed}, command exit={code}")
            runner.run(label + "-stop", "stop", label)
            runner.run(label + "-remove", "rm", label)
            names.remove(label)
            if 1 not in resolver.questions or resolver.invalid:
                raise RuntimeError("rebind test lacks a valid observed DNS A query")
            if bool(any(e["http"] for e in proxy.events)) != disabled:
                raise RuntimeError("DNS-rebind selection did not control actual guest reachability")
            report["cases"].append({"case": label, "status": "passed",
                                    "dns_questions": list(resolver.questions)})

        for label in ("policy-denied", "bad-auth", "missing-credential", "unavailable-proxy"):
            proxy = SocksFixture(b"expected-password" if label in ("bad-auth", "missing-credential") else None)
            proxies.append(proxy)
            names.add(label)
            held = socket.socket()
            try:
                url = proxy.url
                if label == "unavailable-proxy":
                    # Reserve the endpoint without listening, so another process cannot
                    # take this port between the negative test's setup and launch.
                    held.bind(("127.0.0.1", 0))
                    url = f"socks5://127.0.0.1:{held.getsockname()[1]}"
                flags = ["--from-snapshot", "baseline", "--name", label, "--pull", "never",
                         "--proxy", url, "--no-stdin", "--no-tty"]
                flags += network_fixture
                flags += (["--net-default", "deny"] if label == "policy-denied"
                          else ["--net-rule", "allow@198.51.100.0/24"])
                if label in ("bad-auth", "missing-credential"):
                    runner.env.pop(PASSWORD_ENV, None)
                    if label == "bad-auth":
                        runner.env[PASSWORD_ENV] = "wrong-password"
                    flags += ["--socks5-username", "fixture", "--socks5-password-env", PASSWORD_ENV]
                code, stdout = runner.run(label + "-run", "run", *flags, "--", "sh", "-ec",
                                          f'if {fetch}; then exit 97; fi; echo request-refused',
                                          expected=None if label == "missing-credential" else 0)
                if label == "missing-credential":
                    if code == 0 or "request-refused" in stdout:
                        raise RuntimeError("missing credential did not refuse before the command")
                    if PASSWORD_ENV not in (args.output / f"{label}-run.stderr").read_text():
                        raise RuntimeError("missing credential failed for an unrelated reason")
                elif "request-refused" not in stdout:
                    raise RuntimeError("negative request did not finish its refusal assertion")
                inspect_code, _ = runner.run(label + "-inspect", "inspect", label, "--format", "json", expected=None)
                if inspect_code == 0:
                    runner.run(label + "-stop", "stop", label)
                    runner.run(label + "-remove", "rm", label)
                proxy.close()
                if any(e["http"] for e in proxy.events):
                    raise RuntimeError("refused request reached the proxy HTTP endpoint")
                if label == "bad-auth" and not any(
                        e["authentication"] == "rejected" for e in proxy.events):
                    raise RuntimeError("authentication refusal was not observed by the proxy")
                if label in ("policy-denied", "missing-credential") and proxy.events:
                    raise RuntimeError("pre-connection refusal nevertheless contacted the proxy")
                names.remove(label)
                report["cases"].append({"case": label, "status": "passed", "launch_exit": code})
            finally:
                held.close()
        report["sealed_unchanged"] = sealed(home / "snapshots/baseline") == before
        if not report["sealed_unchanged"]:
            raise RuntimeError("launch changed immutable snapshot inputs")
        report["status"] = "passed"
    except BaseException as error:
        report["status"], report["error"] = "failed", str(error)
        raise
    finally:
        for name in sorted(names):
            for operation in ("stop", "rm"):
                try:
                    code, _ = runner.run(f"cleanup-{name}-{operation}", operation, name, expected=None)
                    report["cleanup"][f"{name}/{operation}"] = code
                except Exception as error:
                    report["cleanup"][f"{name}/{operation}"] = type(error).__name__
        for index, fixture in enumerate([*proxies, *resolvers]):
            try:
                fixture.close()
            except Exception as error:
                report["cleanup"][f"fixture/{index}"] = type(error).__name__
        report["proxy_events"] = [p.events for p in proxies]
        audit_inputs_and_catalog(report, args.archive, original_hash, home)
        (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    if report["status"] != "passed":
        raise RuntimeError("qualification cleanup or immutable input check failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("candidate", "agent", "firmware", "archive", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--temp-root", type=Path, default=Path("/tmp"))
    args = parser.parse_args()
    for name, value in vars(args).items():
        if isinstance(value, Path):
            setattr(args, name, value.resolve())
    install_termination_handler()
    qualify(args)


if __name__ == "__main__":
    main()
