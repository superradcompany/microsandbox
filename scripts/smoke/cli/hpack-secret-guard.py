#!/usr/bin/env python3

import json
import os
import pathlib
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid


ROOT_DIR = pathlib.Path(__file__).resolve().parents[3]
MSB_BIN = pathlib.Path(os.environ.get("MSB_BIN", ROOT_DIR / "build" / "msb"))
IMAGE = os.environ.get("MSB_CLI_SMOKE_PYTHON_IMAGE", "mirror.gcr.io/library/python:3.12-alpine")
HOST = os.environ.get("MSB_CLI_SMOKE_HPACK_HOST", "host.microsandbox.internal")
SECRET_ENV = "MSB_CLI_SMOKE_HPACK_SECRET"
BAD_BLOCKS = ("ff", "67", "7fc5", "342242")
FRAGMENTED_BLOCKS = ("7fc5", "342242")
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
H2_SETTINGS = bytes.fromhex("000000040000000000")
H2_SETTINGS_ACK = H2_SETTINGS


class SmokeFailure(Exception):
    def __init__(self, kind, message):
        super().__init__(f"{kind}: {message}")
        self.kind = kind


class CommandLog:
    def __init__(self, path):
        self.path = path

    def record(self, args, proc):
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {
                        "args": args,
                        "returncode": proc.returncode,
                        "stdout": proc.stdout,
                        "stderr": proc.stderr,
                    }
                )
                + "\n"
            )


class UpstreamSink:
    def __init__(self, root, tls):
        self.root = root
        self.records = []
        self._lock = threading.Lock()
        self._closed = threading.Event()
        self._context = None
        self._socket = socket.socket()
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen()
        self.port = self._socket.getsockname()[1]

        if tls:
            self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._context.load_cert_chain(root / "cert.pem", root / "key.pem")

        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    def close(self):
        self._closed.set()
        try:
            self._socket.close()
        except OSError:
            pass

    def wait_for_record(self, start, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                new = self.records[start:]
                if new and all(record["done"] for record in new):
                    return list(new)
            time.sleep(0.01)
        with self._lock:
            return list(self.records[start:])

    def _accept(self):
        while not self._closed.is_set():
            try:
                conn, _ = self._socket.accept()
            except OSError:
                return
            threading.Thread(target=self._read_one, args=(conn,), daemon=True).start()

    def _read_one(self, conn):
        record = {"bytes": 0, "hex": "", "complete_headers": False, "done": False}
        with self._lock:
            self.records.append(record)

        try:
            conn.settimeout(20)
            if self._context is not None:
                conn = self._context.wrap_socket(conn, server_side=True)

            data = b""
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
                complete_headers = has_complete_headers(data)
                with self._lock:
                    record["bytes"] = len(data)
                    record["hex"] = data.hex()
                    record["complete_headers"] = complete_headers
                if complete_headers:
                    conn.sendall(H2_SETTINGS_ACK)
                    break
        except Exception as error:
            with self._lock:
                record["error"] = repr(error)
        finally:
            try:
                conn.close()
            except OSError:
                pass
            with self._lock:
                record["done"] = True


def has_complete_headers(data):
    if len(data) < len(H2_PREFACE) or data[: len(H2_PREFACE)] != H2_PREFACE:
        return False

    pos = len(H2_PREFACE)
    saw_open_headers = False
    while pos + 9 <= len(data):
        size = int.from_bytes(data[pos : pos + 3], "big")
        kind = data[pos + 3]
        flags = data[pos + 4]
        end = pos + 9 + size
        if end > len(data):
            return False

        if kind == 0x1:
            saw_open_headers = True
            if flags & 0x4:
                return True
        elif kind == 0x9 and saw_open_headers and flags & 0x4:
            return True

        pos = end
    return False


GUEST_PROBE = r"""
import json
import socket
import ssl
import sys
import time

host, port, tls, payload, fragment = sys.argv[1:]
port = int(port)
tls = int(tls)
fragment = int(fragment)


def frame(kind, flags, body):
    return len(body).to_bytes(3, "big") + bytes([kind, flags]) + (1).to_bytes(4, "big") + body


if payload == "valid":
    authority = host.encode()
    scheme = 0x87 if tls else 0x86
    block = bytes([0x82, scheme, 0x84, 0x01, len(authority)]) + authority
else:
    block = bytes.fromhex(payload)

prefix = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + bytes.fromhex("000000040000000000")
if fragment:
    wire = prefix + frame(1, 1, block[:1]) + frame(9, 4, block[1:])
else:
    wire = prefix + frame(1, 5, block)

sock = socket.create_connection((host, port), timeout=12)
if tls:
    sock = ssl._create_unverified_context().wrap_socket(sock, server_hostname=host)

start = time.monotonic()
sock.sendall(wire)
try:
    result = sock.recv(1024)
    outcome = "eof" if not result else "data"
except (ConnectionResetError, ssl.SSLEOFError):
    outcome = "reset"
    result = b""
finally:
    sock.close()

elapsed = round(time.monotonic() - start, 3)
print(json.dumps({"payload": payload, "fragmented": bool(fragment), "outcome": outcome,
                  "received": len(result), "seconds": elapsed}))

if payload == "valid":
    assert outcome == "data"
else:
    assert outcome in ["eof", "reset"]
"""


def main():
    if not MSB_BIN.is_file() or not os.access(MSB_BIN, os.X_OK):
        raise SmokeFailure("setup", f"msb binary is not executable: {MSB_BIN}")

    if sys.platform.startswith("linux") and not os.access("/dev/kvm", os.R_OK | os.W_OK):
        raise SmokeFailure("setup", "/dev/kvm must be readable and writable for CLI smoke tests")

    if shutil.which("openssl") is None:
        raise SmokeFailure("setup", "openssl is required for the TLS HPACK smoke test")

    temp_base = pathlib.Path(os.environ.get("MSB_CLI_SMOKE_TMPDIR", "/tmp"))
    root = pathlib.Path(tempfile.mkdtemp(prefix="msb-h2.", dir=temp_base))
    created_home = False
    if os.environ.get("MSB_HOME"):
        home = pathlib.Path(os.environ["MSB_HOME"])
    else:
        home = root / "home"
        home.mkdir()
        created_home = True

    command_log = CommandLog(root / "commands.jsonl")
    env = os.environ.copy()
    env.update(
        {
            "MSB_HOME": str(home),
            "MSB_PATH": str(MSB_BIN),
            SECRET_ENV: "synthetic-smoke-secret",
        }
    )
    env.pop("MSB_AGENTD_PATH", None)
    env.pop("MSB_API_URL", None)

    names = [f"h2tcp-{uuid.uuid4().hex[:6]}", f"h2tls-{uuid.uuid4().hex[:6]}"]
    results = []

    try:
        generate_certificate(root, command_log)
        for name, tls in [(names[0], False), (names[1], True)]:
            results.append(run_mode(root, home, env, command_log, name, tls))
        (root / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"HPACK secret guard smoke PASS: {root}")
    finally:
        for name in names:
            try:
                run_msb(env, command_log, "remove", "--force", name, timeout=90, check=False)
            except Exception:
                pass
        if created_home:
            shutil.rmtree(home, ignore_errors=True)
        if os.environ.get("MSB_CLI_SMOKE_KEEP_ARTIFACTS") != "1":
            shutil.rmtree(root, ignore_errors=True)
        else:
            print(f"kept smoke artifacts: {root}", file=sys.stderr)


def generate_certificate(root, command_log):
    args = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-subj",
        f"/CN={HOST}",
        "-addext",
        f"subjectAltName=DNS:{HOST}",
        "-keyout",
        str(root / "key.pem"),
        "-out",
        str(root / "cert.pem"),
    ]
    proc = subprocess.run(args, text=True, capture_output=True, timeout=30)
    command_log.record(args, proc)
    if proc.returncode != 0:
        raise SmokeFailure("setup", f"openssl certificate generation failed: {proc.stderr}")


def run_mode(root, home, env, command_log, name, tls):
    sink = UpstreamSink(root, tls)
    try:
        args = [
            "create",
            IMAGE,
            "--name",
            name,
            "--cpus",
            "1",
            "--memory",
            "512M",
            "--log-level",
            "debug",
            "--net-default",
            "allow",
            "--net-rule",
            f"allow@{HOST}",
        ]
        if tls:
            args.extend(
                [
                    "--tls-intercept",
                    "--tls-intercept-port",
                    str(sink.port),
                    "--tls-no-verify-upstream-for",
                    HOST,
                    "--secret",
                    f"{SECRET_ENV}@{HOST}",
                ]
            )

        run_msb(env, command_log, *args, timeout=240)
        identity = machine_identity(name)
        boot_id = run_msb(
            env,
            command_log,
            "exec",
            name,
            "--no-stdin",
            "--",
            "cat",
            "/proc/sys/kernel/random/boot_id",
        ).strip()

        cases = [run_case(env, command_log, name, sink, tls, "valid")]
        for payload in BAD_BLOCKS:
            cases.append(run_case(env, command_log, name, sink, tls, payload))
            assert_same_machine(name, identity)
        for payload in FRAGMENTED_BLOCKS:
            cases.append(run_case(env, command_log, name, sink, tls, payload, fragmented=True))
            assert_same_machine(name, identity)
        cases.append(run_case(env, command_log, name, sink, tls, "valid"))

        later_boot_id = run_msb(
            env,
            command_log,
            "exec",
            name,
            "--no-stdin",
            "--",
            "cat",
            "/proc/sys/kernel/random/boot_id",
        ).strip()
        if later_boot_id != boot_id:
            raise SmokeFailure("product", f"{name} restarted: {boot_id} -> {later_boot_id}")
        assert_same_machine(name, identity)

        still_alive = run_msb(env, command_log, "exec", name, "--no-stdin", "--", "echo", "still-alive").strip()
        if still_alive != "still-alive":
            raise SmokeFailure("product", f"{name} did not execute after malformed HPACK cases")

        runtime_logs = read_runtime_logs(home, name)
        (root / f"{name}-runtime.log").write_text(runtime_logs, encoding="utf-8")
        expected_rejections = len(BAD_BLOCKS) + len(FRAGMENTED_BLOCKS)
        actual_rejections = runtime_logs.count("rejecting guest HTTP/2 header block")
        if actual_rejections < expected_rejections:
            raise SmokeFailure(
                "product",
                f"{name} logged {actual_rejections} HPACK rejections, expected at least {expected_rejections}",
            )
        if "panicked at" in runtime_logs:
            raise SmokeFailure("product", f"{name} runtime log contains a panic")

        return {"name": name, "tls": tls, "boot_id": boot_id, "machine": identity, "cases": cases}
    finally:
        sink.close()
        run_msb(env, command_log, "remove", "--force", name, timeout=90, check=False)


def run_case(env, command_log, name, sink, tls, payload, fragmented=False):
    start = len(sink.records)
    output = run_msb(
        env,
        command_log,
        "exec",
        name,
        "--no-stdin",
        "--timeout",
        "20s",
        "--",
        "python3",
        "-c",
        GUEST_PROBE,
        HOST,
        str(sink.port),
        str(int(tls)),
        payload,
        str(int(fragmented)),
        failure_kind="product",
    )
    result = json.loads(output)
    records = sink.wait_for_record(start, 3)
    if len(records) != 1 or not records[0].get("done"):
        raise SmokeFailure("product", f"{name} produced unexpected upstream records: {records}")

    upstream = bytes.fromhex(records[0]["hex"])
    if payload == "valid":
        if b":authority" not in upstream or HOST.encode() not in upstream:
            raise SmokeFailure("product", f"{name} valid HTTP/2 request was not forwarded correctly")
        if not records[0]["complete_headers"]:
            raise SmokeFailure("product", f"{name} valid HTTP/2 request did not reach upstream headers")
    elif fragmented:
        allowed_prefix = H2_PREFACE + H2_SETTINGS
        if not allowed_prefix.startswith(upstream):
            raise SmokeFailure("product", f"{name} forwarded malformed fragmented headers: {upstream.hex()}")
    elif upstream:
        raise SmokeFailure("product", f"{name} forwarded malformed headers: {upstream.hex()}")

    result["upstream_bytes"] = len(upstream)
    print(json.dumps({"mode": "tls" if tls else "tcp", **result}), flush=True)
    return result


def run_msb(env, command_log, *args, timeout=90, check=True, failure_kind="setup"):
    proc = subprocess.run([str(MSB_BIN), *args], env=env, text=True, capture_output=True, timeout=timeout)
    command_log.record(args, proc)
    if check and proc.returncode != 0:
        raise SmokeFailure(failure_kind, f"msb {' '.join(args)} failed: {proc.stderr or proc.stdout}")
    return proc.stdout


def machine_identity(name):
    proc = subprocess.run(["ps", "-axo", "pid=,lstart=,command="], text=True, capture_output=True, check=True)
    matches = [line.strip() for line in proc.stdout.splitlines() if f" machine " in line and f"--name {name} " in line]
    if len(matches) != 1:
        raise SmokeFailure("product", f"expected one machine process for {name}, found {matches}")
    return matches[0]


def assert_same_machine(name, expected):
    actual = machine_identity(name)
    if actual != expected:
        raise SmokeFailure("product", f"{name} machine process changed:\nexpected: {expected}\nactual:   {actual}")


def read_runtime_logs(home, name):
    parts = []
    for path in sorted(home.rglob("runtime.log")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if f"sandbox={name}" in text:
            parts.append(text)
    if not parts:
        raise SmokeFailure("setup", f"no runtime.log found for {name} under {home}")
    return "\n".join(parts)


if __name__ == "__main__":
    try:
        main()
    except SmokeFailure as error:
        print(error, file=sys.stderr)
        sys.exit(1)
