#!/usr/bin/env python3
"""Live local-branch preparation regression; isolated VMs, heap/disk churn, no tmpfs.

Uses a matching development msb/agentd/firmware build. Text evidence and phase
timings are retained; only this suite's private home is removed after a clean pass.
This is a correctness smoke test, not a performance-comparison benchmark.
"""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import uuid


HELPER = Path(__file__).with_name("snapshot-branch.py")
SPEC = importlib.util.spec_from_file_location("snapshot_branch_smoke", HELPER)
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)

# Every page contains its index and revision. A separate in-memory revision table
# catches inconsistent RAM capture, and comparison with the open disk file catches
# lost/reordered guest writes. The lock makes a validator wait for any captured
# in-flight update to finish, not mistake a legitimate half-update for corruption.
WORKER = r'''
import hashlib, http.server, json, os, struct, threading, time, urllib.parse, uuid
PAGE = 4096
PAGES = 8192
lock = threading.Lock()
heap = bytearray(PAGE * PAGES)
epochs = [0] * PAGES
extra = []
sequence = generation = 0
tag = "source"
nonce = str(uuid.uuid4())
fd = os.open("/branch-churn.bin", os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600)

def page(index, epoch):
    return struct.pack("<QQ", index, epoch) * (PAGE // 16)

def persist_marker():
    with open("/branch-marker.json", "w") as stream:
        json.dump({"tag": tag, "generation": generation, "nonce": nonce}, stream)

for i in range(PAGES):
    value = page(i, 0)
    heap[i * PAGE:(i + 1) * PAGE] = value
    assert os.pwrite(fd, value, i * PAGE) == PAGE
persist_marker()

def churn():
    global sequence
    while True:
        with lock:
            sequence += 1
            index = sequence % PAGES
            value = page(index, sequence)
            heap[index * PAGE:(index + 1) * PAGE] = value
            assert os.pwrite(fd, value, index * PAGE) == PAGE
            epochs[index] = sequence
        time.sleep(0.002)

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        global generation, tag, extra
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        with lock:
            if parsed.path == "/advance":
                generation += 1
                persist_marker()
            elif parsed.path == "/tag":
                tag = query["value"][0]
                persist_marker()
            elif parsed.path == "/grow":
                # Allocate beyond the 256 MiB boot capacity after online growth.
                # Chunking avoids a second full-size temporary allocation.
                extra = [bytearray(b"\xd3") * 1048576 for _ in range(256)]
            result = dict(nonce=nonce, sequence=sequence, generation=generation,
                          tag=tag, extra_bytes=sum(map(len, extra)),
                          challenge=query.get("challenge", [None])[0])
            with open("/branch-marker.json") as stream:
                result["disk_marker"] = json.load(stream)
            if parsed.path == "/validate":
                for i, epoch in enumerate(epochs):
                    expected = page(i, epoch)
                    assert heap[i * PAGE:(i + 1) * PAGE] == expected, ("RAM", i, epoch)
                    assert os.pread(fd, PAGE, i * PAGE) == expected, ("disk", i, epoch)
                digest = hashlib.sha256()
                expected_digest = hashlib.sha256()
                for block in extra:
                    digest.update(block)
                    expected_digest.update(b"\xd3" * len(block))
                assert digest.digest() == expected_digest.digest(), "grown RAM mismatch"
                result.update(valid=True, checked_heap_bytes=len(heap),
                              checked_disk_bytes=PAGE * PAGES,
                              extra_sha256=digest.hexdigest())
        data = json.dumps(result).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def log_message(self, *args):
        pass

threading.Thread(target=churn, daemon=True).start()
http.server.HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''

COLD_CHECK = r'''
import json, os, struct, sys
with open("/branch-marker.json") as stream:
    marker = json.load(stream)
assert marker["tag"] == sys.argv[1], marker
with open("/branch-churn.bin", "rb") as stream:
    for index in range(8192):
        data = stream.read(4096)
        assert len(data) == 4096, ("short page", index)
        saved_index, epoch = struct.unpack("<QQ", data[:16])
        assert saved_index == index and data == data[:16] * 256, ("bad disk page", index)
    assert not stream.read(1), "unexpected disk payload length"
fs = os.statvfs("/")
print(json.dumps(dict(valid=True, disk_marker=marker, checked_disk_bytes=8192 * 4096,
                      filesystem_bytes=fs.f_blocks * fs.f_frsize)))
'''


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def check_state(state, nonce, generation, tag="source", extra_bytes=0):
    expected_marker = dict(nonce=nonce, generation=generation, tag=tag)
    for key, expected in expected_marker.items():
        if state[key] != expected:
            raise AssertionError(f"{key}: expected {expected!r}, got {state[key]!r}")
    if state["disk_marker"] != expected_marker or state["extra_bytes"] != extra_bytes:
        raise AssertionError(f"RAM/disk marker or grown-memory mismatch: {state}")


class PreparationSmoke(BASE.Smoke):
    def __init__(self, args):
        super().__init__(args)
        self.ports = {}
        self.report.update(suite="local-branch-preparation", started_at=utc_now(),
                           probes=[], runtime_phases={}, backing_chains=[])

    def run(self, case, *args, **kwargs):
        started_at = utc_now()
        print(f"[{started_at}] {case}", flush=True)
        before = len(self.report["commands"])
        try:
            return super().run(case, *args, **kwargs)
        finally:
            if len(self.report["commands"]) > before:
                self.report["commands"][-1].update(started_at=started_at,
                    seconds=self.report["commands"][-1]["ms"] / 1000)
                self.persist()

    def port_option(self, name):
        # Reserve distinct ephemeral ports within this suite, never a fixed shared port.
        while True:
            with socket.socket() as connection:
                connection.bind(("127.0.0.1", 0))
                port = connection.getsockname()[1]
            if port not in self.ports.values():
                self.ports[name] = port
                return f"127.0.0.1:{port}:8080"

    def request(self, name, path="/", timeout=10):
        challenge = uuid.uuid4().hex
        path += ("&" if "?" in path else "?") + "challenge=" + challenge
        connection = http.client.HTTPConnection("127.0.0.1", self.ports[name], timeout=timeout)
        try:
            connection.request("GET", path)
            reply = connection.getresponse()
            body = reply.read()
            if reply.status != 200:
                raise RuntimeError(f"{name}: HTTP {reply.status}: {body!r}")
            result = json.loads(body)
            if result.get("challenge") != challenge:
                raise AssertionError("application did not answer this request's fresh challenge")
            return result
        finally:
            connection.close()

    def probe(self, case, name, path="/validate"):
        started_at, started = utc_now(), time.monotonic()
        result = self.request(name, path, timeout=min(60, self.args.timeout))
        self.report["probes"].append(dict(case=case, sandbox=name, started_at=started_at,
            seconds=time.monotonic() - started, response=result))
        self.persist()
        print(f"[{started_at}] {case}: {self.report['probes'][-1]['seconds']:.3f}s", flush=True)
        return result

    def verify(self, name, generation, tag="source", extra_bytes=0):
        state = self.probe("validate-" + name, name)
        if not state.get("valid") or state["checked_heap_bytes"] != 32 * 1048576:
            raise AssertionError(f"incomplete memory validation: {state}")
        check_state(state, self.nonce, generation, tag, extra_bytes)
        return state

    def branch(self, source, child):
        self.remember(child)
        self.run("branch-" + child, "branch", source, "--name", child,
                 "--port", self.port_option(child))

    def progressing_branch(self, source, child):
        before = self.request(source)
        observations = []
        stop = threading.Event()

        def observe():
            # This is a correctness probe, not part of benchmark latency. Frozen
            # workloads can time out; successful responses must keep their identity.
            while not stop.is_set():
                started = time.monotonic()
                row = dict(started_at=utc_now())
                try:
                    row["response"] = self.request(source, timeout=0.2)
                except (OSError, http.client.HTTPException) as error:
                    row["unavailable"] = str(error)
                row["seconds"] = time.monotonic() - started
                observations.append(row)
                stop.wait(0.01)

        observer = threading.Thread(target=observe, daemon=True)
        observer.start()
        try:
            self.branch(source, child)
        finally:
            stop.set()
            observer.join(timeout=2)
            self.report.setdefault("source_progress", {})[child] = observations
            self.persist()
        deadline = time.monotonic() + 10
        while True:
            after = self.request(source)
            if after["sequence"] > before["sequence"]:
                break
            if time.monotonic() >= deadline:
                raise AssertionError("source worker stopped progressing after branch")
            time.sleep(0.01)
        if after["nonce"] != before["nonce"]:
            raise AssertionError("source restarted instead of continuing")
        for row in observations:
            if "response" in row and row["response"]["nonce"] != before["nonce"]:
                raise AssertionError("source identity changed during branch")

    def harvest_phases(self, name):
        runtime = self.home / "sandboxes" / name / "logs" / "runtime.log"
        if runtime.exists():
            data = runtime.read_text(errors="replace")
            (self.logs / f"{name}.runtime.log").write_text(data)
            self.report["runtime_phases"][name] = [line for line in data.splitlines()
                if "timing" in line or "local_memory" in line]
            self.persist()

    def backing_chain(self, name, label):
        tool = shutil.which("qemu-img")
        if tool is None:
            self.report["backing_chains"].append(dict(case=label, skipped="qemu-img unavailable"))
            return
        journal = json.loads((self.home / "sandboxes" / name / "runtime" / "root-disk.json").read_text())
        head = journal["layers"][-1]["path"]
        started_at, started = utc_now(), time.monotonic()
        result = subprocess.run([tool, "info", "--backing-chain", "--output=json", head],
                                capture_output=True, text=True, timeout=self.args.timeout)
        self.report["backing_chains"].append(dict(case=label, started_at=started_at,
            seconds=time.monotonic() - started, exit=result.returncode,
            stdout=result.stdout, stderr=result.stderr))
        self.persist()
        if result.returncode != 0:
            raise AssertionError(f"{label}: broken backing chain: {result.stderr}")

    def branch_without_ram_cache(self):
        if sys.platform != "linux":
            return
        backend = (self.home / "cache" / "memory").resolve(strict=True)
        namespace = (Path(f"/dev/shm/microsandbox-memory-{os.geteuid()}")
                     / hashlib.sha256(os.fsencode(backend)).hexdigest())
        if not namespace.exists():
            self.report["ram_unavailable_fallback"] = "not applicable: no RAM namespace"
            return
        metadata = namespace.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise AssertionError("RAM fixture namespace is redirected or not owned")
        original_mode = stat.S_IMODE(metadata.st_mode)
        try:
            # Only this fixture's namespace becomes read-only. Existing immutable
            # backings remain readable; a new handoff must choose ordinary disk.
            namespace.chmod(0o500)
            self.branch("source", "disk-fallback")
            self.verify("disk-fallback", 1)
            self.verify("source", 1)
        finally:
            namespace.chmod(original_mode)
        self.report["ram_unavailable_fallback"] = True
        self.persist()
        self.stop("disk-fallback")

    def cold_check(self, name, tag, minimum_disk_bytes=0):
        output = self.run("cold-disk-" + name, "exec", name, "--", "python3", "-c",
                          COLD_CHECK, tag)[0]
        result = json.loads(output)
        if not result["valid"] or result["filesystem_bytes"] < minimum_disk_bytes:
            raise AssertionError(output)

    def exercise(self):
        self.create("source", self.args.image, "--memory", "256M", "--max-memory", "768M",
                    "--cpus", "1", "--max-cpus", "2", "--root-disk", "1G",
                    "--log-level", "info", "--port", self.port_option("source"))
        encoded = base64.b64encode(WORKER.encode()).decode()
        self.guest("start-churning-worker", "source",
            f"echo {shlex.quote(encoded)} | base64 -d > /branch-worker.py; "
            "nohup python3 -u /branch-worker.py >/branch-worker.log 2>&1 </dev/null &")
        deadline = time.monotonic() + 30
        while True:
            try:
                self.nonce = self.request("source")["nonce"]
                break
            except (OSError, http.client.HTTPException):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.05)
        self.verify("source", 0)
        self.progressing_branch("source", "child")
        self.verify("child", 0)

        self.probe("advance-before-preparation", "source", "/advance")
        self.progressing_branch("source", "repeated")
        self.verify("repeated", 1)
        self.verify("child", 0)
        self.verify("source", 1)
        self.branch_without_ram_cache()

        # A durable capture supersedes the retained local dirty baseline. The next
        # branch must capture a fresh complete generation, never reuse the old base.
        self.capture("interleaved", full=True)
        self.probe("advance-after-full", "source", "/advance")
        self.progressing_branch("source", "after-full")
        self.verify("after-full", 2)
        self.verify("repeated", 1)
        self.stop("after-full")
        self.stop("repeated")

        self.run("grow-memory-and-cpus", "modify", "source", "--memory", "512M",
                 "--cpus", "2", "--format", "json")
        self.probe("populate-grown-ram", "source", "/grow")
        self.probe("advance-after-growth", "source", "/advance")
        self.progressing_branch("source", "grown")
        self.verify("grown", 3, extra_bytes=256 * 1048576)
        self.verify("source", 3, extra_bytes=256 * 1048576)
        self.verify("child", 0)
        self.stop("grown")

        self.run("pause-source", "pause", "source")
        self.check_status("source", "Paused")
        self.branch("source", "paused-child")
        self.verify("paused-child", 3, extra_bytes=256 * 1048576)
        self.check_status("source", "Paused")
        self.run("resume-source", "resume", "source")
        self.verify("source", 3, extra_bytes=256 * 1048576)
        self.stop("paused-child")

        self.probe("private-child-write", "child", "/tag?value=child")
        self.progressing_branch("child", "grandchild")
        self.verify("grandchild", 0, "child")
        self.probe("private-grandchild-write", "grandchild", "/tag?value=grandchild")
        self.verify("child", 0, "child")
        self.verify("source", 3, extra_bytes=256 * 1048576)

        self.harvest_phases("source")
        self.stop("source")
        self.run("remove-source", "remove", "source")
        self.verify("child", 0, "child")
        self.verify("grandchild", 0, "grandchild")

        # Maintenance and a cold boot must resolve every child-owned ancestor after
        # deleting the source; a still-running VM's open descriptors can hide a
        # broken path, so successful live reads alone would not prove this invariant.
        self.run("compact-live-child", "modify", "child", "--compact", "--format", "json")
        self.verify("child", 0, "child")
        self.verify("grandchild", 0, "grandchild")
        self.stop("child")
        self.backing_chain("child", "child-after-source-deletion")
        self.run("grow-stopped-child-root", "modify", "child", "--root-disk", "1536M",
                 "--format", "json")
        self.active.append("child")
        self.run("cold-start-child", "start", "child")
        self.cold_check("child", "child", minimum_disk_bytes=1400 * 1048576)
        self.verify("grandchild", 0, "grandchild")
        self.stop("child")
        self.backing_chain("child", "child-after-grow-and-cold-start")

        self.stop("grandchild")
        self.backing_chain("grandchild", "grandchild-after-source-deletion")
        self.active.append("grandchild")
        self.run("cold-start-grandchild", "start", "grandchild")
        self.cold_check("grandchild", "grandchild")
        self.stop("grandchild")

    def cleanup(self):
        for name in self.names:
            try:
                self.harvest_phases(name)
            except OSError as error:
                # Failure to read diagnostics must never prevent the owned VM stops.
                self.report.setdefault("phase_log_errors", []).append(f"{name}: {error}")
        return super().cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=BASE.REPOSITORY / "build" / "msb")
    parser.add_argument("--output", type=Path, help="New private output directory")
    parser.add_argument("--image", default="mirror.gcr.io/library/python:3.13-alpine3.22")
    parser.add_argument("--timeout", type=BASE.positive_seconds, default=90)
    parser.add_argument("--suite-timeout", type=BASE.positive_seconds, default=480)
    args = parser.parse_args()
    args.layout = "managed"

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt("interrupted; cleaning up owned test VMs")

    signal.signal(signal.SIGTERM, interrupted)
    try:
        return PreparationSmoke(args).execute()
    except (OSError, ValueError) as error:
        parser.exit(1, f"branch preparation smoke: {error}\n")


if __name__ == "__main__":
    sys.exit(main())
