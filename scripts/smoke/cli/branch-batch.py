#!/usr/bin/env python3
"""Live capture-once branching invariants and paired batch/loop timings; owns its test VMs."""

import argparse
from contextlib import closing, contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import sqlite3
import statistics
import subprocess
import sys
import time

if os.name == "posix":
    import fcntl

spec = importlib.util.spec_from_file_location("snapshot_branch", Path(__file__).with_name("snapshot-branch.py"))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)

# Keep actual RAM resident, plus data on the root disk. No tmpfs workload or disk.
WORKER = """
import hashlib, http.server, os
ram = bytearray(b'a' * (32 * 1024 * 1024))
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/write/'):
            ram[:8] = self.path.rsplit('/', 1)[1].encode().ljust(8, b'_')[:8]
        self.send_response(200)
        self.end_headers()
        self.wfile.write(hashlib.blake2s(ram).hexdigest().encode() if self.path == '/digest' else bytes(ram[:8]))
    def log_message(self, *args): pass
http.server.HTTPServer(('127.0.0.1', 8080), Handler).serve_forever()
"""


class BatchSmoke(smoke.Smoke):
    def __init__(self, args):
        super().__init__(args)
        self.report["fixture"] = {"cpus": args.cpus, "memory": args.memory, "disk": args.disk,
                                  "heap_mib": args.heap_mib, "data_mib": args.data_mib,
                                  "integrity": args.integrity, "children": args.children,
                                  "repeats": args.repeats,
                                  "baseline_binary": str(args.baseline_binary) if args.baseline_binary else None}

    def batch(self, source, names, label, *options):
        for name in names:
            self.remember(name)
        _, output = self.run(label, "branch", source, "--names", *names, *options)
        self.verify_output_order(output, names)

    @staticmethod
    def verify_output_order(output, names):
        # Completion order may vary; the CLI publishes successful outcomes in input order.
        reported = re.findall(r"Branched\s+(\S+)", output)
        assert reported == names, f"batch outcome order differs: {reported!r}, expected {names!r}"

    @contextmanager
    def held_lock(self, name, lineage=False):
        # Match runtime/client/ipc.rs. These stable lock inodes must never be unlinked.
        digest = hashlib.sha256(name.encode()).hexdigest()[:32]
        directory = self.home / "run" / ("locks" if lineage else "creation-locks")
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / (digest + (".snapshot-lineage.lock" if lineage else ".lock"))
        with path.open("a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                yield lambda: fcntl.flock(lock, fcntl.LOCK_UN)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    @staticmethod
    def wait_until(process, deadline, predicate, description):
        while not predicate():
            if process.poll() is not None:
                raise RuntimeError(f"batch exited before {description}: {process.returncode}")
            if time.monotonic() >= deadline:
                raise RuntimeError(f"timed out waiting for {description}")
            time.sleep(0.01)

    def statuses(self):
        database = self.home / "db/msb.db"
        with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=2)) as db:
            return dict(db.execute('SELECT name, status FROM "sandbox"'))

    def observed_batch(self, case, names, observe, *options, expected_failure=False):
        # Own the client process while inspecting a deterministic lock boundary. File-backed
        # output cannot fill a pipe while the observer waits for another child to become ready.
        command = [str(self.binary), "branch", "source", "--names", *names, *options]
        started = time.monotonic()
        deadline = min(started + self.args.timeout, self.deadline or float("inf"))
        if deadline <= started:
            raise RuntimeError(f"suite deadline exceeded before {case}")
        prefix = f"{len(self.report['commands']):03d}-{case}"
        stdout_path = self.logs / f"{prefix}.stdout.log"
        stderr_path = self.logs / f"{prefix}.stderr.log"
        process = None
        timed_out = False
        try:
            with stdout_path.open("w") as stdout, stderr_path.open("w") as stderr:
                process = subprocess.Popen(command, env=self.env, cwd=self.root, stdout=stdout, stderr=stderr)
                observe(process, deadline)
                process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
            raise RuntimeError(f"{case} timed out") from None
        finally:
            # This process belongs to this test. Never let an assertion leave a client blocked
            # on a test-held lock; detached VMs remain covered by the ordinary name cleanup.
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            elapsed = round((time.monotonic() - started) * 1000, 2)
            code = process.returncode if process is not None else None
            self.report["commands"].append(dict(case=case, phase="operations", argv=command[1:], ms=elapsed,
                                                exit=code, expected_failure=expected_failure,
                                                timed_out=timed_out))
            self.persist()
            print(f"{case}: {elapsed:.2f} ms (exit={code})", flush=True)
        output = stdout_path.read_text(encoding="utf-8", errors="replace").strip()
        error = stderr_path.read_text(encoding="utf-8", errors="replace").strip()
        if code is None or code < 0 or code > 255 or (code != 0) != expected_failure:
            raise RuntimeError(f"{case} failed (exit={code}): {error[-2000:]}")
        return output, error

    def memory(self, name, write=None):
        path = "write/" + write if write else ""
        return self.guest("ram-" + name, name, f"wget -qO- http://127.0.0.1:8080/{path}")

    def verify_heap(self, name, prefix=b"aaaaaaaa"):
        # Test-only full-content validation, deliberately outside the timed branch arms.
        expected = hashlib.blake2s(prefix)
        remaining = self.args.heap_mib * 1024 * 1024 - len(prefix)
        chunk = b"a" * (1024 * 1024)
        while remaining:
            size = min(remaining, len(chunk))
            expected.update(chunk[:size])
            remaining -= size
        actual = self.guest("verify-heap-" + name, name, "wget -qO- http://127.0.0.1:8080/digest")
        assert actual == expected.hexdigest(), f"full heap differs in {name}"

    def state(self, name):
        root = self.home / "sandboxes" / name / "runtime"
        activation = json.loads((root / "restore-activation.json").read_text())
        disk = json.loads((root / "root-disk.json").read_text())
        return {"id": activation["attempt_id"], "vm_generation_id": activation["vm_generation_id"],
                "layers": disk["layers"][:-1], "writable_head": disk["layers"][-1]}

    def verify_batch(self, names):
        states = [self.state(name) for name in names]
        assert len({state["id"] for state in states}) == 1, "batch captured multiple epochs"
        assert len({state["vm_generation_id"] for state in states}) == len(names), "children reused VM generation identity"
        assert all(len(state["layers"]) == len(states[0]["layers"]) for state in states), "disk chain lengths differ"
        for name, state in zip(names, states):
            owned = self.home / "sandboxes" / name
            assert all(Path(layer["path"]).parent == owned for layer in [*state["layers"], state["writable_head"]])
            assert all(bool(layer.get("integrity_root")) == self.args.integrity for layer in state["layers"])
        if os.name == "posix":
            def identity(path):
                metadata = os.stat(path)
                return metadata.st_dev, metadata.st_ino
            assert len({identity(state["layers"][0]["path"]) for state in states}) == 1, "immutable disk base was copied instead of linked"
            heads = {identity(state["writable_head"]["path"]) for state in states}
            sealed = {identity(layer["path"]) for state in states for layer in state["layers"]}
            assert len(heads) == len(names) and heads.isdisjoint(sealed), "children share writable disk storage"
        return states

    def captures(self, name="source"):
        path = self.home / "sandboxes" / name / "logs" / "runtime.log"
        return [line for line in path.read_text().splitlines() if 'operation="capture"' in line]

    def partial_failure(self, flags, first=False):
        names = (["first-bad", "first-good", "first-last"] if first
                 else ["partial-good", "partial-bad", "partial-last"])
        bad = names[0] if first else names[1]
        good = [name for name in names if name != bad]
        before = len(self.captures())
        for name in good:
            self.remember(name)
        if first:
            # The first child reaches ordinary startup rollback and may retain a Stopped row.
            self.remember(bad)
        with self.held_lock("source", lineage=True) as release_capture:
            def inject(process, deadline):
                child = self.home / "sandboxes" / names[0]
                self.wait_until(process, deadline, child.is_dir, "first-child reservation")
                assert len(self.captures()) == before, "capture bypassed the lineage barrier"
                if first:
                    # Capture only writes .branch-restore. Obstructing runtime/scripts fails
                    # the first child's later spawn, after its shared generation is retained.
                    with (child / "runtime").open("x") as marker:
                        marker.write("test-only first-child startup obstruction")
                else:
                    # Preflight has completed, but no sibling may reserve before capture.
                    blocker = self.home / "sandboxes" / bad
                    blocker.mkdir()
                    (blocker / "owner-marker").write_text("reserved by test competitor")
                release_capture()
            _, error = self.observed_batch("first-child-failure" if first else "later-child-failure",
                                            names, inject, *flags, expected_failure=True)
        self.verify_output_order(error, good)
        assert bad + ":" in error and "1 batch children failed" in error, error
        assert len(self.captures()) == before + 1, "failed children recaptured the source"
        if not first:
            assert (self.home / "sandboxes" / bad / "owner-marker").read_text() == "reserved by test competitor"
        self.verify_batch(good)
        for name in good:
            assert self.memory(name) == "aaaaaaaa"
            self.verify_heap(name)
            assert self.guest("partial-disk-" + name, name, "cat /marker") == "original"
            self.stop(name)
        if first:
            statuses = self.statuses()
            assert statuses.get(bad) in (None, "Stopped", "Crashed"), "failed first child remained active"
            if bad in statuses:
                self.stop(bad)
            else:
                self.active.remove(bad)
        self.check_status("source", "Running")
        assert not list((self.home / "sandboxes").glob(".branch-batch-*")), "failed batch lease leaked"

    def overlap_and_ownership(self, flags):
        names = ["owner-a", "owner-b", "owner-c"]
        for name in names:
            self.remember(name)
        before = len(self.captures())
        with self.held_lock("source", lineage=True) as release_capture:
            def observe(process, deadline):
                first = self.home / "sandboxes" / names[0]
                self.wait_until(process, deadline, first.is_dir, "first-child reservation")
                # Acquire only after preflight, so this is a fanout barrier. A sequential
                # creator stalls at owner-b and cannot make owner-c ready while we hold it.
                with self.held_lock(names[1]):
                    release_capture()
                    self.wait_until(process, deadline,
                                    lambda: all(self.statuses().get(name) == "Running" for name in [names[0], names[2]]),
                                    "third child readiness while the second child is blocked")
                    assert self.statuses().get(names[1]) is None, "blocked child bypassed its reservation lock"
                    assert len(self.captures()) == before + 1, "overlap batch captured more than once"
                    states = self.verify_batch([names[0], names[2]])
                    self.report["startup_overlap"] = {"ready": [names[0], names[2]], "blocked": names[1],
                                                      "capture_id": states[0]["id"]}
                    # Source and first-child ownership disappear before owner-b can stage its
                    # disk links or pin RAM. The batch generation must carry it through launch.
                    assert self.memory("source") == "aaaaaaaa"
                    for name in ["source", names[0]]:
                        self.stop(name)
                        self.run("remove-" + name, "remove", name)
                    assert self.memory(names[2]) == "aaaaaaaa"
            _, output = self.observed_batch("overlap-source-first-removal", names, observe, *flags)
        self.verify_output_order(output, names)
        self.verify_batch(names[1:])
        for name in names[1:]:
            assert self.memory(name) == "aaaaaaaa"
            self.verify_heap(name)
            assert self.guest("ownership-disk-" + name, name, "cat /marker") == "original"
        assert not list((self.home / "sandboxes").glob(".branch-batch-*")), "ownership batch lease leaked"
        self.branch("owner-b", "orphan-grandchild")
        assert self.memory("orphan-grandchild") == "aaaaaaaa"

    def exercise(self):
        layout = ("flat:" if self.args.layout == "flat" else "") + self.args.disk
        self.create("source", self.args.image, "--root-disk", layout, "--memory", self.args.memory, "--cpus", str(self.args.cpus))
        worker = WORKER.replace("32 * 1024 * 1024", f"{self.args.heap_mib} * 1024 * 1024")
        self.guest("seed", "source", f"echo original > /marker; dd if=/dev/urandom of=/data bs=1M count={self.args.data_mib} 2>/dev/null; "
                   + "python3 -c " + shlex.quote(worker) + " >/worker.log 2>&1 </dev/null &")
        for _ in range(50):
            try:
                if self.memory("source") == "aaaaaaaa": break
            except RuntimeError:
                time.sleep(0.1)
        else:
            raise RuntimeError("worker did not become ready")
        snapshots = set((self.home / "snapshots").rglob("snapshot.json"))
        for names in [["source"], ["x", "x"], ["x", "../bad"], ["x", "X"]]:
            self.run("reject-names", "branch", "source", "--names", *names, expected_failure=True)
        self.run("reject-both", "branch", "source", "--name", "x", "--names", "y", expected_failure=True)
        self.run("reject-empty", "branch", "source", "--names", expected_failure=True)
        assert not (self.home / "sandboxes" / "x").exists()
        assert not self.captures(), "invalid names mutated the source"
        flags = ["--integrity"] if self.args.integrity else []
        self.batch("source", ["alice", "bob", "carol"], "batch-three", *flags)
        assert len(self.captures()) == 1, "batch captured more than once"
        states = self.verify_batch(["alice", "bob", "carol"])
        self.report["batch_capture_id"] = states[0]["id"]
        self.check_status("source", "Running")
        disk_digest = self.guest("source-disk-digest", "source", "sha256sum /data").split()[0]
        for name in ["alice", "bob", "carol"]:
            assert self.memory(name) == "aaaaaaaa"
            self.verify_heap(name)
            assert self.guest("disk-" + name, name, "cat /marker") == "original"
            assert self.guest("disk-digest-" + name, name, "sha256sum /data").split()[0] == disk_digest
        assert self.memory("alice", "changed") == "changed_"
        self.verify_heap("alice", b"changed_")
        self.guest("private-disk", "alice", "echo alice > /marker")
        for name in ["source", "bob", "carol"]:
            assert self.memory(name) == "aaaaaaaa"
            assert self.guest("private-check", name, "cat /marker") == "original"
        self.batch("alice", ["grand-a", "grand-b"], "grandchildren", *flags)
        self.verify_batch(["grand-a", "grand-b"])
        assert self.memory("grand-a") == "changed_"
        self.verify_heap("grand-a", b"changed_")
        assert self.guest("grand-disk", "grand-b", "cat /marker") == "alice"
        assert len(self.captures("alice")) == 1, "grandchild batch captured more than once"
        self.run("pause-source", "pause", "source")
        before = len(self.captures())
        self.batch("source", ["paused-a", "paused-b"], "paused-batch", *flags)
        assert len(self.captures()) == before + 1, "paused batch captured more than once"
        self.verify_batch(["paused-a", "paused-b"])
        self.check_status("source", "Paused")
        assert self.memory("paused-b") == "aaaaaaaa"
        self.verify_heap("paused-b")
        self.run("resume-source", "resume", "source")
        self.run("reject-existing", "branch", "source", "--names", "unused", "bob", expected_failure=True)
        assert not (self.home / "sandboxes" / "unused").exists()
        assert set((self.home / "snapshots").rglob("snapshot.json")) == snapshots
        assert not list((self.home / "sandboxes").glob(".branch-batch-*")), "batch lease leaked"
        for name in ["alice", "bob", "carol", "grand-a", "grand-b", "paused-a", "paused-b"]:
            self.stop(name)
        if os.name == "posix":
            self.partial_failure(flags)
            self.partial_failure(flags, first=True)
        else:
            self.report["skipped"] = ["deterministic partial failures and startup overlap require POSIX flock"]
        # Alternate order to avoid always rewarding the second (warmer) operation. Keep
        # the same number of live children in each arm; no child is stopped inside timing.
        timings = {"individual": [], "batch": []}
        if self.args.baseline_binary: timings["individual_before"] = []
        for repeat in range(self.args.repeats):
            modes = list(timings)
            modes = modes[repeat % len(modes):] + modes[:repeat % len(modes)]
            for mode in modes:
                names = [f"{mode}-{repeat}-{i}" for i in range(self.args.children)]
                started = time.perf_counter()
                before = len(self.captures())
                first_command = len(self.report["commands"])
                if mode == "batch": self.batch("source", names, f"timed-{mode}-{repeat}", *flags)
                else:
                    for name in names:
                        self.remember(name)
                        binary = self.binary
                        try:
                            if mode == "individual_before": self.binary = self.args.baseline_binary
                            self.run("timed-" + name, "branch", "source", "--name", name, *flags)
                        finally:
                            self.binary = binary
                # Exclude report/log writes: both arms measure subprocess completion only.
                cli_seconds = sum(c["ms"] for c in self.report["commands"][first_command:]) / 1000
                workflow_seconds = time.perf_counter() - started
                for name in names: assert self.memory(name) == "aaaaaaaa"
                ready_seconds = time.perf_counter() - started
                ids = {self.state(name)["id"] for name in names}
                assert len(ids) == (1 if mode == "batch" else len(names))
                cuts = self.captures()[before:]
                assert len(cuts) == (1 if mode == "batch" else len(names)), "unexpected capture count"
                pause_us = sum(int(re.search(r"workload_unavailable_us=(\d+)", cut)[1]) for cut in cuts)
                timings[mode].append({"cli_seconds": cli_seconds, "all_children_respond_seconds": ready_seconds,
                                      "workflow_seconds": workflow_seconds,
                                      "captures": len(cuts), "source_unavailable_seconds": pause_us / 1e6})
                for name in names: self.stop(name)
        self.report["batch_benchmark"] = {"children": self.args.children, "samples": timings,
            "cli_median_seconds": {k: statistics.median(r["cli_seconds"] for r in v) for k, v in timings.items() if v}}
        runtime_log = (self.home / "sandboxes/source/logs/runtime.log").read_text()
        self.report["memory_preparation"] = {"ram_backed": runtime_log.count("ram_backed=true"),
                                              "disk_backed": runtime_log.count("ram_backed=false")}
        if os.name == "posix":
            self.overlap_and_ownership(flags)
        else:
            # The same lifetime checks remain available without POSIX scheduling barriers.
            self.batch("source", ["owner-a", "owner-b"], "ownership-batch", *flags)
            for name in ["source", "owner-a"]:
                self.stop(name)
                self.run("remove-" + name, "remove", name)
            assert self.memory("owner-b") == "aaaaaaaa"
            self.branch("owner-b", "orphan-grandchild")
            assert self.memory("orphan-grandchild") == "aaaaaaaa"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--layout", choices=["managed", "flat"], default="managed")
    parser.add_argument("--image", default="mirror.gcr.io/library/python:3.12-alpine")
    parser.add_argument("--timeout", type=float, default=90)
    parser.add_argument("--suite-timeout", type=float, default=900)
    parser.add_argument("--children", type=int, default=3)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--baseline-binary", type=Path)
    parser.add_argument("--cpus", type=int, default=1)
    parser.add_argument("--memory", default="256M")
    parser.add_argument("--disk", default="512M")
    parser.add_argument("--heap-mib", type=int, default=32)
    parser.add_argument("--data-mib", type=int, default=16)
    parser.add_argument("--integrity", action="store_true")
    args = parser.parse_args()
    if args.children < 1 or args.repeats < 0: parser.error("invalid children/repeats")
    if args.heap_mib < 1 or args.data_mib < 1: parser.error("heap/data sizes must be positive")
    return BatchSmoke(args).execute()


if __name__ == "__main__":
    sys.exit(main())
