#!/usr/bin/env python3
"""Isolated live transport/checkpoint regression and baseline/candidate comparison.

Example (use matching, codesigned runtime/agentd/firmware builds):
  python3 scripts/smoke/cli/transport-checkpoint.py \
    --baseline /build/before/msb --baseline-firmware /build/before/libkrunfw.dylib \
    --candidate /build/after/msb --candidate-firmware /build/after/libkrunfw.dylib

Images are pulled/materialized before measurements; timed programs use no external network.
Pipe cases restore installed snapshots eagerly; PTY cases restore .msb archives with --forked.
Use --cases idle throughput for a passing pre/post performance baseline independently of the
freeze/thaw regression cases. Opt-in tcp-paused/tcp-full/tcp-branch cases exercise inline
TCP backpressure without BulkOffer; restored TCP connections are intentionally not inherited.
Use --cases stdin-throughput to isolate stdin from concurrent control output and bulk copies.
Results retain individual samples, correctness checks, and nearest-rank p50/p95. PTY EOF
means canonical VEOF, not a nonexistent PTY half-close. Bulk overlap is measured at the CLI
operation boundary, not claimed as an instrumented guest-frame boundary. This is a POSIX
harness. It never reads or stops sandboxes from the caller's MSB_HOME.
Use --home-parent /short/disk/path when /tmp has a RAM or per-user quota; every run still
creates and owns a fresh home underneath that directory.
"""

import argparse
import errno
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import pty
import resource
import select
import shlex
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import tty


SPEC = importlib.util.spec_from_file_location(
    "snapshot_branch_smoke", Path(__file__).with_name("snapshot-branch.py"))
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
TCP_SPEC = importlib.util.spec_from_file_location(
    "transport_tcp_probe", Path(__file__).with_name("transport_tcp.py"))
TCP = importlib.util.module_from_spec(TCP_SPEC)
TCP_SPEC.loader.exec_module(TCP)
MIB = 1024 * 1024
INPUT_LINE = b"0123456789abcdef" * 31 + b"0123456789abcde\n"  # 512-byte canonical lines.
PREFIX_BYTES = 64 * 1024
LATE_BYTES = 64 * 1024
CONTROL_SUFFIX = b"0123456789abcdef" * 14 + b"abcdef\n"

# Regression consumers acknowledge a prefix, then wait behind an autonomous timer gate.
# The independent gate timestamp proves fresh metadata exec completed without draining input.
# Throughput and VM-free fixture modes can still open a file gate explicitly.
INPUT_PROGRAM = r'''
import hashlib, json, os, select, sys, termios, time
gate, receipt, is_pty = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
prefix = int(sys.argv[4]) if len(sys.argv) > 4 else 0
delay = float(sys.argv[5]) if len(sys.argv) > 5 else 0
if is_pty:
    attrs = termios.tcgetattr(0)
    attrs[0] &= ~(termios.ICRNL | termios.INLCR | termios.IGNCR)
    attrs[1] &= ~termios.OPOST
    attrs[3] = (attrs[3] | termios.ICANON) & ~(termios.ECHO | termios.ECHONL)
    attrs[6][termios.VEOF] = b"\x04"
    termios.tcsetattr(0, termios.TCSANOW, attrs)
print("INPUT_READY", flush=True)
h, size = hashlib.sha256(), 0
while size < prefix:
    block = os.read(0, min(65536, prefix - size))
    if not block: raise RuntimeError("EOF before acknowledged prefix")
    h.update(block); size += len(block)
if prefix:
    value = dict(bytes=size, sha256=h.hexdigest())
    with open(receipt + ".prefix", "w") as f: json.dump(value, f)
    print("INPUT_PREFIX " + json.dumps(value), flush=True)
deadline = time.monotonic() + delay if delay else float("inf")
while not os.path.exists(gate) and time.monotonic() < deadline: time.sleep(.005)
if prefix:
    with open(receipt + ".gate", "w") as f:
        json.dump(dict(unix_ns=time.time_ns(), monotonic_ns=time.monotonic_ns()), f)
# A restored PTY deliberately has no inherited host input/half-close. Its bounded probe
# drains available canonical lines, then records quiescence, not an invented EOF.
probe = False
eof = False
while True:
    if is_pty and prefix:
        # Detect the child marker even if a slow restore outlived the autonomous timer.
        # Otherwise that child could enter a blocking read before fresh exec creates it.
        probe = os.path.exists(receipt + ".probe")
        if not select.select([0], [], [], 1 if probe else .05)[0]:
            if probe: break
            continue
    block = os.read(0, 65536)
    if not block:
        eof = True
        break
    h.update(block); size += len(block)
value = dict(bytes=size, sha256=h.hexdigest(), eof=eof,
             eof_kind="pty-quiescent" if probe else "pty-veof" if is_pty else "pipe-close")
with open(receipt + ".tmp" if prefix else receipt, "w") as f: json.dump(value, f)
if prefix: os.replace(receipt + ".tmp", receipt)  # No partial JSON for child observers.
print("INPUT_RESULT " + json.dumps(value), flush=True)
'''

CONTROL_PROGRAM = r'''
import os, sys, time
stop = sys.argv[1]
suffix = b"0123456789abcdef" * 14 + b"abcdef\n"
sys.stdout.buffer.write(b"CONTROL_READY\n"); sys.stdout.buffer.flush()
n = 0
while not os.path.exists(stop):
    block = b"".join(b"CONTROL:" + f"{i:016x}".encode() + b":" + suffix for i in range(n, n + 32))
    sys.stdout.buffer.write(block); sys.stdout.buffer.flush(); n += 32
    time.sleep(.001)
print("CONTROL_DONE " + str(n), flush=True)
'''

TCP_PROGRAM = r'''
import hashlib, json, os, socket, sys, time
gate, receipt, port, delay = sys.argv[1], sys.argv[2], int(sys.argv[3]), float(sys.argv[4])
listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
listener.bind(("127.0.0.1", port)); listener.listen(1)
print("INPUT_READY", flush=True)
peer, _ = listener.accept(); listener.close()
deadline = time.monotonic() + delay
while time.monotonic() < deadline: time.sleep(.005)
with open(receipt + ".gate", "w") as f:
    json.dump(dict(unix_ns=time.time_ns(), monotonic_ns=time.monotonic_ns()), f)
h, size = hashlib.sha256(), 0
while True:
    block = peer.recv(65536)
    if not block: break
    h.update(block); size += len(block)
value = dict(bytes=size, sha256=h.hexdigest(), eof=True, eof_kind="pipe-close")
with open(receipt + ".tmp", "w") as f: json.dump(value, f)
os.replace(receipt + ".tmp", receipt)
peer.sendall(json.dumps(value).encode() + b"\n")
peer.shutdown(socket.SHUT_WR); peer.close()
print("INPUT_RESULT " + json.dumps(value), flush=True)
'''


def bounded_int(value):
    number = int(value)
    if not 1 <= number <= 1024:
        raise argparse.ArgumentTypeError("value must be between 1 and 1024")
    return number


def distribution(values):
    """Do not invent percentiles for failed/missing measurements or interpolate tiny samples."""
    values = sorted(values)
    if not values:
        return {"n": 0, "p50": None, "p95": None}
    if any(not math.isfinite(v) or v < 0 for v in values):
        raise ValueError("samples must be finite and nonnegative")
    return {"n": len(values), "p50": values[math.ceil(len(values) * .50) - 1],
            "p95": values[math.ceil(len(values) * .95) - 1]}


def file_digest(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(MIB), b""):
            digest.update(block)
    return digest.hexdigest()


def control_line(index):
    return b"CONTROL:" + f"{index:016x}".encode() + b":" + CONTROL_SUFFIX


def cpu_seconds(text):
    """Parse ps TIME ([[days-]hours:]minutes:seconds), retaining its coarse precision."""
    text = text.strip()
    days = 0
    if "-" in text:
        day, text = text.split("-", 1)
        days = int(day)
    fields = [float(part) for part in text.split(":")]
    if len(fields) not in (2, 3):
        raise ValueError(f"unrecognized ps CPU time: {text!r}")
    value = days * 86400
    for field, multiplier in zip(reversed(fields), (1, 60, 3600)):
        value += field * multiplier
    return value


def verify_receipt(value, size, digest, is_pty):
    expected = dict(bytes=size, sha256=digest, eof=True,
                    eof_kind="pty-veof" if is_pty else "pipe-close")
    if value != expected:
        raise RuntimeError(f"stdin bytes/EOF mismatch: expected {expected}, got {value}")


def input_bytes(offset, size, cutoff=None):
    """Regression lines carry positions; throughput keeps its original measured workload."""
    if cutoff is None:
        block = INPUT_LINE * ((offset % 512 + size + 511) // 512)
    else:
        block = b"".join(
            ((b"BEFORE" if index * 512 < cutoff else b"AFTER!")
             + f":{index:016x}:".encode() + b"x" * 487 + b"\n")
            for index in range(offset // 512, (offset + size + 511) // 512))
    return block[offset % 512:offset % 512 + size]


def input_digest(size, cutoff=None):
    digest = hashlib.sha256()
    if cutoff is None:
        for _ in range(size // len(INPUT_LINE)):
            digest.update(INPUT_LINE)
        digest.update(INPUT_LINE[:size % len(INPUT_LINE)])
        return digest.hexdigest()
    for offset in range(0, size, 65536):
        digest.update(input_bytes(offset, min(65536, size - offset), cutoff))
    return digest.hexdigest()


def verify_child_receipt(value, acknowledged, cutoff, is_pty):
    """Host enqueue is not guest admission: validate a prefix range, never the whole stream."""
    size = value.get("bytes")
    if type(size) is not int or not acknowledged <= size <= cutoff:
        raise RuntimeError(f"child input is outside the acknowledged/pre-cut range: {value}")
    expected = dict(bytes=size, sha256=input_digest(size, cutoff), eof=not is_pty,
                    eof_kind="pty-quiescent" if is_pty else "pipe-close")
    if value != expected:
        raise RuntimeError(f"child input prefix/EOF mismatch: expected {expected}, got {value}")


def verify_gate_timing(opened, before, after, operations):
    # Clock probes bracket the guest read with host reads. Use the union of both offset
    # intervals, not optimistic midpoint alignment. A changing clock is evidence we cannot
    # qualify, never permission to count a timer that opened before checkpoint completion.
    earliest = opened["unix_ns"] + min(probe["host_before_ns"] - probe["guest_ns"]
                                       for probe in (before, after))
    completed = max(operation["wall_end_ns"] for operation in operations)
    if earliest <= completed:
        raise RuntimeError("autonomous input gate may have opened before operation completion; overlap unproven")
    return dict(earliest_host_open_ns=earliest, latest_operation_end_ns=completed,
                minimum_margin_ms=(earliest - completed) / 1e6,
                clock_assumption="guest-host wall offset remained within pre/post probe bounds")


class Job:
    """A direct child/process group owned by this test, never a recycled catalog PID."""

    def __init__(self, command, env, cwd, **stdio):
        self.started = time.monotonic()
        self.ended = None
        self.process = subprocess.Popen(command, env=env, cwd=cwd,
                                        start_new_session=True, **stdio)

    def wait(self, timeout):
        code = self.process.wait(timeout=timeout)
        self.ended = time.monotonic()
        return code

    def terminate(self):
        if self.process.poll() is not None:
            return
        # This child has not been reaped, so its PID cannot have been reused. Never use this
        # operation for historical PIDs read from the runtime database.
        try:
            os.killpg(self.process.pid, signal.SIGTERM)
            self.wait(1)
        except subprocess.TimeoutExpired:
            os.killpg(self.process.pid, signal.SIGKILL)
            self.wait(2)
        except ProcessLookupError:
            self.wait(2)


class Stream:
    """Bounded streaming reader plus a nonblocking stdin producer, with explicit evidence."""

    def __init__(self, smoke, label, program, arguments, is_pty=False, control=False, no_input=False):
        self.smoke, self.label = smoke, label
        self.is_pty, self.control = is_pty, control
        self.ready, self.done, self.cancel = threading.Event(), threading.Event(), threading.Event()
        self.prefix_ready, self.offer, self.after_cut = (threading.Event() for _ in range(3))
        self.prefix_receipt = None
        self.error, self.receipt = None, None
        self.sent, self.blocked, self.control_bytes = 0, 0, 0
        self.producer = None
        self.master = None
        self.closed = False
        self.started = time.monotonic()
        command = [str(smoke.binary), "exec", "source", "--tty" if is_pty else "--stream",
                   "--", "python3", "-u", "-c", program, *arguments]
        self.stderr = (smoke.logs / (label + ".stderr.log")).open("wb")
        if is_pty:
            self.master, slave = pty.openpty()
            tty.setraw(slave)
            try:
                self.job = smoke.track(Job(command, smoke.env, smoke.root,
                                           stdin=slave, stdout=slave, stderr=self.stderr))
            finally:
                os.close(slave)
            self.input_fd, self.output_fd = self.master, self.master
        else:
            self.job = smoke.track(Job(command, smoke.env, smoke.root,
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=self.stderr))
            self.input_fd = self.job.process.stdin.fileno()
            self.output_fd = self.job.process.stdout.fileno()
        os.set_blocking(self.input_fd, False)
        if control or no_input:
            # This workload has no input. Leaving a pipe open strands the CLI's blocking
            # Tokio stdin reader during runtime shutdown even after the guest has exited.
            self.job.process.stdin.close()
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()

    def read(self):
        buffer, lines, ended = b"", 0, False
        try:
            while not self.cancel.is_set():
                if not select.select([self.output_fd], [], [], .1)[0]:
                    continue
                try:
                    block = os.read(self.output_fd, 65536)
                except OSError as error:
                    if self.is_pty and error.errno == errno.EIO:
                        block = b""  # A PTY master reports slave closure as EIO on Linux.
                    else:
                        raise
                if not block:
                    if buffer:
                        raise RuntimeError("unterminated stream framing")
                    break
                buffer += block
                if len(buffer) > MIB:
                    raise RuntimeError("stream exceeded bounded line buffer")
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    line = line.removesuffix(b"\r")
                    if ended:
                        raise RuntimeError("bytes followed final stream receipt")
                    if line == (b"CONTROL_READY" if self.control else b"INPUT_READY"):
                        if self.ready.is_set():
                            raise RuntimeError("duplicate stream readiness marker")
                        self.ready.set()
                    elif self.control and line + b"\n" == control_line(lines):
                        if not self.ready.is_set():
                            raise RuntimeError("control bytes arrived before readiness")
                        lines += 1
                        self.control_bytes += len(control_line(lines - 1))
                    elif self.control and line.startswith(b"CONTROL_DONE "):
                        if int(line.split()[1]) != lines:
                            raise RuntimeError("control stdout sequence lost or duplicated bytes")
                        ended = True
                    elif not self.control and line.startswith(b"INPUT_RESULT "):
                        self.receipt = json.loads(line[len(b"INPUT_RESULT "):])
                        ended = True
                    elif not self.control and line.startswith(b"INPUT_PREFIX "):
                        if not self.ready.is_set() or self.prefix_ready.is_set():
                            raise RuntimeError("invalid or duplicate consumed-prefix acknowledgment")
                        self.prefix_receipt = json.loads(line[len(b"INPUT_PREFIX "):])
                        self.prefix_ready.set()
                    else:
                        raise RuntimeError(f"unexpected stream frame: {line[:160]!r}")
            if not ended and not self.cancel.is_set():
                raise RuntimeError("stream ended without final receipt")
        except Exception as error:
            self.error = error
        finally:
            self.done.set()

    def await_ready(self):
        until = time.monotonic() + self.smoke.limit()
        while not self.ready.wait(.02):
            if self.done.is_set() or time.monotonic() >= until:
                raise RuntimeError(f"{self.label}: readiness failed: {self.error}")

    def feed(self, size, regression=False):
        self.size = size
        self.cutoff = size - LATE_BYTES if regression else None
        if regression and self.cutoff <= PREFIX_BYTES:
            raise ValueError("regression input must exceed prefix plus withheld suffix")
        self.expected_digest = input_digest(size, self.cutoff)

        def write():
            try:
                throughput_block = INPUT_LINE * 128
                while self.sent < size and not self.cancel.is_set():
                    boundary = size
                    if regression:
                        boundary = PREFIX_BYTES if self.sent < PREFIX_BYTES else self.cutoff
                        event = self.offer if self.sent == PREFIX_BYTES else self.after_cut
                        if self.sent in (PREFIX_BYTES, self.cutoff):
                            while not event.wait(.02):
                                if self.cancel.is_set():
                                    return
                        if self.sent >= self.cutoff:
                            boundary = size
                    try:
                        if regression:
                            block = input_bytes(self.sent, min(65536, boundary - self.sent), self.cutoff)
                        else:
                            offset = self.sent % len(throughput_block)
                            block = throughput_block[offset:offset + min(
                                len(throughput_block) - offset, size - self.sent)]
                        count = os.write(self.input_fd, block)
                        self.sent += count
                    except BlockingIOError:
                        self.blocked += 1
                        select.select([], [self.input_fd], [], .02)
                if self.cancel.is_set():
                    return
                if self.is_pty:
                    # Every data chunk ends at a newline. VEOF now yields a genuine zero-length
                    # guest read without closing the bidirectional host PTY or losing its output.
                    while not self.cancel.is_set():
                        try:
                            os.write(self.input_fd, b"\x04")
                            break
                        except BlockingIOError:
                            select.select([], [self.input_fd], [], .02)
                else:
                    self.job.process.stdin.close()
            except Exception as error:
                self.error = error

        self.producer = threading.Thread(target=write, daemon=True)
        self.producer.start()

    def await_prefix(self):
        until = time.monotonic() + self.smoke.limit()
        while not self.prefix_ready.wait(.02):
            if self.error or self.done.is_set() or time.monotonic() >= until:
                raise RuntimeError(f"{self.label}: consumed-prefix acknowledgment failed: {self.error}")
        expected = dict(bytes=PREFIX_BYTES, sha256=input_digest(PREFIX_BYTES, self.cutoff))
        if self.prefix_receipt != expected:
            raise RuntimeError(f"invalid consumed-prefix acknowledgment: {self.prefix_receipt}")
        return self.prefix_receipt

    def await_pressure(self):
        until = time.monotonic() + self.smoke.limit()
        previous, stable_since = -1, time.monotonic()
        while time.monotonic() < until:
            if self.error:
                raise self.error
            if self.sent >= (self.cutoff if self.cutoff is not None else self.size):
                raise RuntimeError("input fit in forwarding queues; increase --stdin-mib; saturation unproven")
            if self.sent != previous:
                previous, stable_since = self.sent, time.monotonic()
            elif self.blocked and time.monotonic() - stable_since >= .2:
                return {"forwarded_bytes": self.sent, "eagain_count": self.blocked,
                        "stable_blocked_seconds": time.monotonic() - stable_since}
            time.sleep(.01)
        raise RuntimeError("could not demonstrate sustained stdin backpressure")

    def finish(self):
        if self.producer:
            self.producer.join(self.smoke.limit())
            if self.producer.is_alive():
                raise RuntimeError(f"{self.label}: stdin did not drain")
        code = self.job.wait(self.smoke.limit())
        self.reader.join(self.smoke.limit())
        if self.reader.is_alive() or self.error or code:
            raise RuntimeError(f"{self.label}: stream failed (exit={code}): {self.error}")
        if not self.control:
            verify_receipt(self.receipt, self.size, self.expected_digest, self.is_pty)
        return {"bytes": self.control_bytes if self.control else self.size,
                "seconds": time.monotonic() - self.started, "receipt": self.receipt}

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.cancel.set()
        self.job.terminate()
        for thread in (self.producer, self.reader):
            if thread:
                thread.join(3)
        if self.master is not None:
            os.close(self.master)
            self.master = None
        else:
            for file in (self.job.process.stdin, self.job.process.stdout):
                file.close()
        self.stderr.close()


class Bulk:
    """Continuous finite, independently verified uploads/downloads around a checkpoint."""

    def __init__(self, smoke, label, direction):
        self.smoke, self.label, self.direction = smoke, label, direction
        self.stop = threading.Event()
        self.error, self.current = None, None
        self.samples = []
        self.thread = threading.Thread(target=self.work, daemon=True)
        self.thread.start()

    def work(self):
        try:
            index = 0
            while not self.stop.is_set():
                label = f"{self.label}-{self.direction}-{index}"
                destination = self.smoke.root / "artifacts" / (label + ".bin")
                args = ([str(self.smoke.blob), "source:/transport-upload.bin"]
                        if self.direction == "upload"
                        else ["source:/transport-download.bin", str(destination)])
                _, _, row = self.smoke.invoke(label, "copy", *args,
                                             started=lambda job: setattr(self, "current", job))
                self.current = None
                if self.direction == "upload":
                    digest = self.smoke.guest(label + "-hash", "source",
                        "sha256sum /transport-upload.bin").split()[0]
                else:
                    digest = file_digest(destination)
                    destination.unlink()
                if digest != self.smoke.blob_digest:
                    raise RuntimeError(f"{label}: bulk checksum mismatch")
                self.samples.append({"start": row["start"], "end": row["end"],
                                     "bytes": self.smoke.args.bulk_mib * MIB,
                                     "seconds": row["ms"] / 1000, "sha256": digest})
                index += 1
        except Exception as error:
            self.error = error

    def finish(self):
        self.stop.set()
        self.thread.join(self.smoke.limit())
        if self.thread.is_alive() or self.error:
            raise RuntimeError(f"{self.label}/{self.direction}: {self.error or 'copy did not finish'}")
        return self.samples


class TransportSmoke(BASE.Smoke):
    def __init__(self, args):
        self.lock = threading.RLock()
        self.jobs, self.streams, self.bulk_workers, self.tcp_clients = [], [], [], []
        self.cleaning = False
        super().__init__(args)
        # Reports may live under a long build directory; Unix sockets cannot. Allocate the
        # home independently, never borrow an existing path. Base cleanup still owns exactly
        # this freshly allocated directory and only removes it after catalog/PID verification.
        # Some Linux hosts mount /tmp as quota-limited tmpfs. Keep the short-path default,
        # but permit an explicit disk-backed parent for archive and CoW memory fixtures.
        self.home = Path(tempfile.mkdtemp(prefix="msb-t-", dir=args.home_parent))
        self.env["MSB_HOME"] = str(self.home)
        self.report["home"] = str(self.home)
        # Make the CLI and its launched runtime an explicit matching pair. Do not inherit a
        # caller's agentd/runtime override, profile, or alternate config file accidentally.
        for key in ("MSB_PATH", "MSB_LIBKRUNFW_PATH", "MSB_AGENTD_PATH"):
            self.env.pop(key, None)
        self.env["MSB_PATH"] = str(self.binary)
        self.env["MSB_LIBKRUNFW_PATH"] = str(args.firmware.resolve(strict=True))
        if args.agentd:
            self.env["MSB_AGENTD_PATH"] = str(args.agentd.resolve(strict=True))
        self.report.update(label=args.label, firmware=self.env["MSB_LIBKRUNFW_PATH"],
                           agentd=self.env.get("MSB_AGENTD_PATH", "embedded"), samples=[],
                           binary_sha256=file_digest(self.binary),
                           firmware_sha256=file_digest(Path(self.env["MSB_LIBKRUNFW_PATH"])),
                           agentd_sha256=(file_digest(Path(self.env["MSB_AGENTD_PATH"]))
                                          if "MSB_AGENTD_PATH" in self.env else None),
                           host=platform.platform(), host_node=platform.node(), harness_python=sys.version,
                           parameters={key: getattr(args, key) for key in
                                       ("samples", "stdin_mib", "bulk_mib", "image", "cases", "input_modes")},
                           latency_scope="CLI completion; independent source/child exec verifies readiness before input drains",
                           throughput_scope="end-to-end CLI streams including startup/gating, not raw device throughput",
                           cpu_scope="source runtime ps TIME; CLI children rusage; harness process_time; not total guest CPU",
                           bulk_overlap_scope="checksum-verified CLI operation lifetimes, not guest-frame instrumentation")
        self.report["harness_sha256"] = {
            name: file_digest(Path(__file__).with_name(name))
            for name in ("transport-checkpoint.py", "transport_tcp.py", "snapshot-branch.py")}
        (self.root / "artifacts").mkdir()
        if any(case.startswith("tcp-") for case in args.cases):
            self.report["parameters"]["tcp_mib"] = args.tcp_mib
        if any(case not in ("idle", "throughput", "stdin-throughput") for case in args.cases):
            self.report["parameters"]["gate_delay"] = args.gate_delay
        self.persist()

    def persist(self):
        with self.lock:
            super().persist()

    def track(self, job):
        with self.lock:
            self.jobs.append(job)
        return job

    def limit(self):
        remaining = self.args.timeout if self.deadline is None else self.deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("transport suite deadline exceeded")
        return min(self.args.timeout, remaining)

    def invoke(self, case, *arguments, expected_failure=False, phase="operations", timeout=None,
               started=None):
        if self.cleaning and phase == "operations":
            raise RuntimeError("cleanup has closed admission of new operation clients")
        limit = timeout or (self.limit() if phase == "operations" else self.args.timeout)
        with self.lock:
            sequence = len(self.report["commands"])
            row = dict(case=case, argv=list(map(str, arguments)), phase=phase, start=time.monotonic())
            self.report["commands"].append(row)
        prefix = self.logs / f"{sequence:04d}-{case}"
        outpath, errpath = prefix.with_suffix(".stdout.log"), prefix.with_suffix(".stderr.log")
        job, code, timed_out = None, None, False
        try:
            with outpath.open("wb") as out, errpath.open("wb") as err:
                job = self.track(Job([str(self.binary), *map(str, arguments)], self.env, self.root,
                                     stdin=subprocess.DEVNULL, stdout=out, stderr=err))
                if started:
                    started(job)
                code = job.wait(limit)
        except subprocess.TimeoutExpired:
            timed_out = True
            job.terminate()
        finally:
            row.update(end=time.monotonic(), exit=code, timed_out=timed_out)
            row["ms"] = (row["end"] - row["start"]) * 1000
            self.persist()
        stdout, stderr = outpath.read_text(errors="replace"), errpath.read_text(errors="replace")
        if timed_out or code is None or code < 0 or code > 255 or (code != 0) != expected_failure:
            raise RuntimeError(f"{case}: exit={code}, timeout={timed_out}: {stderr[-2000:]}")
        return stdout.strip(), stderr.strip(), row

    def run(self, case, *arguments, **kwargs):
        out, err, _ = self.invoke(case, *arguments, **kwargs)
        return out, err

    def source_cpu(self):
        # Read only this harness's catalog. Missing/unsupported CPU observations are explicitly
        # null, never zero. No catalog PID is signalled by the harness.
        try:
            database = self.home / "db/msb.db"
            with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=2) as db:
                pid = db.execute('SELECT pid FROM "run" ORDER BY id ASC LIMIT 1').fetchone()[0]
            result = subprocess.run(["ps", "-p", str(pid), "-o", "time="],
                                    capture_output=True, text=True, timeout=2, check=True)
            return cpu_seconds(result.stdout)
        except (OSError, ValueError, TypeError, IndexError, sqlite3.Error, subprocess.SubprocessError):
            return None

    def operation(self, row, metric, *arguments):
        started = time.monotonic()
        wall_start = time.time_ns()
        self.run(row["case"] + "-" + metric, *arguments)
        ended = time.monotonic()
        row[metric + "_ms"] = (ended - started) * 1000
        row.setdefault("operations", []).append(dict(kind=metric, start=started, end=ended,
                                                      wall_start_ns=wall_start, wall_end_ns=time.time_ns()))

    def clock_probe(self, label):
        before = time.time_ns()
        guest = int(self.guest(label, "source", "python3 -c 'import time; print(time.time_ns())'"))
        return dict(host_before_ns=before, guest_ns=guest, host_after_ns=time.time_ns())

    def gate_proof(self, row, receipt):
        after = self.clock_probe(row["case"] + "-clock-after")
        opened = json.loads(self.guest(row["case"] + "-gate-proof", "source", f"cat {receipt}.gate"))
        evidence = dict(opened=opened, clock_after=after,
                        waiting_excluded_from_checkpoint_latency=True)
        row["autonomous_gate"] = evidence
        try:
            evidence.update(verify_gate_timing(opened, row["gate_clock_before"], after, row["operations"]))
        except RuntimeError as error:
            evidence["qualification_error"] = str(error)
            self.persist()  # Retain the raw opening/clock observations even when overlap is unproven.
            raise

    def child_ready(self, row, name):
        started, wall_start = time.monotonic(), time.time_ns()
        actual = self.guest(row["case"] + "-child-ready-exec", name,
                   "test \"$(cat /transport-marker)\" = source; "
                   "test \"$(cat /dev/shm/transport-marker)\" = source; "
                   "echo child > /transport-marker; echo child > /dev/shm/transport-marker; "
                   "printf 'CHILD_FRAME_OK\\n'")
        ended = time.monotonic()
        row["child_ready_exec_ms"] = (ended - started) * 1000
        # Restore completion alone cannot prove fresh control traffic escapes inherited
        # input debt. This command must also finish before the autonomous read gate opens;
        # child_input deliberately opens the child's gate only after this check returns.
        row.setdefault("operations", []).append(dict(kind="child-ready-exec", start=started,
            end=ended, wall_start_ns=wall_start, wall_end_ns=time.time_ns()))
        if actual != "CHILD_FRAME_OK":
            raise RuntimeError(f"child framing mismatch: {actual!r}")
        row["child_exec_independent"] = True

    def source_ready(self, row):
        started, wall_start = time.monotonic(), time.time_ns()
        actual = self.guest(row["case"] + "-source-ready-exec", "source",
                            "printf 'SOURCE_FRAME_OK\\n'")
        ended = time.monotonic()
        row["source_ready_exec_ms"] = (ended - started) * 1000
        # Unlike the restored child's empty host queue, this source still owns queued input.
        # Do not open its gate: completion before the autonomous timestamp must prove that
        # fresh metadata can pass credit-blocked data while the input consumer stays blocked.
        row.setdefault("operations", []).append(dict(kind="source-ready-exec", start=started,
            end=ended, wall_start_ns=wall_start, wall_end_ns=time.time_ns()))
        if actual != "SOURCE_FRAME_OK":
            raise RuntimeError(f"source framing mismatch: {actual!r}")
        row["source_exec_independent"] = True

    def child_input(self, row, name, gate, receipt, stream):
        # This read happens before the host releases AFTER! bytes. The source's closed gate
        # is an independent copy, so inspecting the child cannot drain the source stream.
        prefix = json.loads(self.guest(row["case"] + "-child-prefix", name,
                                      f"cat {receipt}.prefix"))
        if prefix != stream.prefix_receipt:
            raise RuntimeError(f"child lost the consumed-prefix marker: {prefix}")
        wait = ("import json, os, sys, time; path=sys.argv[1]; "
                "deadline=time.monotonic()+float(sys.argv[2]);\n"
                "while not os.path.exists(path):\n"
                " if time.monotonic() >= deadline: raise RuntimeError('child input did not settle')\n"
                " time.sleep(.01)\n"
                "print(open(path).read())")
        command = (f"touch {receipt}.probe; touch {gate}; python3 -c {shlex.quote(wait)} "
                   f"{receipt} {max(.1, self.limit() - 2)}")
        value = json.loads(self.guest(row["case"] + "-child-input", name, command))
        verify_child_receipt(value, PREFIX_BYTES, stream.cutoff, stream.is_pty)
        row["child_stdin"] = dict(receipt=value, acknowledged_prefix=prefix,
                                  offered_pre_cut_upper_bound=stream.cutoff,
                                  withheld_post_cut_bytes=LATE_BYTES,
                                  exact_guest_admission_frontier_observed=False)

    def wait_bulk_active(self, workers):
        until = time.monotonic() + self.limit()
        while time.monotonic() < until:
            if any(worker.error for worker in workers):
                raise RuntimeError(f"bulk start failed: {[str(w.error) for w in workers]}")
            if all(w.current and w.current.process.poll() is None for w in workers):
                return
            time.sleep(.002)
        raise RuntimeError("bidirectional bulk operations never overlapped")

    def scenario(self, kind, is_pty, index):
        label = f"{kind}-{'pty' if is_pty else 'pipe'}-{index}"
        row = dict(case=label, kind=kind, tty=is_pty, index=index, status="running")
        self.report["samples"].append(row)
        started, host_cpu = time.monotonic(), time.process_time()
        source_before = self.source_cpu()
        cli_before = resource.getrusage(resource.RUSAGE_CHILDREN)
        gate, receipt, stop = (f"/transport-{label}-{suffix}" for suffix in ("go", "receipt", "stop"))
        regression = kind not in ("throughput", "stdin-throughput")
        if regression:
            row["gate_clock_before"] = self.clock_probe(label + "-clock-before")
        stream = Stream(self, label, INPUT_PROGRAM,
                        [gate, receipt, "1" if is_pty else "0", str(PREFIX_BYTES if regression else 0),
                         str(self.args.gate_delay if regression else 0)],
                        is_pty)
        self.streams.append(stream)
        stream.await_ready()
        control, workers, child, member = None, [], None, None
        if kind in ("full", "branch", "throughput"):
            control = Stream(self, label + "-control", CONTROL_PROGRAM, [stop], control=True)
            self.streams.append(control)
            control.await_ready()
            workers = [Bulk(self, label, direction) for direction in ("upload", "download")]
            self.bulk_workers.extend(workers)
            self.wait_bulk_active(workers)
        if regression:
            stream.feed(self.args.stdin_mib * MIB, regression=True)
            row["acknowledged_prefix"] = stream.await_prefix()
        if kind == "paused":
            self.operation(row, "pause", "pause", "source")
            self.check_status("source", "Paused")
        if not regression:
            self.guest(label + "-go", "source", f"touch {gate}")
            stream.feed(self.args.stdin_mib * MIB)
        if regression:
            stream.offer.set()
            row["backpressure"] = stream.await_pressure()
        if kind == "paused":
            self.operation(row, "resume", "resume", "source")
        elif kind == "branch":
            child = label + "-child"
            self.remember(child)
            self.wait_bulk_active(workers)
            self.operation(row, "branch_ready", "branch", "source", "--name", child)
            self.child_ready(row, child)
            self.child_input(row, child, gate, receipt, stream)
        elif kind == "full":
            member = label
            self.wait_bulk_active(workers)
            self.operation(row, "capture", "snapshot", "create", member,
                           "--from-sandbox", "source", "--group", "transport", "--full")
            child = label + "-child"
            self.remember(child)
            # Exercise both durable restore routes on every repetition without silently pooling
            # their latency distributions: pipe=eager/installed; PTY=forked/archive.
            source = "transport:" + member
            row["restore_source"] = "archive" if is_pty else "installed"
            row["restore_memory"] = "forked" if is_pty else "eager"
            if is_pty:
                archive = self.root / "artifacts" / (label + ".msb")
                self.run(label + "-save", "snapshot", "save", source, archive)
                source = str(archive)
            self.wait_bulk_active(workers)
            self.operation(row, "restore_ready", "create", "--name", child,
                           "--from-snapshot", source, "--pull", "never",
                           *(["--forked"] if is_pty else []))
            self.child_ready(row, child)
            self.child_input(row, child, gate, receipt, stream)
        if regression:
            self.source_ready(row)
            stream.after_cut.set()
            # The timer remains independent evidence, not a metadata-progress workaround.
            # Neither readiness exec opens the source gate before its queued input drains.
        row["stdin"] = stream.finish()
        stream.close()
        verify_receipt(json.loads(self.guest(label + "-source-receipt", "source", f"cat {receipt}")),
                       stream.size, stream.expected_digest, is_pty)
        if regression:
            self.gate_proof(row, receipt)
        if control:
            self.guest(label + "-control-stop", "source", f"touch {stop}")
            row["control_stdout"] = control.finish()
            control.close()
        for worker in workers:
            worker.stop.set()
        row["bulk"] = {worker.direction: worker.finish() for worker in workers}
        if kind in ("full", "branch"):
            # Require a verified operation interval covering the *start* of every checkpoint
            # action. A transfer that starts only after thaw is not counted as overlap.
            for operation in row["operations"]:
                if operation["kind"] in ("child-ready-exec", "source-ready-exec"):
                    continue  # This probes control readiness, not checkpoint/bulk overlap.
                for direction, samples in row["bulk"].items():
                    overlaps = [s for s in samples if s["start"] <= operation["start"] < s["end"]]
                    if not overlaps:
                        raise RuntimeError(f"{label}/{operation['kind']}: no verified {direction} overlap; increase --bulk-mib")
        # Exact fresh framing and disk/RAM identity checks after the busy session's EOF.
        actual = self.guest(label + "-framing", "source",
            "test \"$(cat /transport-marker)\" = source; "
            "test \"$(cat /dev/shm/transport-marker)\" = source; printf 'POST_FRAME_OK\\n'")
        if actual != "POST_FRAME_OK":
            raise RuntimeError(f"post-checkpoint framing mismatch: {actual!r}")
        cli_after = resource.getrusage(resource.RUSAGE_CHILDREN)
        source_after = self.source_cpu()
        row.update(status="passed", elapsed_ms=(time.monotonic() - started) * 1000,
                   harness_cpu_seconds=time.process_time() - host_cpu,
                   cli_cpu_seconds=(cli_after.ru_utime + cli_after.ru_stime
                                    - cli_before.ru_utime - cli_before.ru_stime),
                   source_runtime_cpu_seconds=(source_after - source_before
                       if source_before is not None and source_after is not None else None))
        self.persist()
        if child:
            self.stop(child)
        if member:
            self.run(label + "-remove", "snapshot", "remove", "transport:" + member)
            archive = self.root / "artifacts" / (label + ".msb")
            archive.unlink(missing_ok=True)
        print(f"{self.args.label}/{label}: correctness passed", flush=True)

    def tcp_scenario(self, kind, index):
        label = f"{kind}-{index}"
        row = dict(case=label, kind=kind, index=index, status="running", tcp_mode="inline-no-bulk-offer")
        self.report["samples"].append(row)
        gate, receipt = f"/transport-{label}-go", f"/transport-{label}-receipt"
        row["gate_clock_before"] = self.clock_probe(label + "-clock-before")
        server = Stream(self, label, TCP_PROGRAM,
                        [gate, receipt, "32017", str(self.args.gate_delay)], no_input=True)
        self.streams.append(server)
        server.await_ready()
        # This canonical endpoint is scoped to our fresh home and exact source name. Never
        # discover a global socket or inherit a caller's agent-client connection.
        socket_path = self.home / "run/sandboxes" / hashlib.sha256(b"source").hexdigest()[:24] / "agent.sock"
        client = TCP.InlineTcp(socket_path, 32017, self.limit)
        self.tcp_clients.append(client)
        size = self.args.tcp_mib * MIB
        server.size, server.expected_digest = size, input_digest(size, size)
        client.feed(size, lambda offset, count: input_bytes(offset, count, size))
        row["backpressure"] = client.await_pressure()
        child, member = None, None
        if kind == "tcp-paused":
            self.operation(row, "pause", "pause", "source")
            self.check_status("source", "Paused")
            self.operation(row, "resume", "resume", "source")
        elif kind == "tcp-branch":
            child = label + "-child"
            self.remember(child)
            self.operation(row, "branch_ready", "branch", "source", "--name", child)
        else:
            member, child = label, label + "-child"
            self.operation(row, "capture", "snapshot", "create", member,
                           "--from-sandbox", "source", "--group", "transport", "--full")
            self.remember(child)
            self.operation(row, "restore_ready", "create", "--name", child,
                           "--from-snapshot", "transport:" + member, "--pull", "never")
        if child:
            self.child_ready(row, child)
            row["child_tcp_expectation"] = "old connection detached; only fresh child exec asserted"
        self.source_ready(row)
        row["tcp_receipt"] = client.finish()
        verify_receipt(row["tcp_receipt"], size, server.expected_digest, False)
        row["server"] = server.finish()
        client.close()
        server.close()
        self.gate_proof(row, receipt)
        if self.guest(label + "-framing", "source", "printf 'TCP_POST_FRAME_OK\\n'") != "TCP_POST_FRAME_OK":
            raise RuntimeError("post-TCP fresh exec framing failed")
        row["status"] = "passed"
        self.persist()
        if child:
            self.stop(child)
        if member:
            self.run(label + "-remove", "snapshot", "remove", "transport:" + member)
        print(f"{self.args.label}/{label}: correctness passed", flush=True)

    def exercise(self):
        self.blob = self.root / "artifacts" / "payload.bin"
        block = bytes(range(256)) * 4096
        with self.blob.open("wb") as destination:
            for _ in range(self.args.bulk_mib):
                destination.write(block)
        self.blob_digest = file_digest(self.blob)
        disk_mib = max(2048, self.args.bulk_mib * 2 + 512)
        self.create("source", self.args.image, "--root-disk", f"{disk_mib}M",
                    "--memory", "512M", "--cpus", "2", "--pull", "never")
        inspected = json.loads(self.run("source-provenance", "inspect", "source", "--format", "json")[0])
        self.report["image_manifest_digest"] = inspected["config"].get("manifest_digest")
        if not self.report["image_manifest_digest"]:
            raise RuntimeError("source did not expose a pinned image manifest for benchmark provenance")
        self.guest("prepare-source", "source",
                   "python3 --version; echo source > /transport-marker; "
                   "echo source > /dev/shm/transport-marker; sync")
        self.run("seed-download", "copy", self.blob, "source:/transport-download.bin")
        if self.guest("seed-download-hash", "source", "sha256sum /transport-download.bin").split()[0] != self.blob_digest:
            raise RuntimeError("initial bulk payload checksum mismatch")
        for index in range(self.args.samples):
            if "idle" in self.args.cases:
                idle = dict(case=f"idle-{index}", kind="idle", status="running")
                self.report["samples"].append(idle)
                self.operation(idle, "pause", "pause", "source")
                self.operation(idle, "resume", "resume", "source")
                self.guest(f"idle-probe-{index}", "source", "true")
                idle["status"] = "passed"
            for mode in self.args.input_modes:
                is_pty = mode == "pty"
                for kind in ("throughput", "stdin-throughput", "paused", "full", "branch"):
                    if kind in self.args.cases:
                        self.scenario(kind, is_pty, index)
            for kind in ("tcp-paused", "tcp-full", "tcp-branch"):
                if kind in self.args.cases:
                    self.tcp_scenario(kind, index)

    def cleanup_owned(self):
        errors = []
        self.cleaning = True
        # First stop admission of new clients, then kill owned client process groups, then stop
        # every registered VM. Cleanup is independent of the expired operation deadline.
        for worker in self.bulk_workers:
            worker.stop.set()
        for client in self.tcp_clients:
            try:
                client.close()
            except Exception as error:
                errors.append(f"TCP client cleanup: {error}")
        for stream in self.streams:
            try:
                stream.close()
            except Exception as error:
                errors.append(f"stream cleanup: {error}")
        for job in list(self.jobs):
            try:
                job.terminate()
            except Exception as error:
                errors.append(f"client cleanup: {error}")
        for worker in self.bulk_workers:
            worker.thread.join(3)
            if worker.thread.is_alive():
                errors.append("bulk worker remained alive after owned clients were terminated")
        errors.extend(super().cleanup_owned())
        for row in self.report["samples"]:
            if row["status"] == "running":
                row["status"] = "incomplete"
        self.report["statistics"] = summarize(self.report["samples"])
        return errors


def summarize(samples):
    groups = {}
    for row in samples:
        if row["status"] != "passed":
            continue
        prefix = row["kind"] + ("/pty" if row.get("tty") else "/pipe")
        for key in ("pause_ms", "resume_ms", "capture_ms", "branch_ready_ms", "restore_ready_ms",
                    "child_ready_exec_ms", "source_ready_exec_ms",
                    "elapsed_ms", "harness_cpu_seconds", "cli_cpu_seconds", "source_runtime_cpu_seconds"):
            if row.get(key) is not None:
                groups.setdefault(prefix + "/" + key, []).append(row[key])
        for channel in ("stdin", "control_stdout"):
            if channel in row:
                value = row[channel]
                groups.setdefault(prefix + "/" + channel + "_mib_s", []).append(
                    value["bytes"] / MIB / value["seconds"])
        for direction, transfers in row.get("bulk", {}).items():
            for value in transfers:
                groups.setdefault(prefix + "/" + direction + "_mib_s", []).append(
                    value["bytes"] / MIB / value["seconds"])
    return {key: distribution(values) for key, values in sorted(groups.items())}


def compare(reports):
    if any(reports.get(label, {}).get("status") != "passed" for label in ("baseline", "candidate")):
        return {}  # Failed/partial runs are correctness evidence, not a fair performance baseline.
    baseline, candidate = reports["baseline"], reports["candidate"]
    if (not baseline.get("image_manifest_digest")
            or baseline["image_manifest_digest"] != candidate.get("image_manifest_digest")
            or baseline.get("parameters") != candidate.get("parameters")
            or not baseline.get("firmware_sha256")
            or baseline["firmware_sha256"] != candidate.get("firmware_sha256")
            or not baseline.get("host") or baseline["host"] != candidate.get("host")
            or not baseline.get("host_node") or baseline["host_node"] != candidate.get("host_node")):
        return {}  # Changed image, workload, firmware, or host is not an isolated binary delta.
    before = reports.get("baseline", {}).get("statistics", {})
    after = reports.get("candidate", {}).get("statistics", {})
    return {key: {"baseline": before[key], "candidate": after[key],
                  "candidate_over_baseline_p50": (after[key]["p50"] / before[key]["p50"]
                      if before[key]["p50"] else None)} for key in before.keys() & after.keys()}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for label in ("baseline", "candidate"):
        parser.add_argument("--" + label, type=Path, help="Matching msb CLI/runtime binary")
        parser.add_argument("--" + label + "-firmware", type=Path)
        parser.add_argument("--" + label + "-agentd", type=Path, help="Otherwise use embedded agentd")
    parser.add_argument("--output", type=Path, help="Exclusive new report directory")
    parser.add_argument("--home-parent", type=Path, default=Path("/tmp"),
                        help="Existing short directory for a fresh isolated home (default: /tmp)")
    parser.add_argument("--samples", type=bounded_int, default=3)
    parser.add_argument("--input-modes", nargs="+", choices=("pipe", "pty"), default=["pipe", "pty"])
    parser.add_argument("--cases", nargs="+", choices=("idle", "throughput", "stdin-throughput", "paused", "full", "branch",
                                                      "tcp-paused", "tcp-full", "tcp-branch"),
                        default=["idle", "throughput", "paused", "full", "branch"],
                        help="Select regression cases, or idle throughput for a standalone performance run")
    parser.add_argument("--stdin-mib", type=bounded_int, default=16)
    parser.add_argument("--bulk-mib", type=bounded_int, default=64)
    parser.add_argument("--tcp-mib", type=bounded_int, default=64,
                        help="Finite input for opt-in inline TCP backpressure cases")
    parser.add_argument("--gate-delay", type=BASE.positive_seconds, default=20,
                        help="Guest-autonomous regression gate delay; actual opening must follow checkpoint completion")
    parser.add_argument("--image", default="mirror.gcr.io/library/python:3.13-alpine")
    parser.add_argument("--timeout", type=BASE.positive_seconds, default=45)
    parser.add_argument("--suite-timeout", type=BASE.positive_seconds, default=900)
    args = parser.parse_args()
    labels = [label for label in ("baseline", "candidate") if getattr(args, label)]
    if not labels or os.name != "posix":
        parser.error("provide --baseline and/or --candidate; this harness requires POSIX PTYs")
    for label in labels:
        if not getattr(args, label + "_firmware"):
            parser.error(f"--{label}-firmware is required for an explicit matching runtime pair")
    root = args.output.expanduser().resolve() if args.output else Path(
        tempfile.mkdtemp(prefix="msb-transport-", dir="/tmp"))
    if args.output:
        root.mkdir(parents=True, mode=0o700, exist_ok=False)
    reports, failed = {}, False

    def interrupt(_signum, _frame):
        raise KeyboardInterrupt("interrupted; cleaning up owned transport-test VMs")

    signal.signal(signal.SIGTERM, interrupt)
    for label in labels:
        selected = argparse.Namespace(**vars(args))
        selected.binary, selected.output, selected.label = getattr(args, label), root / label, label
        selected.firmware, selected.agentd = getattr(args, label + "_firmware"), getattr(args, label + "_agentd")
        selected.layout = "managed"
        smoke = TransportSmoke(selected)
        failed |= bool(smoke.execute())
        reports[label] = smoke.report
        if smoke.report["status"] == "passed":
            smoke.blob.unlink(missing_ok=True)
        if smoke.report["cleanup_errors"]:
            break  # Do not benchmark the next binary alongside an unverified surviving runtime.
    result = dict(reports={key: str(root / key / "report.json") for key in reports},
                  comparison=compare(reports), status="failed" if failed else "passed",
                  comparison_requirement="two completely passing runs with identical host, firmware, pinned image, and workload parameters")
    (root / "comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"Comparison: {root / 'comparison.json'}", flush=True)
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
