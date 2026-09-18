#!/usr/bin/env python3
"""VM-free checks for transport workload integrity, measurements, and process cleanup."""

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
import unittest.mock as mock


SPEC = importlib.util.spec_from_file_location(
    "transport_checkpoint_smoke", Path(__file__).with_name("transport-checkpoint.py"))
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)


class TransportCheckpointTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="transport-unit-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.firmware = self.root / "fixture-firmware"
        self.firmware.write_bytes(b"not a live firmware")
        self.output = self.root / "logs"
        self.output.mkdir()

    def smoke(self, home_parent=Path("/tmp")):
        smoke = HARNESS.TransportSmoke(argparse.Namespace(
            binary=Path(sys.executable), output=self.root / "run", label="candidate",
            firmware=self.firmware, agentd=None, image="never-pull-this-unit-fixture",
            layout="managed", timeout=3, suite_timeout=20, samples=1, stdin_mib=2, bulk_mib=1,
            gate_delay=20, tcp_mib=64, home_parent=home_parent,
            cases=["idle", "throughput", "paused", "full", "branch"],
            input_modes=["pipe", "pty"],
        ))
        self.addCleanup(shutil.rmtree, smoke.home, True)
        return smoke

    def test_custom_home_parent_allocates_fresh_owned_directory(self):
        parent = self.root / "homes"
        parent.mkdir()
        existing = parent / "keep"
        existing.write_text("not owned by the harness")
        smoke = self.smoke(home_parent=parent)
        self.assertEqual(smoke.home.parent, parent)
        self.assertTrue(smoke.home.name.startswith("msb-t-"))
        self.assertTrue(smoke.home.is_dir())
        self.assertEqual(smoke.env["MSB_HOME"], str(smoke.home))
        self.assertEqual(existing.read_text(), "not owned by the harness")

    def stream(self, program=None, arguments=None, is_pty=False, control=False):
        # Only the small guest Python fixture runs, as a local child. The real CLI invocation
        # is translated here before Popen: these tests cannot accidentally launch an msb VM.
        smoke = SimpleNamespace(binary=Path(sys.executable), logs=self.output,
                                env=dict(os.environ), root=self.root,
                                track=lambda job: job, limit=lambda: 5)
        actual_job = HARNESS.Job

        def local_python_job(command, env, cwd, **stdio):
            position = command.index("--")
            self.assertEqual(command[position + 1], "python3")
            return actual_job([sys.executable, *command[position + 2:]], env, cwd, **stdio)

        if arguments is None:
            arguments = [str(self.root / "gate"), str(self.root / "receipt"), "1" if is_pty else "0"]
        with mock.patch.object(HARNESS, "Job", side_effect=local_python_job):
            stream = HARNESS.Stream(smoke, "fixture", program or HARNESS.INPUT_PROGRAM,
                                    arguments, is_pty, control)
        self.addCleanup(stream.close)
        return stream

    def test_nearest_rank_percentiles_include_real_sample_counts(self):
        self.assertEqual(HARNESS.distribution([]), {"n": 0, "p50": None, "p95": None})
        self.assertEqual(HARNESS.distribution([3, 1, 2]), {"n": 3, "p50": 2, "p95": 3})
        for invalid in (-1, float("inf"), float("nan")):
            with self.assertRaises(ValueError):
                HARNESS.distribution([invalid])

    def test_cpu_time_parser_keeps_fractional_and_day_values(self):
        self.assertAlmostEqual(HARNESS.cpu_seconds("02:03.45"), 123.45)
        self.assertEqual(HARNESS.cpu_seconds("1-02:03:04"), 93784)
        with self.assertRaises(ValueError):
            HARNESS.cpu_seconds("not available")

    def test_receipts_reject_corruption_truncation_and_wrong_eof(self):
        receipt = dict(bytes=123, sha256="expected", eof=True, eof_kind="pipe-close")
        HARNESS.verify_receipt(receipt, 123, "expected", False)
        for key, value in [("bytes", 122), ("sha256", "corrupt"), ("eof", False),
                           ("eof_kind", "pty-veof")]:
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, "mismatch"):
                HARNESS.verify_receipt({**receipt, key: value}, 123, "expected", False)

    def test_line_fixtures_are_canonical_bounded_and_sequence_sensitive(self):
        self.assertEqual(len(HARNESS.INPUT_LINE), 512)
        self.assertTrue(HARNESS.INPUT_LINE.endswith(b"\n"))
        self.assertEqual(len(HARNESS.control_line(0)), 256)
        self.assertNotEqual(HARNESS.control_line(0), HARNESS.control_line(1))
        cutoff = HARNESS.MIB
        payload = HARNESS.input_bytes(0, cutoff + 512, cutoff)
        self.assertEqual(len(payload), cutoff + 512)
        self.assertNotEqual(payload[:512], payload[512:1024])
        self.assertTrue(payload[:512].startswith(b"BEFORE:"))
        self.assertTrue(payload[cutoff:].startswith(b"AFTER!:"))
        self.assertEqual(HARNESS.input_bytes(997, 70001, cutoff), payload[997:70998])

    def test_child_receipt_requires_valid_bounded_prefix_and_correct_eof(self):
        cutoff = HARNESS.MIB
        value = dict(bytes=70001, sha256=HARNESS.input_digest(70001, cutoff),
                     eof=True, eof_kind="pipe-close")
        HARNESS.verify_child_receipt(value, HARNESS.PREFIX_BYTES, cutoff, False)
        for key, wrong in (("bytes", HARNESS.PREFIX_BYTES - 1), ("bytes", cutoff + 1),
                           ("sha256", "corrupt"), ("eof", False), ("eof_kind", "pty-quiescent")):
            with self.subTest(key=key, wrong=wrong), self.assertRaises(RuntimeError):
                HARNESS.verify_child_receipt({**value, key: wrong}, HARNESS.PREFIX_BYTES, cutoff, False)
        pty_value = {**value, "eof": False, "eof_kind": "pty-quiescent"}
        HARNESS.verify_child_receipt(pty_value, HARNESS.PREFIX_BYTES, cutoff, True)
        with self.assertRaises(RuntimeError):
            HARNESS.verify_child_receipt(value, HARNESS.PREFIX_BYTES, cutoff, True)

    def test_gate_timing_uses_conservative_clock_bounds(self):
        before = dict(host_before_ns=1000, guest_ns=1500, host_after_ns=1200)
        after = dict(host_before_ns=9000, guest_ns=9600, host_after_ns=9300)
        operations = [dict(wall_end_ns=4000)]
        proof = HARNESS.verify_gate_timing(dict(unix_ns=5000), before, after, operations)
        self.assertEqual(proof["earliest_host_open_ns"], 4400)
        with self.assertRaisesRegex(RuntimeError, "overlap unproven"):
            HARNESS.verify_gate_timing(dict(unix_ns=4600), before, after, operations)

    def test_fresh_source_and_child_exec_must_finish_before_autonomous_gate(self):
        before = dict(host_before_ns=1000, guest_ns=1500, host_after_ns=1200)
        after = dict(host_before_ns=9000, guest_ns=9600, host_after_ns=9300)
        operations = [dict(kind="restore_ready", wall_end_ns=4000)]
        opened = dict(unix_ns=5000)
        HARNESS.verify_gate_timing(opened, before, after, operations)
        # A fast restore followed by control credit starvation is not a passing restore:
        # the first independent exec must complete while inherited input is still blocked.
        for kind in ("child-ready-exec", "source-ready-exec"):
            with self.subTest(kind=kind), self.assertRaisesRegex(RuntimeError, "overlap unproven"):
                HARNESS.verify_gate_timing(opened, before, after,
                    [*operations, dict(kind=kind, wall_end_ns=4500)])

    def test_child_ready_records_first_exec_in_gate_deadline_operations(self):
        smoke = self.smoke()
        row = dict(case="full-pipe-0", operations=[dict(kind="restore_ready")])
        with mock.patch.object(smoke, "guest", return_value="CHILD_FRAME_OK") as guest, \
                mock.patch.object(HARNESS.time, "monotonic", side_effect=[1.25, 1.5]), \
                mock.patch.object(HARNESS.time, "time_ns", side_effect=[1000, 1250]):
            smoke.child_ready(row, "child")
        self.assertEqual(guest.call_args.args[:2], ("full-pipe-0-child-ready-exec", "child"))
        self.assertNotIn("touch ", guest.call_args.args[2])
        self.assertTrue(row["child_exec_independent"])
        self.assertEqual(row["child_ready_exec_ms"], 250)
        self.assertEqual(row["operations"], [dict(kind="restore_ready"),
            dict(kind="child-ready-exec", start=1.25, end=1.5,
                 wall_start_ns=1000, wall_end_ns=1250)])

    def test_source_ready_records_fresh_exec_without_opening_consumer_gate(self):
        smoke = self.smoke()
        row = dict(case="full-pipe-0", operations=[dict(kind="capture")])
        with mock.patch.object(smoke, "guest", return_value="SOURCE_FRAME_OK") as guest, \
                mock.patch.object(HARNESS.time, "monotonic", side_effect=[2.0, 2.125]), \
                mock.patch.object(HARNESS.time, "time_ns", side_effect=[2000, 2125]):
            smoke.source_ready(row)
        guest.assert_called_once_with("full-pipe-0-source-ready-exec", "source",
                                      "printf 'SOURCE_FRAME_OK\\n'")
        self.assertTrue(row["source_exec_independent"])
        self.assertEqual(row["source_ready_exec_ms"], 125)
        self.assertEqual(row["operations"], [dict(kind="capture"),
            dict(kind="source-ready-exec", start=2.0, end=2.125,
                 wall_start_ns=2000, wall_end_ns=2125)])

    def test_source_ready_rejects_corrupt_marker_and_keeps_timing_evidence(self):
        smoke = self.smoke()
        row = dict(case="paused-pipe-0")
        with mock.patch.object(smoke, "guest", return_value="SOURCE_FRAME_OK extra"):
            with self.assertRaisesRegex(RuntimeError, "source framing mismatch"):
                smoke.source_ready(row)
        self.assertNotIn("source_exec_independent", row)
        self.assertEqual(row["operations"][0]["kind"], "source-ready-exec")
        self.assertGreaterEqual(row["source_ready_exec_ms"], 0)

    def test_source_ready_latency_is_summarized_only_for_passing_samples(self):
        samples = [dict(kind="full", tty=False, status="passed", source_ready_exec_ms=12),
                   dict(kind="full", tty=False, status="passed", source_ready_exec_ms=18),
                   dict(kind="full", tty=False, status="failed", source_ready_exec_ms=900)]
        self.assertEqual(HARNESS.summarize(samples)["full/pipe/source_ready_exec_ms"],
                         dict(n=2, p50=12, p95=18))

    def test_regression_timer_opens_without_an_ordinary_control_exec(self):
        stream = self.stream(arguments=[str(self.root / "absent-gate"), str(self.root / "receipt"),
                                        "0", str(HARNESS.PREFIX_BYTES), ".35"])
        stream.await_ready()
        stream.feed(2 * HARNESS.MIB, regression=True)
        stream.await_prefix()
        stream.offer.set()
        stream.await_pressure()
        stream.after_cut.set()
        self.assertEqual(stream.finish()["receipt"]["bytes"], 2 * HARNESS.MIB)
        self.assertFalse((self.root / "absent-gate").exists())
        self.assertTrue((self.root / "receipt.gate").exists())

    def test_sequence_sensitive_pty_regression_keeps_suffix_and_canonical_eof(self):
        stream = self.stream(arguments=[str(self.root / "gate"), str(self.root / "receipt"),
                                        "1", str(HARNESS.PREFIX_BYTES)], is_pty=True)
        stream.await_ready()
        stream.feed(2 * HARNESS.MIB, regression=True)
        stream.await_prefix()
        stream.offer.set()
        self.assertGreater(stream.await_pressure()["eagain_count"], 0)
        stream.after_cut.set()
        (self.root / "gate").touch()
        value = stream.finish()["receipt"]
        self.assertEqual(value["bytes"], 2 * HARNESS.MIB)
        self.assertEqual(value["eof_kind"], "pty-veof")

    def test_runtime_and_home_isolation_discards_ambient_overrides(self):
        with mock.patch.dict(os.environ, {"MSB_HOME": "/caller", "MSB_BACKEND": "cloud",
                                         "MSB_PROFILE": "production", "MSB_PATH": "/wrong/msb",
                                         "MSB_AGENTD_PATH": "/wrong/agentd",
                                         "MSB_CONFIG_PATH": "/caller/config"}):
            smoke = self.smoke()
        self.assertEqual(smoke.env["MSB_PATH"], str(Path(sys.executable).resolve()))
        self.assertEqual(smoke.env["MSB_LIBKRUNFW_PATH"], str(self.firmware.resolve()))
        self.assertEqual(smoke.env["MSB_HOME"], str(smoke.home))
        self.assertTrue(str(smoke.home).startswith("/tmp/msb-t-"))
        self.assertEqual(smoke.env["MSB_BACKEND"], "local")
        for key in ("MSB_CONFIG_PATH", "MSB_PROFILE", "MSB_AGENTD_PATH"):
            self.assertNotIn(key, smoke.env)

    def test_refuses_existing_output_directory(self):
        smoke = self.smoke()
        with self.assertRaises(FileExistsError):
            self.smoke()
        self.assertTrue((smoke.root / "report.json").exists())

    def test_pipe_backpressure_preserves_partial_write_bytes_and_eof(self):
        stream = self.stream()
        stream.await_ready()
        actual_write = os.write

        def short_write(fd, data):
            return actual_write(fd, data[:997])  # Force non-line-aligned short writes.

        with mock.patch.object(HARNESS.os, "write", side_effect=short_write):
            stream.feed(2 * HARNESS.MIB)
            proof = stream.await_pressure()
            self.assertGreater(proof["eagain_count"], 0)
            self.assertLess(proof["forwarded_bytes"], 2 * HARNESS.MIB)
            (self.root / "gate").touch()
            result = stream.finish()
        self.assertEqual(result["receipt"]["bytes"], 2 * HARNESS.MIB)
        self.assertEqual(result["receipt"]["eof_kind"], "pipe-close")
        stream.close()
        stream.close()  # Global cleanup may revisit an already-finished stream.

    @unittest.skipUnless(os.name == "posix", "PTY workload requires POSIX")
    def test_pty_backpressure_preserves_bytes_and_canonical_eof(self):
        stream = self.stream(is_pty=True)
        stream.await_ready()
        stream.feed(2 * HARNESS.MIB)
        self.assertGreater(stream.await_pressure()["eagain_count"], 0)
        (self.root / "gate").touch()
        result = stream.finish()
        self.assertEqual(result["receipt"]["eof_kind"], "pty-veof")
        self.assertEqual(result["receipt"]["bytes"], 2 * HARNESS.MIB)
        stream.close()
        stream.close()

    def test_regression_producer_acknowledges_prefix_and_withholds_post_cut_bytes(self):
        stream = self.stream(arguments=[str(self.root / "gate"), str(self.root / "receipt"),
                                        "0", str(HARNESS.PREFIX_BYTES)])
        stream.await_ready()
        stream.feed(2 * HARNESS.MIB, regression=True)
        prefix = stream.await_prefix()
        self.assertEqual(prefix["bytes"], HARNESS.PREFIX_BYTES)
        self.assertEqual(stream.sent, HARNESS.PREFIX_BYTES)
        stream.offer.set()
        self.assertGreater(stream.await_pressure()["eagain_count"], 0)
        (self.root / "gate").touch()
        deadline = time.monotonic() + 3
        while stream.sent < stream.cutoff and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertEqual(stream.sent, stream.cutoff)
        self.assertIsNone(stream.receipt)  # No host EOF or AFTER! suffix before explicit release.
        stream.after_cut.set()
        self.assertEqual(stream.finish()["receipt"]["bytes"], 2 * HARNESS.MIB)

    def test_detached_child_fixtures_pipe_eof_and_pty_no_half_close(self):
        # Simulate only the fixture's inherited input endpoint, not VM checkpoint machinery:
        # pipe closes after its prefix; PTY stays open and reports bounded quiescence.
        for is_pty in (False, True):
            with self.subTest(is_pty=is_pty):
                gate = self.root / ("child-gate-" + str(is_pty))
                receipt = self.root / ("child-receipt-" + str(is_pty))
                stream = self.stream(arguments=[str(gate), str(receipt), "1" if is_pty else "0",
                                                str(HARNESS.PREFIX_BYTES)], is_pty=is_pty)
                stream.await_ready()
                stream.cutoff = HARNESS.MIB
                data = HARNESS.input_bytes(0, HARNESS.PREFIX_BYTES + 4096, stream.cutoff)

                def send_prefix():
                    offset = 0
                    while offset < len(data):
                        try:
                            offset += os.write(stream.input_fd, data[offset:offset + 997])
                        except BlockingIOError:
                            select.select([], [stream.input_fd], [], .02)
                    if not is_pty:
                        stream.job.process.stdin.close()

                writer = threading.Thread(target=send_prefix, daemon=True)
                writer.start()
                stream.await_prefix()
                Path(str(receipt) + ".probe").touch()
                gate.touch()
                writer.join(3)
                self.assertFalse(writer.is_alive())
                self.assertEqual(stream.job.wait(3), 0)
                stream.reader.join(3)
                self.assertIsNone(stream.error)
                HARNESS.verify_child_receipt(stream.receipt, HARNESS.PREFIX_BYTES,
                                             stream.cutoff, is_pty)
                self.assertEqual(stream.receipt["bytes"], len(data))
                stream.close()

    def test_stream_missing_receipt_is_not_successful_exit(self):
        stream = self.stream("print('INPUT_READY', flush=True)", [])
        stream.await_ready()
        stream.size, stream.expected_digest = 0, hashlib.sha256(b"").hexdigest()
        with self.assertRaisesRegex(RuntimeError, "without final receipt"):
            stream.finish()

    def test_control_output_has_exact_sequenced_framing(self):
        stop = self.root / "control-stop"
        stream = self.stream(HARNESS.CONTROL_PROGRAM, [str(stop)], control=True)
        self.assertTrue(stream.job.process.stdin.closed)
        stream.await_ready()
        deadline = time.monotonic() + 2
        while stream.control_bytes < 8192 and time.monotonic() < deadline:
            time.sleep(.01)
        stop.touch()
        result = stream.finish()
        self.assertGreaterEqual(result["bytes"], 8192)

    def test_control_reordered_or_duplicate_frame_fails(self):
        program = f"import sys; sys.stdout.buffer.write(b'CONTROL_READY\\n' + {HARNESS.control_line(1)!r}); sys.stdout.flush()"
        stream = self.stream(program, [], control=True)
        stream.await_ready()
        with self.assertRaisesRegex(RuntimeError, "unexpected stream frame"):
            stream.finish()

    def test_owned_process_group_termination_is_bounded(self):
        job = HARNESS.Job([sys.executable, "-c", "import time; time.sleep(60)"],
                          dict(os.environ), self.root, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        self.addCleanup(job.terminate)
        started = time.monotonic()
        job.terminate()
        self.assertIsNotNone(job.process.poll())
        self.assertLess(time.monotonic() - started, 4)

    def test_cleanup_closes_new_operations_but_permits_cleanup_commands(self):
        smoke = self.smoke()
        smoke.cleaning = True
        with mock.patch.object(HARNESS, "Job") as job:
            with self.assertRaisesRegex(RuntimeError, "closed admission"):
                smoke.invoke("late-copy", "copy", "fixture", "source:/fixture")
            job.assert_not_called()
        # A real local Python process proves cleanup is independent of an expired deadline;
        # no msb process is involved because binary=sys.executable in smoke().
        smoke.deadline = time.monotonic() - 1
        result = smoke.run("cleanup-probe", "-c", "print('cleanup')", phase="cleanup", timeout=2)
        self.assertEqual(result[0], "cleanup")

    def test_command_timeout_records_failure_and_reaps_owned_process(self):
        smoke = self.smoke()
        with self.assertRaisesRegex(RuntimeError, "timeout=True"):
            smoke.invoke("timeout", "-c", "import time; time.sleep(60)", timeout=.05)
        self.assertTrue(smoke.report["commands"][-1]["timed_out"])
        self.assertIsNotNone(smoke.jobs[-1].process.poll())

    def test_cleanup_attempts_every_owned_client_before_vm_cleanup(self):
        smoke = self.smoke()
        smoke.streams = [mock.Mock(), mock.Mock()]
        smoke.streams[0].close.side_effect = RuntimeError("injected stream error")
        smoke.jobs = [mock.Mock(), mock.Mock()]
        worker = mock.Mock()
        worker.thread.is_alive.return_value = False
        smoke.bulk_workers = [worker]
        with mock.patch.object(HARNESS.BASE.Smoke, "cleanup_owned", return_value=[]) as base:
            errors = smoke.cleanup_owned()
        self.assertTrue(smoke.cleaning)
        self.assertEqual(len(errors), 1)
        for stream in smoke.streams:
            stream.close.assert_called_once()
        for job in smoke.jobs:
            job.terminate.assert_called_once()
        worker.stop.set.assert_called_once()
        worker.thread.join.assert_called_once_with(3)
        base.assert_called_once()

    def test_stdin_only_throughput_does_not_create_control_or_bulk_workers(self):
        smoke = self.smoke()
        size = smoke.args.stdin_mib * HARNESS.MIB
        receipt = dict(bytes=size, sha256=HARNESS.input_digest(size), eof=True, eof_kind="pipe-close")
        stream = mock.Mock(size=size, expected_digest=receipt["sha256"])
        stream.finish.return_value = dict(bytes=size, seconds=1, receipt=receipt)

        def guest(_label, _name, command):
            if command.startswith("touch "):
                return ""
            if command.startswith("cat "):
                return json.dumps(receipt)
            return "POST_FRAME_OK"

        with mock.patch.object(HARNESS, "Stream", return_value=stream) as constructor, \
                mock.patch.object(HARNESS, "Bulk") as bulk, \
                mock.patch.object(smoke, "guest", side_effect=guest), \
                contextlib.redirect_stdout(io.StringIO()):
            smoke.scenario("stdin-throughput", False, 0)
        constructor.assert_called_once()
        bulk.assert_not_called()
        stream.feed.assert_called_once_with(size)
        stream.await_pressure.assert_not_called()
        sample = smoke.report["samples"][0]
        self.assertEqual(sample["status"], "passed")
        self.assertEqual(sample["bulk"], {})
        self.assertNotIn("control_stdout", sample)

    def test_source_exec_precedes_post_cut_release_and_source_stdin_finish(self):
        smoke = self.smoke()
        size = smoke.args.stdin_mib * HARNESS.MIB
        receipt = dict(bytes=size, sha256=HARNESS.input_digest(size, size - HARNESS.LATE_BYTES),
                       eof=True, eof_kind="pipe-close")
        stream = mock.Mock(size=size, expected_digest=receipt["sha256"])
        stream.after_cut = threading.Event()
        stream.await_prefix.return_value = dict(bytes=HARNESS.PREFIX_BYTES)
        stream.await_pressure.return_value = dict(eagain_count=1)
        events = []

        def guest(_label, _name, command):
            if command == "printf 'SOURCE_FRAME_OK\\n'":
                self.assertFalse(stream.after_cut.is_set())
                self.assertEqual(events, ["pause", "resume"])
                events.append("source-ready-exec")
                return "SOURCE_FRAME_OK"
            return json.dumps(receipt) if command.startswith("cat ") else "POST_FRAME_OK"

        def finish():
            self.assertTrue(stream.after_cut.is_set())
            self.assertEqual(events[-1], "source-ready-exec")
            events.append("stdin-finish")
            return dict(bytes=size, seconds=1, receipt=receipt)

        def gate_proof(row, _receipt):
            self.assertEqual(row["operations"][-1]["kind"], "source-ready-exec")
            self.assertTrue(row["source_exec_independent"])

        stream.finish.side_effect = finish
        with mock.patch.object(HARNESS, "Stream", return_value=stream), \
                mock.patch.object(smoke, "guest", side_effect=guest), \
                mock.patch.object(smoke, "run", side_effect=lambda _label, kind, *args: events.append(kind)), \
                mock.patch.object(smoke, "clock_probe", return_value={}), \
                mock.patch.object(smoke, "check_status"), \
                mock.patch.object(smoke, "gate_proof", side_effect=gate_proof), \
                contextlib.redirect_stdout(io.StringIO()):
            smoke.scenario("paused", False, 0)
        self.assertEqual(events, ["pause", "resume", "source-ready-exec", "stdin-finish"])
        self.assertEqual(smoke.report["samples"][0]["status"], "passed")

    def test_tcp_source_exec_follows_child_probe_and_precedes_input_finish(self):
        smoke = self.smoke()
        smoke.args.tcp_mib = 1
        receipt = dict(bytes=HARNESS.MIB, sha256=HARNESS.input_digest(HARNESS.MIB, HARNESS.MIB),
                       eof=True, eof_kind="pipe-close")
        server, client = mock.Mock(), mock.Mock()
        server.finish.return_value = dict(receipt=receipt)
        client.await_pressure.return_value = dict(eagain_count=1)
        events = []

        def guest(_label, _name, command):
            if command == "printf 'SOURCE_FRAME_OK\\n'":
                self.assertEqual(events, ["child-ready-exec"])
                events.append("source-ready-exec")
                return "SOURCE_FRAME_OK"
            return "TCP_POST_FRAME_OK"

        def finish():
            self.assertEqual(events, ["child-ready-exec", "source-ready-exec"])
            events.append("tcp-finish")
            return receipt

        def gate_proof(row, _receipt):
            self.assertEqual(row["operations"][-1]["kind"], "source-ready-exec")
            self.assertTrue(row["source_exec_independent"])

        client.finish.side_effect = finish
        with mock.patch.object(HARNESS, "Stream", return_value=server), \
                mock.patch.object(HARNESS.TCP, "InlineTcp", return_value=client), \
                mock.patch.object(smoke, "guest", side_effect=guest), \
                mock.patch.object(smoke, "run"), \
                mock.patch.object(smoke, "clock_probe", return_value={}), \
                mock.patch.object(smoke, "child_ready", side_effect=lambda *args: events.append("child-ready-exec")), \
                mock.patch.object(smoke, "gate_proof", side_effect=gate_proof), \
                mock.patch.object(smoke, "stop"), \
                contextlib.redirect_stdout(io.StringIO()):
            smoke.tcp_scenario("tcp-branch", 0)
        self.assertEqual(events, ["child-ready-exec", "source-ready-exec", "tcp-finish"])
        self.assertEqual(smoke.report["samples"][0]["status"], "passed")

    def test_failed_samples_and_failed_baselines_do_not_generate_performance_claims(self):
        sample = dict(kind="full", tty=False, status="failed", capture_ms=12)
        self.assertEqual(HARNESS.summarize([sample]), {})
        sample["status"] = "passed"
        stats = HARNESS.summarize([sample])
        self.assertEqual(stats["full/pipe/capture_ms"]["n"], 1)
        reports = {"baseline": dict(status="failed", statistics=stats),
                   "candidate": dict(status="passed", statistics=stats)}
        self.assertEqual(HARNESS.compare(reports), {})
        reports["baseline"]["status"] = "passed"
        for report in reports.values():
            report["image_manifest_digest"] = "sha256:fixture"
            report["parameters"] = {"samples": 1}
            report["firmware_sha256"] = "same-firmware"
            report["host"] = "same-host"
            report["host_node"] = "same-machine"
        self.assertEqual(HARNESS.compare(reports)["full/pipe/capture_ms"]["candidate_over_baseline_p50"], 1)
        for field in ("firmware_sha256", "host", "host_node"):
            previous = reports["candidate"][field]
            reports["candidate"][field] = "different"
            self.assertEqual(HARNESS.compare(reports), {})
            reports["candidate"][field] = previous
        reports["candidate"]["image_manifest_digest"] = "sha256:different-image"
        self.assertEqual(HARNESS.compare(reports), {})


if __name__ == "__main__":
    unittest.main()
