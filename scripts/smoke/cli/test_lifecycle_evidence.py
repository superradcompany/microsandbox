#!/usr/bin/env python3
"""VM-free interruption and cleanup regressions for lifecycle evidence collection."""

import asyncio
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch

import lifecycle_evidence as evidence


def interruptions():
    # CancelledError is a BaseException too. Catching only Exception, or just
    # KeyboardInterrupt/SystemExit, would skip cleanup for an async caller.
    return [KeyboardInterrupt(), SystemExit(143), asyncio.CancelledError()]


class LifecycleEvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_cleanup_finishes_removal_before_propagating_interruption(self):
        for error in interruptions():
            with self.subTest(error=type(error).__name__):
                runner = Mock()
                runner.run.side_effect = [error, 0]
                result = {}
                with self.assertRaises(type(error)) as raised:
                    evidence.cleanup(runner, "case", "sandbox", result, force=True)
                self.assertIs(raised.exception, error)
                self.assertEqual(result, {"stop": str(error), "rm": 0})
                self.assertEqual([call.args for call in runner.run.call_args_list], [
                    ("case-cleanup-stop", "stop", "--force", "sandbox"),
                    ("case-cleanup-rm", "rm", "sandbox"),
                ])
                self.assertTrue(all(call.kwargs == {"required": False}
                                    for call in runner.run.call_args_list))

    def test_ordinary_cleanup_failure_is_recorded_without_skipping_removal(self):
        runner = Mock()
        runner.run.side_effect = [OSError("stop unavailable"), 9]
        self.assertEqual(evidence.cleanup(runner, "case", "sandbox"),
                         {"stop": "stop unavailable", "rm": 9})

    def test_each_interrupted_phase_still_cleans_all_targets_audits_and_saves(self):
        for phase in ("prepare", "stop", "rm", "audit"):
            for error in interruptions():
                with self.subTest(phase=phase, error=type(error).__name__):
                    targets = {"first": {}, "second": {}}
                    row = {"status": "passed", "cleanup": targets}
                    report = {"status": "passed", "case": row}
                    runner = Mock()
                    replies = [0, 0, 0, 0]
                    if phase in ("stop", "rm"):
                        replies[0 if phase == "stop" else 1] = error
                    runner.run.side_effect = replies
                    prepare = Mock(side_effect=error if phase == "prepare" else None)

                    def audit():
                        # The audit must run after both targets, including interrupted
                        # cleanup, and its evidence must survive the subsequent raise.
                        self.assertEqual(runner.run.call_count, 4)
                        report["audit_attempted"] = True
                        if phase == "audit":
                            raise error

                    with self.assertRaises(type(error)) as raised:
                        evidence.finish_saved_evidence(runner, targets, row, report,
                                                       self.root, audit, prepare=prepare)
                    self.assertIs(raised.exception, error)
                    saved = json.loads((self.root / "report.json").read_text())
                    self.assertEqual(saved["status"], "failed")
                    self.assertEqual(saved["case"]["status"], "failed")
                    self.assertTrue(saved["audit_attempted"])
                    self.assertEqual(saved["case"]["cleanup"]["second"], {"stop": 0, "rm": 0})
                    self.assertIn(type(error).__name__, saved["case"]["cleanup_error"])

    def test_nonzero_cleanup_cannot_be_reported_as_success(self):
        runner = Mock()
        runner.run.side_effect = [0, 7]
        row = {"status": "passed"}
        report = {"status": "passed", "case": row}
        audit = Mock()
        evidence.finish_saved_evidence(runner, {"sandbox": {}}, row, report, self.root, audit)
        audit.assert_called_once_with()
        self.assertEqual(json.loads((self.root / "report.json").read_text())["status"], "failed")

    def test_supervisor_kills_group_reaps_and_records_before_reraising(self):
        errors = [*interruptions(), subprocess.TimeoutExpired("fixture", 180)]
        for index, error in enumerate(errors):
            with self.subTest(error=type(error).__name__):
                runner = evidence.Runner("fixture", {}, self.root / str(index))
                child = Mock(pid=12345)
                child.wait.side_effect = [error, -signal.SIGKILL]
                process = Mock()
                process.__enter__ = Mock(return_value=child)
                process.__exit__ = Mock(return_value=False)
                events = Mock()
                events.attach_mock(child.wait, "wait")
                with patch.object(evidence.subprocess, "Popen", return_value=process) as popen:
                    with patch.object(evidence.os, "killpg") as kill:
                        events.attach_mock(kill, "kill")
                        with self.assertRaises(type(error)) as raised:
                            runner.run("interrupted", "arg", required=False)
                self.assertIs(raised.exception, error)
                self.assertEqual([call[0] for call in events.mock_calls], ["wait", "kill", "wait"])
                kill.assert_called_once_with(child.pid, signal.SIGKILL)
                self.assertEqual(popen.call_args.kwargs["stdin"], subprocess.DEVNULL)
                self.assertTrue(popen.call_args.kwargs["start_new_session"])
                saved = json.loads((runner.output / "commands.json").read_text())
                self.assertEqual(saved[0]["exit"], -signal.SIGKILL)
                self.assertEqual(saved[0]["error_type"], type(error).__name__)

    def test_exited_child_race_still_reaps_and_preserves_original_error(self):
        runner = evidence.Runner("fixture", {}, self.root)
        error = KeyboardInterrupt()
        child = Mock(pid=12345)
        child.wait.side_effect = [error, 0]
        process = Mock()
        process.__enter__ = Mock(return_value=child)
        process.__exit__ = Mock(return_value=False)
        with patch.object(evidence.subprocess, "Popen", return_value=process):
            with patch.object(evidence.os, "killpg", side_effect=ProcessLookupError()):
                with self.assertRaises(KeyboardInterrupt) as raised:
                    runner.run("raced")
        self.assertIs(raised.exception, error)
        self.assertEqual(child.wait.call_count, 2)
        self.assertEqual(runner.commands[0]["exit"], 0)

    def test_resize_harness_records_interruption_before_final_cleanup(self):
        spec = importlib.util.spec_from_file_location(
            "resize_cancellation_evidence", Path(__file__).with_name("resize-cancellation-evidence.py"))
        harness = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(harness)
        package = types.ModuleType("microsandbox")
        for name in ("ResourceConvergenceState", "ResizeOutcome", "ResizeTimeoutError", "ResizeWaitError", "Sandbox"):
            setattr(package, name, object())
        native = types.ModuleType("microsandbox._microsandbox")
        native.__file__ = __file__
        package._microsandbox = native

        for index, error in enumerate(interruptions()):
            with self.subTest(error=type(error).__name__):
                output = self.root / str(index)
                args = ["evidence", "--output", str(output), "--temp-root", str(self.root)]
                for key in ("binary", "agent", "firmware", "image"):
                    args.extend(["--" + key, __file__])

                def interrupted(coroutine):
                    coroutine.close()
                    raise error

                runner = Mock()
                runner.run.return_value = 0
                with patch.dict(sys.modules, {"microsandbox": package, "microsandbox._microsandbox": native}), \
                        patch.object(sys, "argv", args), patch.dict(os.environ), \
                        patch.object(evidence, "install_termination_handler"), \
                        patch.object(evidence, "Runner", return_value=runner), \
                        patch.object(harness.asyncio, "wait_for", new=lambda coroutine, **_: coroutine), \
                        patch.object(harness.asyncio, "run", side_effect=interrupted):
                    with self.assertRaises(type(error)) as raised:
                        harness.main()
                self.assertIs(raised.exception, error)
                saved = json.loads((output / "report.json").read_text())
                self.assertEqual(saved["status"], "failed")
                self.assertIn(type(error).__name__, saved["traceback"])
                self.assertEqual(saved["cleanup"]["resize-cancel"], {"stop": 0, "rm": 0})
                self.assertEqual(saved["remaining_sandboxes"], 0)
                self.assertEqual(saved["remaining_live_runs"], 0)
                self.assertEqual(saved["surviving_pids"], [])

    def test_resource_harness_records_interruption_and_stops_the_matrix(self):
        spec = importlib.util.spec_from_file_location(
            "resource_capability_evidence", Path(__file__).with_name("resource-capability-evidence.py"))
        harness = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(harness)
        for index, error in enumerate(interruptions()):
            with self.subTest(error=type(error).__name__):
                home = self.root / f"home-{index}"
                (home / "db").mkdir(parents=True)
                with sqlite3.connect(home / "db/msb.db") as db:
                    db.executescript("CREATE TABLE sandbox (id INTEGER); "
                                     "CREATE TABLE run (pid INTEGER, terminated_at TEXT);")
                output = self.root / f"output-{index}"
                args = ["evidence", "--output", str(output), "--temp-root", str(self.root)]
                for key in ("old-runtime", "new-runtime", "old-agent", "new-agent",
                            "firmware", "probe", "image"):
                    args.extend(["--" + key, __file__])
                archive = Mock()
                archive.__enter__ = Mock(return_value=archive)
                archive.__exit__ = Mock(return_value=False)
                archive.extractfile.return_value = io.BytesIO(b'[{"RepoTags":["fixture"]}]')
                runner = Mock()
                runner.run.side_effect = [error, 0, 0]
                with patch.object(sys, "argv", args), \
                        patch.object(evidence, "install_termination_handler"), \
                        patch.object(evidence, "Runner", return_value=runner), \
                        patch.object(harness.tarfile, "open", return_value=archive), \
                        patch.object(harness.tempfile, "mkdtemp", return_value=str(home)):
                    with self.assertRaises(type(error)) as raised:
                        harness.main()
                self.assertIs(raised.exception, error)
                saved = json.loads((output / "report.json").read_text())
                self.assertEqual(saved["status"], "failed")
                self.assertEqual(len(saved["cases"]), 1)
                case = saved["cases"][0]
                self.assertEqual(case["status"], "failed")
                self.assertIn(type(error).__name__, case["traceback"])
                self.assertEqual(case["cleanup"], {"stop": 0, "rm": 0})
                self.assertEqual(case["remaining_sandboxes"], 0)
                self.assertEqual(case["remaining_live_runs"], 0)
                self.assertEqual(case["surviving_pids"], [])

    @unittest.skipUnless(os.name == "posix", "Unix process supervision")
    def test_real_sigterm_reaps_owned_child_and_saves_evidence(self):
        child_file = self.root / "child.pid"
        # Only a disposable Python sleeper is started, never msb or a VM. The marker
        # makes signal delivery deterministic after Runner has admitted its child.
        child_code = "import os,time,pathlib; pathlib.Path(%r).write_text(str(os.getpid())); time.sleep(60)" % str(child_file)
        supervisor_code = (
            "import os,sys; from pathlib import Path; "
            "sys.path.insert(0, sys.argv[1]); import lifecycle_evidence as e; "
            "e.install_termination_handler(); "
            "e.Runner(sys.executable, os.environ.copy(), Path(sys.argv[2])).run('sleeper', '-c', sys.argv[3])"
        )
        with subprocess.Popen([sys.executable, "-c", supervisor_code, str(Path(evidence.__file__).parent),
                               str(self.root / "commands"), child_code],
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True) as supervisor:
            child_pid = None
            try:
                deadline = time.monotonic() + 10
                while not child_file.exists() or not child_file.read_text():
                    if supervisor.poll() is not None or time.monotonic() >= deadline:
                        self.fail("supervised child did not become ready")
                    time.sleep(0.01)
                child_pid = int(child_file.read_text())
                supervisor.send_signal(signal.SIGTERM)
                _, stderr = supervisor.communicate(timeout=10)
                self.assertEqual(supervisor.returncode, 143, stderr)
                with self.assertRaises(ProcessLookupError):
                    os.kill(child_pid, 0)
                child_pid = None  # Already reaped; never signal a subsequently reused PID.
                saved = json.loads((self.root / "commands/commands.json").read_text())
                self.assertEqual(saved[0]["error_type"], "SystemExit")
                self.assertEqual(saved[0]["exit"], -signal.SIGKILL)
            finally:
                # A failing regression must not itself leave the sleeper or supervisor.
                if child_pid is not None:
                    try:
                        os.kill(child_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass  # Expected when the supervisor already reaped its child.
                if supervisor.poll() is None:
                    supervisor.kill()
                supervisor.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
