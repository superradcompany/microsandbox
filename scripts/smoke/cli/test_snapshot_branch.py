#!/usr/bin/env python3
"""VM-free tests for snapshot-branch smoke isolation, reporting, and cleanup."""

from __future__ import annotations

import argparse
import contextlib
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
from types import SimpleNamespace
import unittest
import unittest.mock as mock


SPEC = importlib.util.spec_from_file_location(
    "snapshot_branch_smoke", Path(__file__).with_name("snapshot-branch.py")
)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)


class SnapshotBranchSmokeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="snapshot-branch-unit-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        contexts = contextlib.ExitStack()
        self.addCleanup(contexts.close)
        contexts.enter_context(contextlib.redirect_stdout(io.StringIO()))
        contexts.enter_context(contextlib.redirect_stderr(io.StringIO()))
        # Patch the process boundary globally for each test: no accidental command can boot a VM.
        self.process = contexts.enter_context(mock.patch.object(HARNESS.subprocess, "run"))
        self.process.side_effect = self.successful_process

    @staticmethod
    def successful_process(command, **_kwargs):
        stdout = "[]" if command[1] == "list" else ""
        return subprocess.CompletedProcess(command, 0, stdout, "")

    def smoke(self, output="run"):
        return HARNESS.Smoke(argparse.Namespace(
            binary=Path(sys.executable), output=self.root / output,
            layout="managed", image="test-image", timeout=30, suite_timeout=120,
        ))

    @staticmethod
    def report(smoke):
        return json.loads((smoke.root / "report.json").read_text())

    def commands(self):
        return [call.args[0][1:] for call in self.process.call_args_list]

    @staticmethod
    def run_history(smoke, rows):
        database = smoke.home / "db/msb.db"
        database.parent.mkdir(parents=True)
        with contextlib.closing(sqlite3.connect(database)) as db, db:
            db.execute('CREATE TABLE "run" (pid INTEGER, status TEXT)')
            db.executemany('INSERT INTO "run" (pid, status) VALUES (?, ?)', rows)
        return database

    def test_defer_interrupts_records_signals_and_restores_handlers_on_exception(self):
        original = {signal.SIGINT: mock.Mock(), signal.SIGTERM: mock.Mock()}
        handlers = dict(original)
        with mock.patch.object(HARNESS.signal, "getsignal", side_effect=handlers.__getitem__), \
                mock.patch.object(HARNESS.signal, "signal", side_effect=handlers.__setitem__):
            with self.assertRaisesRegex(RuntimeError, "cleanup failed"):
                with HARNESS.defer_interrupts() as received:
                    handlers[signal.SIGINT](signal.SIGINT, None)
                    handlers[signal.SIGTERM](signal.SIGTERM, None)
                    self.assertEqual(received, [signal.SIGINT, signal.SIGTERM])
                    raise RuntimeError("cleanup failed")
            self.assertEqual(handlers, original)
        for handler in original.values():
            handler.assert_not_called()

    def test_isolates_home_backend_config_and_command_working_directory(self):
        ambient = {
            "MSB_HOME": str(self.root / "caller-home"),
            "MSB_CONFIG_PATH": str(self.root / "caller-config.json"),
            "MSB_BACKEND": "cloud", "MSB_PROFILE": "production",
            "MSB_AGENTD_PATH": "/matching/agentd", "NO_COLOR": "0",
        }
        with mock.patch.dict(os.environ, ambient):
            smoke = self.smoke()
            smoke.run("probe", "list", "--format", "json")
            self.assertEqual(os.environ["MSB_HOME"], ambient["MSB_HOME"])
        passed = self.process.call_args.kwargs
        self.assertEqual(passed["cwd"], smoke.root)
        self.assertEqual(passed["env"]["MSB_HOME"], str(smoke.root / "home"))
        self.assertEqual(passed["env"]["MSB_BACKEND"], "local")
        self.assertEqual(passed["env"]["NO_COLOR"], "1")
        self.assertEqual(passed["env"]["MSB_AGENTD_PATH"], "/matching/agentd")
        self.assertNotIn("MSB_CONFIG_PATH", passed["env"])
        self.assertNotIn("MSB_PROFILE", passed["env"])
        self.assertEqual(self.report(smoke)["home"], str(smoke.home))
        self.assertFalse((self.root / "caller-home").exists())

    def test_refuses_existing_output_without_overwriting_it(self):
        output = self.root / "existing"
        output.mkdir()
        sentinel = output / "report.json"
        sentinel.write_text("keep existing report")
        with self.assertRaises(FileExistsError):
            self.smoke("existing")
        self.assertEqual(sentinel.read_text(), "keep existing report")
        self.process.assert_not_called()

    def test_records_success_and_clean_expected_failures(self):
        smoke = self.smoke()
        for code, expected_failure in [(0, False), (1, True), (2, True), (255, True)]:
            with self.subTest(code=code, expected_failure=expected_failure):
                self.process.side_effect = None
                self.process.return_value = subprocess.CompletedProcess(
                    [], code, " output\n", " diagnostic\n"
                )
                self.assertEqual(
                    smoke.run(f"exit-{code}", "probe", expected_failure=expected_failure),
                    ("output", "diagnostic"),
                )
                row = self.report(smoke)["commands"][-1]
                self.assertEqual(row["exit"], code)
                self.assertEqual(row["expected_failure"], expected_failure)
                self.assertFalse(row["timed_out"])

    def test_unexpected_success_failure_and_crashes_are_not_accepted(self):
        smoke = self.smoke()
        # Windows exception statuses are positive; they must not pass as ordinary refusals.
        for code, expected_failure in [
            (0, True), (1, False), (-9, False), (-9, True),
            (256, True), (0xC0000005, False), (0xC0000005, True),
        ]:
            with self.subTest(code=code, expected_failure=expected_failure):
                self.process.side_effect = None
                self.process.return_value = subprocess.CompletedProcess([], code, "", "failed")
                with self.assertRaisesRegex(RuntimeError, "failed"):
                    smoke.run("rejected", "probe", expected_failure=expected_failure)
                self.assertEqual(self.report(smoke)["commands"][-1]["exit"], code)

    def test_timeout_preserves_partial_bytes_in_logs_and_report(self):
        smoke = self.smoke()
        self.process.side_effect = subprocess.TimeoutExpired(
            [sys.executable, "probe"], 30, output=b"partial\xff\n", stderr=b"waiting\xfe"
        )
        with self.assertRaisesRegex(RuntimeError, "timed out"):
            smoke.run("slow", "probe", expected_failure=True)
        row = self.report(smoke)["commands"][-1]
        self.assertTrue(row["timed_out"])
        self.assertIsNone(row["exit"])
        self.assertEqual(next(smoke.logs.glob("*slow.stdout.log")).read_text(encoding="utf-8"), "partial\ufffd\n")
        self.assertEqual(next(smoke.logs.glob("*slow.stderr.log")).read_text(encoding="utf-8"), "waiting\ufffd")

    def test_expired_suite_deadline_still_allows_bounded_cleanup(self):
        smoke = self.smoke()
        smoke.remember("owned")
        smoke.deadline = time.monotonic() - 1
        with self.assertRaisesRegex(RuntimeError, "suite deadline exceeded"):
            smoke.run("too-late", "probe")
        self.process.assert_not_called()
        self.assertEqual(smoke.cleanup(), [])
        self.assertIn(["stop", "owned", "--timeout", "5"], self.commands())
        self.assertEqual(self.commands()[-1], ["list", "--format", "json"])
        self.assertTrue(all(call.kwargs["timeout"] > 0 for call in self.process.call_args_list))
        self.assertTrue(all(row["phase"] == "cleanup" for row in smoke.report["commands"]))

    def test_restore_uses_dedicated_command_and_registers_cleanup(self):
        smoke = self.smoke()
        smoke.restore("child", "saved.msb", "--forked")
        self.assertEqual(self.commands(), [["restore", "saved.msb", "--name", "child", "--forked"]])
        self.assertEqual(smoke.active, ["child"])

    def test_failed_create_is_still_registered_for_cleanup(self):
        smoke = self.smoke()
        self.process.side_effect = subprocess.TimeoutExpired([sys.executable, "create"], 30)
        with self.assertRaisesRegex(RuntimeError, "timed out"):
            smoke.create("possibly-started", "test-image")
        self.process.side_effect = self.successful_process
        self.assertEqual(smoke.cleanup(), [])
        self.assertIn(["stop", "possibly-started", "--timeout", "5"], self.commands())

    def test_cleanup_attempts_every_vm_and_force_fallback_despite_stop_failures(self):
        smoke = self.smoke()
        for name in ("first", "second", "third"):
            smoke.remember(name)

        def process(command, **kwargs):
            if command[1] == "stop":
                name, forced = command[2], "--force" in command
                # One fallback succeeds; another fails. Neither may prevent the next VM's stop.
                code = int(name == "third" or (name == "second" and not forced))
                return subprocess.CompletedProcess(command, code, "", "stop refused")
            return self.successful_process(command, **kwargs)

        self.process.side_effect = process
        errors = smoke.cleanup()
        for name in ("first", "second", "third"):
            self.assertIn(["stop", name, "--timeout", "5"], self.commands())
        for name in ("second", "third"):
            self.assertIn(["stop", name, "--force"], self.commands())
        self.assertEqual(self.commands()[-1], ["list", "--format", "json"])
        self.assertEqual(len(smoke.report["cleanup"]), 3)
        self.assertTrue(any("third" in error for error in errors))

    def test_cleanup_rejects_resident_inventory_but_accepts_terminal_entries(self):
        smoke = self.smoke()
        resident = [{"name": "running", "status": "Running"},
                    {"name": "paused", "status": "Paused"}]
        terminal = [{"name": "stopped", "status": "Stopped"},
                    {"name": "crashed", "status": "Crashed"}]
        self.process.side_effect = None
        self.process.return_value = subprocess.CompletedProcess(
            [], 0, json.dumps(resident + terminal), ""
        )
        self.assertTrue(any("remain resident" in error for error in smoke.cleanup()))
        self.assertEqual(smoke.report["remaining_sandboxes"], resident)
        self.process.return_value = subprocess.CompletedProcess([], 0, json.dumps(terminal), "")
        self.assertEqual(smoke.cleanup(), [])
        self.assertEqual(smoke.report["remaining_sandboxes"], [])

    def test_cleanup_inventory_failure_is_reported(self):
        smoke = self.smoke()
        self.process.side_effect = None
        self.process.return_value = subprocess.CompletedProcess([], 0, "not JSON", "")
        self.assertTrue(any("could not verify VM cleanup" in error for error in smoke.cleanup()))

    def test_runtime_pids_checks_stopped_history_and_ignores_zombies_and_absent_processes(self):
        smoke = self.smoke()
        database = self.run_history(smoke, [
            (41001, "Stopped"), (41002, "Stopped"), (41003, "Stopped"),
            (41003, "Crashed"), (0, "Running"), (-1, "Running"), (None, "Stopped"),
        ])
        before = database.read_bytes()
        states = {41001: (0, "Z+\n"), 41002: (1, ""), 41003: (0, "S+\n")}

        def process(command, **_kwargs):
            self.assertEqual(command[0], "ps")
            code, state = states[int(command[2])]
            return subprocess.CompletedProcess(command, code, state, "")

        self.process.side_effect = process
        platform = SimpleNamespace(name="posix", kill=mock.Mock())
        with mock.patch.object(HARNESS, "os", platform), \
                mock.patch.object(HARNESS.sqlite3, "connect", wraps=sqlite3.connect) as connect:
            self.assertEqual(smoke.runtime_pids(), [41003])
        self.assertEqual(connect.call_args.args[0], database.as_uri() + "?mode=ro")
        self.assertTrue(connect.call_args.kwargs["uri"])
        self.assertEqual([int(call.args[0][2]) for call in self.process.call_args_list],
                         [41001, 41002, 41003])
        self.assertEqual(database.read_bytes(), before)
        platform.kill.assert_not_called()

    def test_runtime_pids_reads_windows_tasklist_csv_and_requires_exact_pid(self):
        smoke = self.smoke()
        self.run_history(smoke, [(42001, "Stopped"), (42002, "Stopped"), (42003, "Stopped")])
        outputs = {
            42001: '"msb.exe","42001","Console","1","8,192 K"\r\n',
            42002: "INFO: No tasks are running which match the specified criteria.\r\n",
            42003: '"msb.exe","420030","Console","1","4,096 K"\r\n',
        }

        def process(command, **kwargs):
            self.assertEqual(command[0], "tasklist")
            self.assertTrue(kwargs["check"])
            pid = int(command[2].split()[-1])
            return subprocess.CompletedProcess(command, 0, outputs[pid], "")

        self.process.side_effect = process
        platform = SimpleNamespace(name="nt", kill=mock.Mock())
        with mock.patch.object(HARNESS, "os", platform):
            self.assertEqual(smoke.runtime_pids(), [42001])
        self.assertEqual(self.process.call_count, 3)
        platform.kill.assert_not_called()

    def test_runtime_pids_does_not_create_a_missing_database(self):
        smoke = self.smoke()
        self.assertEqual(smoke.runtime_pids(), [])
        self.assertFalse((smoke.home / "db/msb.db").exists())
        self.process.assert_not_called()

    def test_runtime_history_connection_is_closed_even_when_query_fails(self):
        smoke = self.smoke()
        self.run_history(smoke, [])
        for error in [None, sqlite3.OperationalError("query failed")]:
            connection = mock.Mock()
            connection.execute.return_value = []
            connection.execute.side_effect = error
            with mock.patch.object(HARNESS.sqlite3, "connect", return_value=connection):
                if error is None:
                    self.assertEqual(smoke.runtime_pids(), [])
                else:
                    with self.assertRaisesRegex(sqlite3.OperationalError, "query failed"):
                        smoke.runtime_pids()
            connection.close.assert_called_once_with()

    def test_runtime_pids_reports_process_inspection_failure(self):
        smoke = self.smoke()
        self.run_history(smoke, [(43001, "Stopped")])
        self.process.side_effect = None
        self.process.return_value = subprocess.CompletedProcess([], 2, "", "ps unavailable")
        with mock.patch.object(HARNESS, "os", SimpleNamespace(name="posix")):
            with self.assertRaisesRegex(RuntimeError, "could not inspect runtime PID 43001"):
                smoke.runtime_pids()

    def test_cleanup_detects_live_runtime_pid_after_catalog_is_stopped_without_real_wait(self):
        smoke = self.smoke()
        self.run_history(smoke, [(44001, "Stopped")])

        def process(command, **_kwargs):
            if command[0] == "ps":
                return subprocess.CompletedProcess(command, 0, "S\n", "")
            return subprocess.CompletedProcess(
                command, 0, json.dumps([{"name": "owned", "status": "Stopped"}]), ""
            )

        self.process.side_effect = process
        # Advance a synthetic clock on each read, so the real grace period costs no wall time.
        with mock.patch.object(HARNESS, "os", SimpleNamespace(name="posix")), \
                mock.patch.object(HARNESS.time, "monotonic", side_effect=iter(range(0, 100, 2))), \
                mock.patch.object(HARNESS.time, "sleep") as sleep:
            errors = smoke.cleanup()
        sleep.assert_called()
        self.assertEqual(smoke.report["remaining_sandboxes"], [])
        self.assertEqual(smoke.report["remaining_runtime_pids"], [44001])
        self.assertTrue(any("runtime PIDs are still alive" in error for error in errors))

    def test_cleanup_succeeds_when_runtime_exits_during_grace_period(self):
        smoke = self.smoke()
        self.run_history(smoke, [(45001, "Stopped")])
        states = iter([(0, "S\n"), (1, "")])

        def process(command, **kwargs):
            if command[0] == "ps":
                code, state = next(states)
                return subprocess.CompletedProcess(command, code, state, "")
            return self.successful_process(command, **kwargs)

        self.process.side_effect = process
        with mock.patch.object(HARNESS, "os", SimpleNamespace(name="posix")), \
                mock.patch.object(HARNESS.time, "sleep") as sleep:
            self.assertEqual(smoke.cleanup(), [])
        sleep.assert_called_once()
        self.assertEqual(smoke.report["remaining_runtime_pids"], [])

    def test_cleanup_defers_interrupt_and_still_attempts_all_owned_vms(self):
        smoke = self.smoke()
        smoke.remember("first")
        smoke.remember("second")
        original = {signal.SIGINT: mock.Mock(), signal.SIGTERM: mock.Mock()}
        handlers = dict(original)

        def process(command, **kwargs):
            if command[1] == "stop" and command[2] == "second":
                handlers[signal.SIGTERM](signal.SIGTERM, None)
            return self.successful_process(command, **kwargs)

        self.process.side_effect = process
        with mock.patch.object(HARNESS.signal, "getsignal", side_effect=handlers.__getitem__), \
                mock.patch.object(HARNESS.signal, "signal", side_effect=handlers.__setitem__):
            errors = smoke.cleanup()
        self.assertEqual(handlers, original)
        self.assertTrue(any("interrupted during cleanup" in error for error in errors))
        for name in ("first", "second"):
            self.assertIn(["stop", name, "--timeout", "5"], self.commands())
        self.assertIn(["list", "--format", "json"], self.commands())

    def test_execute_cleans_and_persists_failure_even_when_interrupted(self):
        for index, error in enumerate((RuntimeError("operation failed"), KeyboardInterrupt())):
            with self.subTest(error=type(error).__name__):
                smoke = self.smoke(f"failure-{index}")
                self.process.reset_mock()

                def exercise():
                    smoke.remember("possibly-started")
                    raise error

                with mock.patch.object(smoke, "exercise", side_effect=exercise):
                    self.assertEqual(smoke.execute(), 1)
                report = self.report(smoke)
                self.assertEqual(report["status"], "failed")
                self.assertEqual(report["error"], str(error) or "interrupted")
                self.assertIn(["stop", "possibly-started", "--timeout", "5"], self.commands())
                self.assertIn(["list", "--format", "json"], self.commands())
                self.assertTrue(any(command[0] == "logs" for command in self.commands()))
                self.assertEqual(report["cleanup_errors"], [])

    def test_execute_setup_failure_still_verifies_cleanup(self):
        smoke = self.smoke()

        def process(command, **kwargs):
            if command[1] == "pull":
                return subprocess.CompletedProcess(command, 1, "", "image preparation failed")
            return self.successful_process(command, **kwargs)

        self.process.side_effect = process
        with mock.patch.object(smoke, "exercise") as exercise:
            self.assertEqual(smoke.execute(), 1)
        exercise.assert_not_called()
        report = self.report(smoke)
        self.assertEqual(report["status"], "failed")
        self.assertIn("prepare-image", report["error"])
        self.assertEqual(report["operations_ms"], 0)
        self.assertIn(["list", "--format", "json"], self.commands())

    def test_execute_fails_if_cleanup_leaves_a_resident_vm(self):
        smoke = self.smoke()

        def process(command, **kwargs):
            if command[1] == "list":
                return subprocess.CompletedProcess(
                    command, 0, json.dumps([{"name": "owned", "status": "Running"}]), ""
                )
            return self.successful_process(command, **kwargs)

        self.process.side_effect = process
        with mock.patch.object(smoke, "exercise", side_effect=lambda: smoke.remember("owned")):
            self.assertEqual(smoke.execute(), 1)
        report = self.report(smoke)
        self.assertEqual(report["status"], "failed")
        self.assertIsNone(report["error"])
        self.assertTrue(report["cleanup_errors"])

    def test_execute_reports_success_only_after_clean_inventory(self):
        smoke = self.smoke()
        with mock.patch.object(smoke, "exercise"):
            self.assertEqual(smoke.execute(), 0)
        report = self.report(smoke)
        self.assertEqual(report["status"], "passed")
        self.assertIsNone(report["error"])
        self.assertEqual(report["cleanup_errors"], [])
        self.assertEqual(self.commands()[-1], ["list", "--format", "json"])

    def test_success_removes_only_owned_home_and_keeps_text_evidence(self):
        smoke = self.smoke()
        smoke.home.mkdir()
        (smoke.home / "test-ram").write_bytes(b"fixture")
        sibling = self.root / "unrelated"
        sibling.write_text("keep")
        with mock.patch.object(smoke, "exercise"):
            self.assertEqual(smoke.execute(), 0)
        self.assertFalse(smoke.home.exists())
        self.assertTrue(self.report(smoke)["home_removed"])
        self.assertTrue(any(smoke.logs.iterdir()))
        self.assertEqual(sibling.read_text(), "keep")

    def test_failure_retains_owned_home_for_investigation(self):
        smoke = self.smoke()
        smoke.home.mkdir()
        fixture = smoke.home / "test-ram"
        fixture.write_bytes(b"fixture")
        with mock.patch.object(smoke, "exercise", side_effect=RuntimeError("injected failure")):
            self.assertEqual(smoke.execute(), 1)
        self.assertEqual(fixture.read_bytes(), b"fixture")
        self.assertFalse(self.report(smoke)["home_removed"])


if __name__ == "__main__":
    unittest.main()
