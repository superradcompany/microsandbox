"""Recovery qualification must prove its crash point and surface damaged artifacts."""

import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "historical_recovery", Path(__file__).with_name("historical-recovery.py"))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.worker = self.root / "worker"
        self.log = self.root / "worker.log"

    def executable(self, body):
        self.worker.write_text(
            f"#!{sys.executable}\n"
            "import json, os, time\n"
            "from pathlib import Path\n"
            "root = Path(os.environ['MSB_TEST_HISTORICAL_ROOT'])\n"
            "(root / 'pid').write_text(str(os.getpid()))\n" + body)
        self.worker.chmod(0o700)

    def marker(self, pid="os.getpid()", action="'upgrade'", phase="'planned'", ready=True):
        return (
            f"(root / 'boundary.json').write_text(json.dumps("
            f"{{'pid': {pid}, 'action': {action}, 'phase': {phase}}}))\n"
            + ("(root / 'boundary-ready').touch()\n" if ready else "")
            + "time.sleep(60)\n")

    def assert_reaped(self):
        pid = int((self.root / "pid").read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def run_kill(self, timeout=3):
        return smoke.run_worker(
            self.worker, self.root, "upgrade", self.log, "planned", timeout=timeout)

    def test_acknowledged_matching_worker_is_killed_and_reaped(self):
        self.executable(self.marker())
        result = self.run_kill()
        self.assertEqual(result["exit"], -signal.SIGKILL)
        self.assertEqual(result["boundary"]["phase"], "planned")
        self.assert_reaped()

    def test_wrong_identity_or_phase_is_not_crash_evidence(self):
        for marker in (self.marker(pid="1"), self.marker(action="'downgrade'"),
                       self.marker(phase="'index_published'")):
            with self.subTest(marker=marker):
                self.executable(marker)
                with self.assertRaisesRegex(RuntimeError, "does not identify"):
                    self.run_kill()
                self.assert_reaped()

    def test_stale_acknowledgement_cannot_certify_unflushed_marker(self):
        (self.root / "boundary-ready").touch()
        self.executable(self.marker(ready=False))
        clock = time.monotonic
        # Expire only after the child writes its marker. Slow interpreter startup must
        # not accidentally test the earlier "no marker" timeout instead.
        def after_marker():
            return clock() + (100 if (self.root / "boundary.json").exists() else 0)
        with patch.object(smoke.time, "monotonic", side_effect=after_marker):
            with self.assertRaisesRegex(RuntimeError, "not durably acknowledged"):
                self.run_kill(timeout=30)
        self.assert_reaped()

    def test_timeout_reaps_worker(self):
        self.executable("time.sleep(60)\n")
        clock = time.monotonic
        def after_start():
            return clock() + (100 if (self.root / "pid").exists() else 0)
        with patch.object(smoke.time, "monotonic", side_effect=after_start):
            with self.assertRaises(TimeoutError):
                self.run_kill(timeout=30)
        self.assert_reaped()

    def test_early_success_is_not_a_kill_test(self):
        self.executable("")
        with self.assertRaisesRegex(RuntimeError, "exited before"):
            self.run_kill()
        self.assert_reaped()

    def test_missing_fresh_result_cannot_reuse_previous_success(self):
        self.executable("")
        (self.root / "result.json").write_text('{"status":"passed"}')
        with self.assertRaises(FileNotFoundError):
            smoke.run_worker(self.worker, self.root, "upgrade", self.log)
        self.assert_reaped()

    def test_nonzero_recovery_exit_fails(self):
        self.executable("raise SystemExit(7)\n")
        with self.assertRaisesRegex(RuntimeError, "failed with 7"):
            smoke.run_worker(self.worker, self.root, "upgrade", self.log)
        self.assert_reaped()

    def test_payload_and_exact_legacy_bytes_are_required(self):
        original, artifact = self.root / "original", self.root / "artifact"
        original.mkdir()
        artifact.mkdir()
        for directory in (original, artifact):
            (directory / "manifest.json").write_text('{"key":1}\n')
            (directory / "upper.ext4").write_bytes(b"guest payload")
        smoke.recovered_bytes(original, artifact, "downgrade")
        (artifact / "manifest.json").write_text('{"key": 1}\n')
        with self.assertRaisesRegex(RuntimeError, "exact original"):
            smoke.recovered_bytes(original, artifact, "downgrade")
        (artifact / "manifest.json").write_bytes((original / "manifest.json").read_bytes())
        (artifact / "upper.ext4").write_bytes(b"corrupted payload")
        with self.assertRaisesRegex(RuntimeError, "changed the historical disk"):
            smoke.recovered_bytes(original, artifact, "downgrade")

    def test_completed_downgrade_cannot_leave_current_descriptor(self):
        original, artifact = self.root / "original", self.root / "artifact"
        original.mkdir()
        artifact.mkdir()
        for directory in (original, artifact):
            (directory / "manifest.json").write_text("{}")
            (directory / "upper.ext4").write_bytes(b"disk")
        (artifact / "snapshot.json").write_text("{}")
        with self.assertRaisesRegex(RuntimeError, "left a canonical"):
            smoke.recovered_bytes(original, artifact, "downgrade")


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        originals = root / "fixture/originals"
        (originals / "artifact").mkdir(parents=True)
        (originals / "artifact/manifest.json").write_text("{}")
        (originals / "artifact/upper.ext4").write_bytes(b"disk")
        (originals / "fixture.msb").write_bytes(b"archive")
        for name in ("candidate", "worker", "legacy", "firmware", "agent"):
            (root / name).write_bytes(b"binary")
        (root / "fixture/fixture.json").write_text(json.dumps({
            "status": "produced", "producer_version": "0.6.6",
            "binary_sha256": smoke.history.digest(root / "legacy"),
            "originals": smoke.history.inventory(originals)}))
        self.args = SimpleNamespace(
            fixture=root / "fixture", candidate=root / "candidate", test_binary=root / "worker",
            legacy_binary=root / "legacy", firmware=root / "firmware", agent=root / "agent",
            output=root / "output", temp_root=root)
        self.failure = None
        self.commands = []

    def runner(self, binary, env, output):
        def run(label, *args, required=True):
            self.commands.append(label)
            if label.endswith("-create") and self.failure == "create":
                raise RuntimeError("failed create")
            if label.endswith("-guest") and self.failure == "guest":
                raise RuntimeError("guest checksum mismatch")
            if label.endswith("-cleanup-rm") and self.failure == "cleanup":
                return 1
            if label.endswith("-persistent") and self.failure == "original":
                (self.args.fixture / "originals/artifact/upper.ext4").write_bytes(b"changed")
            return 0
        return SimpleNamespace(run=run)

    def worker(self, binary, root, action, output, phase=None):
        if self.failure == "worker":
            raise RuntimeError("recovery failed")
        artifact = root / "snapshots/artifact"
        legacy = artifact / "manifest.json"
        if legacy.exists():
            legacy.rename(artifact / ".manifest.json.legacy")
        return {"index": [{"digest": "identity", "migration_state": "complete"}]}

    def qualify(self):
        with patch.object(smoke, "BOUNDARIES", {"upgrade": ("planned",)}), \
                patch.object(smoke.history, "Runner", side_effect=self.runner), \
                patch.object(smoke, "run_worker", side_effect=self.worker), \
                patch.object(smoke, "migration_state", return_value={}), \
                patch.object(smoke, "catalog_empty", return_value=True), \
                patch.object(smoke.subprocess, "check_output", return_value=smoke.WORKER + ": test\n"):
            smoke.qualify(self.args)

    def report(self):
        return json.loads((self.args.output / "report.json").read_text())

    def test_success_requires_guest_restart_and_cleanup(self):
        self.qualify()
        self.assertEqual(self.report()["status"], "passed")
        for suffix in ("-guest", "-restart", "-persistent", "-cleanup-stop", "-cleanup-rm"):
            self.assertTrue(any(label.endswith(suffix) for label in self.commands), suffix)

    def test_worker_failure_is_not_disguised_as_cleanup_failure(self):
        self.failure = "worker"
        with self.assertRaises(RuntimeError):
            self.qualify()
        row = self.report()["cases"][0]
        self.assertEqual(row["error"], "recovery failed")
        self.assertEqual(row["cleanup"], {})
        self.assertFalse(any("-create" in label for label in self.commands))

    def test_failed_create_still_attempts_stop_and_removal(self):
        self.failure = "create"
        with self.assertRaises(RuntimeError):
            self.qualify()
        row = self.report()["cases"][0]
        self.assertEqual(row["error"], "failed create")
        self.assertEqual(row["cleanup"], {"stop": 0, "rm": 0})

    def test_guest_failure_cannot_pass(self):
        self.failure = "guest"
        with self.assertRaises(RuntimeError):
            self.qualify()
        self.assertEqual(self.report()["cases"][0]["error"], "guest checksum mismatch")

    def test_cleanup_failure_cannot_pass(self):
        self.failure = "cleanup"
        with self.assertRaises(RuntimeError):
            self.qualify()
        self.assertEqual(self.report()["cases"][0]["status"], "failed")
        self.assertIn("cleanup_error", self.report()["cases"][0])

    def test_original_mutation_cannot_pass(self):
        self.failure = "original"
        with self.assertRaisesRegex(RuntimeError, "original artifacts changed"):
            self.qualify()
        self.assertEqual(self.report()["status"], "failed")
        self.assertFalse(self.report()["originals_unchanged"])


if __name__ == "__main__":
    unittest.main()
