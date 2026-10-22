"""Failure evidence must survive cleanup timeouts and process interruption."""

import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import Mock

import lifecycle_evidence as evidence


class SavedEvidenceCleanupTests(unittest.TestCase):
    def test_success_requires_zero_cleanup_exits_and_successful_audit(self):
        for code, audit_error in [(0, None), (3, None), (0, RuntimeError("surviving VM"))]:
            with self.subTest(code=code, audit_error=audit_error), tempfile.TemporaryDirectory() as directory:
                report = {"status": "passed", "cleanup": {"one": {}}}
                runner = Mock()
                runner.run.return_value = code
                evidence.finish_saved_evidence(runner, report["cleanup"], report, report,
                                               Path(directory), Mock(side_effect=audit_error))
                saved = json.loads((Path(directory) / "report.json").read_text())
                self.assertEqual(saved["status"], "failed" if code or audit_error else "passed")

    def test_timeout_does_not_skip_remove_other_targets_or_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            row = {"status": "passed", "cleanup": {"one": {}, "two": {}}}
            report = {"status": "passed", "cases": [row]}
            runner = Mock()
            runner.run.side_effect = [subprocess.TimeoutExpired("stop", 180), 0, 0, 0]
            audit = Mock()
            evidence.finish_saved_evidence(runner, row["cleanup"], row, report,
                                           Path(directory), audit, force=True)
            self.assertEqual(runner.run.call_count, 4)
            self.assertEqual([call.args[1] for call in runner.run.call_args_list],
                             ["stop", "rm", "stop", "rm"])
            self.assertEqual(runner.run.call_args_list[0].args[2], "--force")
            audit.assert_called_once()
            saved = json.loads((Path(directory) / "report.json").read_text())
            self.assertEqual(saved["status"], "failed")
            self.assertEqual(saved["cases"][0]["cleanup"]["two"], {"stop": 0, "rm": 0})

    def test_interruptions_save_failure_before_propagation(self):
        for stage in ("prepare", "stop", "audit"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                row = {"status": "passed", "cleanup": {"one": {}, "two": {}}}
                report = {"status": "passed", "cases": [row]}
                runner, prepare, audit = Mock(), Mock(), Mock()
                runner.run.return_value = 0
                interrupted = SystemExit(143)
                if stage == "stop":
                    runner.run.side_effect = [interrupted, 0, 0, 0]
                else:
                    {"prepare": prepare, "audit": audit}[stage].side_effect = interrupted
                with self.assertRaises(SystemExit) as caught:
                    evidence.finish_saved_evidence(runner, row["cleanup"], row, report,
                                                   Path(directory), audit, prepare=prepare)
                self.assertEqual(caught.exception.code, 143)
                self.assertEqual(runner.run.call_count, 4)
                audit.assert_called_once()
                saved = json.loads((Path(directory) / "report.json").read_text())
                self.assertEqual(saved["status"], "failed")
                self.assertEqual(saved["cases"][0]["status"], "failed")

    def fixture(self, directory, harness, cleanup_wait=False):
        root = Path(directory)
        support = root / "support"
        support.mkdir()
        for name in (harness, "lifecycle_evidence.py"):
            shutil.copy2(Path(__file__).with_name(name), support / name)
        # Deliberately omit historical-snapshots.py and its release dependencies.
        binary = root / "candidate"
        binary.write_text(f"#!{sys.executable}\n" +
                          "import os, pathlib, sys, time\n" +
                          f"root = pathlib.Path({str(root)!r})\n" +
                          "operation = sys.argv[1]\n" +
                          "if operation == 'rm':\n"
                          "    (root/'removed').write_text('yes')\n"
                          "    raise SystemExit(0)\n" +
                          ("if operation == 'stop':\n"
                           "    (root/'child.pid').write_text(str(os.getpid()))\n"
                           "    time.sleep(60)\n" if cleanup_wait else "") +
                          ("if operation == 'image': raise SystemExit(0)\n"
                           if harness == "saved-init-evidence.py" else "") +
                          "raise SystemExit(31)\n")
        binary.chmod(0o700)
        image = root / "image.tar"
        with tarfile.open(image, "w") as archive:
            for name, content in {
                "manifest.json": [{"Config": "config.json", "Layers": [], "RepoTags": ["test:image"]}],
                "config.json": {"config": {}},
            }.items():
                data = json.dumps(content).encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        output = root / "output"
        command = [sys.executable, str(support / harness), "--binary", str(binary),
                   "--agent", str(binary), "--firmware", str(binary), "--image", str(image),
                   "--output", str(output), "--temp-root", str(root)]
        if harness == "saved-init-evidence.py":
            command += ["--old", str(binary)]
        else:
            command += ["--support", str(support), "--releases", str(root / "releases")]
            for version in ("v0.6.0", "v0.6.6", "v0.6.7", "v0.6.18", "v0.7.8"):
                target = root / "releases" / version
                target.mkdir(parents=True)
                shutil.copy2(binary, target / "msb")
        return command, output

    def test_entry_points_need_no_historical_matrix_and_report_initial_failure(self):
        for harness in ("saved-init-evidence.py", "saved-presence-evidence.py"):
            with self.subTest(harness=harness), tempfile.TemporaryDirectory() as directory:
                command, output = self.fixture(directory, harness)
                completed = subprocess.run(command, capture_output=True, text=True, timeout=20)
                self.assertNotEqual(completed.returncode, 0)
                report = json.loads((output / "report.json").read_text())
                self.assertEqual(report["status"], "failed")
                self.assertTrue((Path(directory) / "removed").exists())
                self.assertNotIn("ModuleNotFoundError", completed.stderr)

    @unittest.skipUnless(os.name == "posix", "Unix process-group qualification")
    def test_sigterm_during_cleanup_reaps_child_attempts_remove_and_saves_failure(self):
        for harness in ("saved-init-evidence.py", "saved-presence-evidence.py"):
            with self.subTest(harness=harness), tempfile.TemporaryDirectory() as directory:
                command, output = self.fixture(directory, harness, cleanup_wait=True)
                pid_file = Path(directory) / "child.pid"
                with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      text=True) as process:
                    try:
                        deadline = time.monotonic() + 10
                        while not pid_file.exists() and time.monotonic() < deadline:
                            if process.poll() is not None:
                                self.fail(f"exited before cleanup: {process.communicate()}")
                            time.sleep(0.02)
                        self.assertTrue(pid_file.exists())
                        pid = int(pid_file.read_text())
                        process.send_signal(signal.SIGTERM)
                        process.communicate(timeout=15)
                        self.assertNotEqual(process.returncode, 0)
                        with self.assertRaises(ProcessLookupError):
                            os.kill(pid, 0)
                        self.assertTrue((Path(directory) / "removed").exists())
                        report = json.loads((output / "report.json").read_text())
                        self.assertEqual(report["status"], "failed")
                    finally:
                        if process.poll() is None:
                            if pid_file.exists():
                                try:
                                    os.killpg(int(pid_file.read_text()), signal.SIGKILL)
                                except ProcessLookupError:
                                    pass
                            process.kill()
                            process.communicate()


if __name__ == "__main__":
    unittest.main()
