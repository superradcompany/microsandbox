"""Exercise failure and signal handling through the actual harness entry points."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


HARNESSES = ("snapshot-launch-proxy.py", "snapshot-resume-policy.py")


class CleanupTests(unittest.TestCase):
    def fixture(self, root, name, body):
        binary = root / "candidate"
        binary.write_text(f"#!{sys.executable}\n" + body)
        binary.chmod(0o700)
        artifact = root / "input"
        artifact.write_bytes(b"fixture bytes")
        output = root / "report"
        command = [sys.executable, str(Path(__file__).with_name(name)),
                   "--candidate", str(binary), "--agent", str(artifact),
                   "--firmware", str(artifact), "--archive", str(artifact),
                   "--output", str(output), "--temp-root", str(root)]
        return command, output

    def test_initial_failure_keeps_original_error_and_writes_report(self):
        for harness in HARNESSES:
            for catalog in ("absent", "empty", "corrupt"):
                with self.subTest(harness=harness, catalog=catalog), \
                        tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    body = "import os, pathlib, sqlite3\n"
                    if catalog != "absent":
                        body += "p=pathlib.Path(os.environ['MSB_HOME'])/'db/msb.db'\np.parent.mkdir()\n"
                        body += ("sqlite3.connect(p).close()\n" if catalog == "empty"
                                 else "p.write_bytes(b'not a database')\n")
                    body += "raise SystemExit(31)\n"
                    command, output = self.fixture(root, harness, body)
                    completed = subprocess.run(command, capture_output=True, text=True, timeout=20)
                    self.assertNotEqual(completed.returncode, 0)
                    report = json.loads((output / "report.json").read_text())
                    self.assertEqual(report["status"], "failed")
                    self.assertIn("exited 31", report["error"])
                    self.assertIn("catalog_audit", report["cleanup"])
                    self.assertIsNone(report["sandbox_count"])
                    self.assertTrue(report["archive_unchanged"])
                    if catalog == "absent":
                        self.assertFalse((Path(report["home"]) / "db/msb.db").exists())

    @unittest.skipUnless(os.name == "posix", "Unix process-group qualification")
    def test_sigterm_reaps_cli_and_writes_failure_report(self):
        for harness in HARNESSES:
            with self.subTest(harness=harness), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                pid_file = root / "child.pid"
                command, output = self.fixture(
                    root, harness,
                    "import os, pathlib, sys, time\n"
                    "if sys.argv[1] in ('stop', 'rm'): raise SystemExit(0)\n"
                    f"pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid()))\n"
                    "time.sleep(60)\n")
                with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      text=True) as process:
                    try:
                        deadline = time.monotonic() + 10
                        while not pid_file.exists() and time.monotonic() < deadline:
                            if process.poll() is not None:
                                self.fail(f"harness exited before starting the CLI: {process.communicate()}")
                            time.sleep(0.02)
                        self.assertTrue(pid_file.exists())
                        child_pid = int(pid_file.read_text())
                        process.send_signal(signal.SIGTERM)
                        process.communicate(timeout=15)
                        self.assertNotEqual(process.returncode, 0)
                        with self.assertRaises(ProcessLookupError):
                            os.kill(child_pid, 0)
                        report = json.loads((output / "report.json").read_text())
                        self.assertEqual(report["status"], "failed")
                        self.assertEqual(report["error"], str(128 + signal.SIGTERM))
                    finally:
                        if process.poll() is None:
                            if pid_file.exists():
                                try:
                                    os.killpg(int(pid_file.read_text()), signal.SIGKILL)
                                except ProcessLookupError:
                                    # The process group may already have exited during teardown.
                                    pass
                            process.kill()
                            process.communicate()


if __name__ == "__main__":
    unittest.main()
