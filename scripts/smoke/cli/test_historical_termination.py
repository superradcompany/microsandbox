"""Exercise signal cleanup through the historical harnesses' real entry points."""

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


WORKER = "backend::local::snapshot::historical_recovery_tests::historical_recovery_worker"


@unittest.skipUnless(os.name == "posix", "Unix process-group qualification")
class HistoricalTerminationTests(unittest.TestCase):
    def test_sigterm_reaps_command_or_worker_and_finishes_report(self):
        for harness in ("historical-snapshots.py", "historical-recovery.py"):
            with self.subTest(harness=harness), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                pid_file, calls = root / "child.pid", root / "calls"
                binary, worker = root / "candidate", root / "worker"
                binary.write_text(
                    f"#!{sys.executable}\n"
                    "import os, pathlib, sys, time\n"
                    f"with pathlib.Path({str(calls)!r}).open('a') as f: f.write(sys.argv[1]+'\\n')\n"
                    "if sys.argv[1] in ('stop', 'rm', '--version', 'snapshot', 'create'):\n"
                    "    raise SystemExit(0)\n"
                    f"pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid()))\n"
                    "time.sleep(60)\n")
                worker.write_text(
                    f"#!{sys.executable}\n"
                    "import os, pathlib, sys, time\n"
                    f"if '--list' in sys.argv: print({WORKER!r}+': test'); raise SystemExit(0)\n"
                    f"pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid()))\n"
                    "time.sleep(60)\n")
                binary.chmod(0o700)
                worker.chmod(0o700)
                originals = root / "fixture/originals"
                (originals / "artifact").mkdir(parents=True)
                (originals / "fixture.msb").write_bytes(b"private test archive")
                (originals / "artifact/manifest.json").write_text("{}")
                (originals / "artifact/upper.ext4").write_bytes(b"private disk")
                inventory = {str(p.relative_to(originals)): {
                    "bytes": p.stat().st_size, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                    for p in originals.rglob("*") if p.is_file()}
                (root / "fixture/fixture.json").write_text(json.dumps({
                    "status": "produced", "producer_version": "0.6.0", "originals": inventory,
                    "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}))
                output = root / "report"
                command = [sys.executable, str(Path(__file__).with_name(harness))]
                if harness == "historical-snapshots.py":
                    command.append("qualify")
                else:
                    command += ["--test-binary", str(worker), "--legacy-binary", str(binary),
                                "--temp-root", str(root)]
                command += ["--fixture", str(root / "fixture"), "--candidate", str(binary),
                            "--agent", str(binary), "--firmware", str(binary), "--output", str(output)]
                with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      text=True) as process:
                    try:
                        deadline = time.monotonic() + 15
                        while not pid_file.exists() and time.monotonic() < deadline:
                            if process.poll() is not None:
                                self.fail(f"harness exited before its child started: {process.communicate()}")
                            time.sleep(0.02)
                        self.assertTrue(pid_file.exists(), "harness did not start its child")
                        child_pid = int(pid_file.read_text())
                        process.send_signal(signal.SIGTERM)
                        process.communicate(timeout=15)
                        self.assertEqual(process.returncode, 128 + signal.SIGTERM)
                        with self.assertRaises(ProcessLookupError):
                            os.kill(child_pid, 0)
                        report = json.loads((output / "report.json").read_text())
                        self.assertEqual(report["status"], "failed")
                        self.assertEqual(report["error"], str(128 + signal.SIGTERM))
                        self.assertTrue(report["originals_unchanged"])
                        self.assertEqual(report["cases"][0]["status"], "failed")
                        if harness == "historical-snapshots.py":
                            self.assertEqual(report["cases"][0]["cleanup"], {"stop": 0, "rm": 0})
                            self.assertEqual(calls.read_text().splitlines()[-2:], ["stop", "rm"])
                    finally:
                        # Reap the intentionally parked child even when testing the old
                        # broken handler, so the failing regression itself leaks nothing.
                        if pid_file.exists():
                            try:
                                os.killpg(int(pid_file.read_text()), signal.SIGKILL)
                            except ProcessLookupError:
                                pass  # The fixed harness has already reaped this group.
                        if process.poll() is None:
                            process.kill()
                            process.communicate()


if __name__ == "__main__":
    unittest.main()
