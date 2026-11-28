"""Regression tests for the device smoke test's failure cleanup."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "device_permissions", Path(__file__).with_name("device-permissions.py"))
SMOKE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SMOKE)


class CleanupTest(unittest.TestCase):
    def test_removal_timeout_keeps_report_and_attempts_other_sandbox(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "results"
            home = Path(directory) / "home"
            home.mkdir()
            removals = []

            def run(command, **kwargs):
                if command[1] == "rm":
                    removals.append(command[-1])
                    if len(removals) == 1:
                        raise subprocess.TimeoutExpired(command, 120)
                    return subprocess.CompletedProcess(command, 0, "", "")
                if command[1] == "create":
                    return subprocess.CompletedProcess(command, 0, "", "")
                restricted = "device-permissions-restricted" in command
                if "/proc/self/status" in command[-1]:
                    caps = "0" if restricted else "200000"
                    stdout = f"NoNewPrivs: {int(restricted)}\nCapEff: {caps}\n"
                elif "/proc/mounts" in command[-1]:
                    stdout = "rw,nosuid,nodev" if restricted else "rw"
                elif "mount -t tmpfs" in command[-1]:
                    return subprocess.CompletedProcess(command, int(restricted), "", "")
                elif "stat" in command:
                    stdout = "666 0 0"
                else:
                    stdout = ""
                return subprocess.CompletedProcess(command, 0, stdout, "")

            argv = ["device-permissions.py", "--binary", sys.executable,
                    "--output", str(output)]
            with patch.object(sys, "argv", argv), \
                    patch.object(SMOKE.tempfile, "mkdtemp", return_value=str(home)), \
                    patch.object(SMOKE.subprocess, "run", side_effect=run):
                with self.assertRaises(SystemExit):
                    SMOKE.main()
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(removals, ["device-permissions-default",
                                       "device-permissions-restricted"])
            self.assertFalse(report["cleanup_ok"])
            self.assertTrue(any("device-permissions-default" in failure
                                for failure in report["failures"]))
            self.assertTrue(home.exists())


if __name__ == "__main__":
    unittest.main()
