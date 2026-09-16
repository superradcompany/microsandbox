#!/usr/bin/env python3
"""VM-free regression tests for restore-resource-intent cleanup and reporting."""

import contextlib
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
import unittest.mock as mock


SCRIPT = Path(__file__).with_name("restore-resource-intent.py")


class RestoreResourceIntentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="restore-intent-unit-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.output = self.root / "run"
        self.snapshot = self.root / "saved"
        self.snapshot.mkdir()
        # The harness hashes this fixture before and after the restore matrix.
        (self.snapshot / "snapshot.json").write_text('{"fixture": "full snapshot"}\n')
        self.created = []
        self.rejected = set()
        self.cleanup_errors = {}
        self.failed_create = None
        contexts = contextlib.ExitStack()
        self.addCleanup(contexts.close)
        contexts.enter_context(contextlib.redirect_stdout(io.StringIO()))
        contexts.enter_context(mock.patch.dict(os.environ, {
            "MSB_PATH": str(self.root / "fake-msb"),
            "RESTORE_INTENT_OUT": str(self.output),
            "RESTORE_INTENT_LAYOUT": "flat:512M",
        }))
        # Patch the process boundary before runpy: no test command can launch a VM.
        self.process = contexts.enter_context(mock.patch.object(
            subprocess, "run", side_effect=self.fake_process,
        ))

    def fake_process(self, command, **kwargs):
        self.assertEqual(kwargs["input"], "")
        self.assertEqual(kwargs["env"]["MSB_HOME"], str(self.output / "home"))
        if kwargs["timeout"] == 30:
            self.assertEqual(command[1], "stop")
            error = self.cleanup_errors.get(command[2])
            if error is not None:
                raise error
            return subprocess.CompletedProcess(command, 0, "", "")

        self.assertEqual(kwargs["timeout"], 180)
        code, stdout, stderr = 0, "", ""
        if command[1] == "create":
            name = command[command.index("--name") + 1]
            self.created.append(name)
            if name == self.failed_create:
                code, stderr = 1, "original create failure"
            elif name.rsplit("-", 1)[-1] in ("smaller", "larger", "cpus", "flag"):
                self.rejected.add(name)
                code, stderr = 1, "captured CPU and memory geometry"
        elif command[1] == "inspect":
            name = command[2]
            if name in self.rejected:
                code, stderr = 1, "sandbox not found"
            else:
                stdout = json.dumps({"config": {"resources": {
                    "memory_mib": 128 if name == "disk-only" else 512,
                    "max_memory_mib": 512, "cpus": 2, "max_cpus": 2,
                }}})
        elif command[1:3] == ["snapshot", "create"]:
            stdout = str(self.snapshot) + "\n"
        else:
            self.assertTrue(command[1] in ("exec", "stop")
                            or command[1:3] == ["snapshot", "save"], command)
        return subprocess.CompletedProcess(command, code, stdout, stderr)

    def report(self):
        return json.loads((self.output / "results.json").read_text())

    def assert_all_cleanup_attempted(self, report):
        expected = list(reversed(self.created))
        attempted = [call.args[0][2] for call in self.process.call_args_list
                     if call.kwargs["timeout"] == 30]
        self.assertEqual(attempted, expected)
        self.assertEqual([row["name"] for row in report["cleanup"]], expected)

    def test_successful_matrix_reports_timeout_and_cleans_remaining_names(self):
        # TimeoutExpired can carry bytes even when subprocess.run uses text=True.
        self.cleanup_errors["disk-only"] = subprocess.TimeoutExpired(
            ["fake-msb", "stop", "disk-only"], 30, stderr=b"partial stop diagnostic\xff\n",
        )
        runpy.run_path(str(SCRIPT), run_name="__main__")
        report = self.report()
        self.assertTrue(report["success"])
        self.assertEqual(len(self.created), 30)
        self.assert_all_cleanup_attempted(report)
        self.assertEqual(report["cleanup"][0], {
            "name": "disk-only", "exit": "timeout", "timeout_seconds": 30,
            "stderr": "partial stop diagnostic\ufffd\n",
        })
        self.assertEqual(report["cleanup"][-1], {"name": "source", "exit": 0, "stderr": ""})

    def test_cleanup_timeout_preserves_original_matrix_failure_and_report(self):
        self.failed_create = "installed-eager-absent"
        self.cleanup_errors[self.failed_create] = subprocess.TimeoutExpired(
            ["fake-msb", "stop", self.failed_create], 30, stderr="still stopping",
        )
        with self.assertRaisesRegex(AssertionError, "installed-eager-absent: original create failure"):
            runpy.run_path(str(SCRIPT), run_name="__main__")
        report = self.report()
        self.assertFalse(report["success"])
        self.assertEqual(self.created, ["source", self.failed_create])
        self.assert_all_cleanup_attempted(report)
        self.assertEqual(report["rows"][-1]["case"], self.failed_create)
        self.assertEqual(report["rows"][-1]["exit"], 1)
        self.assertEqual(report["cleanup"][0]["exit"], "timeout")
        self.assertEqual(report["cleanup"][0]["stderr"], "still stopping")

    def test_cleanup_launch_error_is_reported_and_remaining_names_are_attempted(self):
        self.cleanup_errors["disk-only"] = OSError("stop executable unavailable")
        runpy.run_path(str(SCRIPT), run_name="__main__")
        report = self.report()
        self.assertTrue(report["success"])
        self.assert_all_cleanup_attempted(report)
        self.assertEqual(report["cleanup"][0], {
            "name": "disk-only", "exit": "error", "stderr": "stop executable unavailable",
        })


if __name__ == "__main__":
    unittest.main()
