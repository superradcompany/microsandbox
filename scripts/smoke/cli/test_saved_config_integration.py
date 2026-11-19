"""Diagnostics survive disposable homes without publishing private records."""

from contextlib import redirect_stderr
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "saved_config_integration", Path(__file__).with_name("saved-config-integration.py"))
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)


class SavedConfigIntegrationTests(unittest.TestCase):
    def fixture(self, root):
        logs = root / "presence/old-writer"
        logs.mkdir(parents=True)
        (logs / "commands.json").write_text(json.dumps([
            {"label": "start", "command": ["msb", "start", "private-argument"], "exit": 1, "seconds": 0.1},
            {"label": "cleanup", "command": ["msb", "rm"], "exit": 0, "seconds": 0.2}]))
        (logs / "start.stderr").write_text(f"no tested sandbox launch contract for runtime 0.8.0: {root}/home")
        (logs / "start.stdout").write_text("private-stdout")
        (logs / "current-source.json").write_text("private-configuration")
        (root / "presence/report.json").write_text(json.dumps({"cases": [{
            "runtime": "current", "status": "failed", "home": str(root / "home"),
            "cleanup": {"stop": 0, "rm": 0}, "remaining_live_runs": 0}]}))

    def test_failure_and_interruption_preserve_diagnostics_before_temporary_cleanup(self):
        for failure in (subprocess.CalledProcessError(1, "fixture"), SystemExit(143)):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "output"
                roots = []

                def run(_args, root):
                    roots.append(root)
                    self.fixture(root)
                    raise failure

                argv = ["harness", "--binary", "/msb", "--agent", "/agent", "--firmware", "/firmware",
                        "--workspace", "/repo", "--archive", "/tests", "--output", str(output)]
                with mock.patch.object(sys, "argv", argv), mock.patch.object(HARNESS, "run", side_effect=run), \
                        mock.patch.object(HARNESS.evidence, "install_termination_handler"), redirect_stderr(io.StringIO()):
                    with self.assertRaises(type(failure)) as caught:
                        HARNESS.main()
                self.assertIs(caught.exception, failure)
                self.assertFalse(roots[0].exists())
                raw = (output / "diagnostics.json").read_text()
                data = json.loads(raw)
                self.assertEqual(data["status"], "failed")
                self.assertIn("no tested sandbox launch contract", data["commands"][0]["stderr"])
                self.assertEqual(data["cases"][0]["cleanup"], {"stop": "0", "rm": "0"})
                for private in (str(roots[0]), "private-argument", "private-stdout", "private-configuration"):
                    self.assertNotIn(private, raw)
                self.assertEqual([path.name for path in output.iterdir()], ["diagnostics.json"])

    def test_stderr_is_bounded_and_missing_logs_do_not_mask_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "fixture"
            self.fixture(root)
            (root / "presence/old-writer/start.stderr").write_text("x" * 70000)
            output = Path(directory) / "out"
            with redirect_stderr(io.StringIO()):
                HARNESS.save_diagnostics(root, output, Path("/repo"), RuntimeError("failed"))
            result = json.loads((output / "diagnostics.json").read_text())
            self.assertEqual(len(result["commands"][0]["stderr"]), 65536)
            self.assertTrue(result["commands"][0]["stderr_truncated"])
            self.assertNotIn("stderr", result["commands"][1])


if __name__ == "__main__":
    unittest.main()
