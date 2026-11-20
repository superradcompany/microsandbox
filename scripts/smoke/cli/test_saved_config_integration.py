"""Diagnostics survive disposable homes without publishing private records."""

from contextlib import redirect_stderr
from argparse import Namespace
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest.mock

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
                with unittest.mock.patch.object(sys, "argv", argv), unittest.mock.patch.object(HARNESS, "run", side_effect=run), \
                        unittest.mock.patch.object(HARNESS.evidence, "install_termination_handler"), redirect_stderr(io.StringIO()):
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

    def test_init_report_keeps_early_failure_and_cleanup_without_private_records(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "fixture"
            init = root / "init"
            init.mkdir(parents=True)
            output = Path(directory) / "out"
            report = {
                "status": "failed", "cases": [],
                "error": f"failed to launch {root}/home from /repo/fixture",
                "cleanup": {"origin-auto": {"stop": 1, "rm": 1}},
                "cleanup_error": f"could not remove {Path.home()}/private-home",
                "remaining_sandboxes": 1, "remaining_live_runs": 1, "surviving_pids": [123],
                "home": str(root / "home"), "host": "private-host-details",
                "binary": "private-binary-digest", "source": "private-configuration",
            }
            (init / "report.json").write_text(json.dumps(report))
            HARNESS.save_diagnostics(root, output, Path("/repo"), RuntimeError("init failed"))
            raw = (output / "diagnostics.json").read_text()
            result = json.loads(raw)
            self.assertEqual(result["cases"], [])
            saved = result["reports"][0]
            self.assertEqual(saved["suite"], "init")
            self.assertEqual(saved["status"], "failed")
            self.assertEqual(saved["error"], "failed to launch <fixture>/home from <workspace>/fixture")
            self.assertEqual(saved["cleanup"], {"origin-auto": "{'stop': 1, 'rm': 1}"})
            self.assertEqual(saved["cleanup_error"], "could not remove <host-home>/private-home")
            self.assertEqual(saved["remaining_sandboxes"], 1)
            self.assertEqual(saved["remaining_live_runs"], 1)
            self.assertEqual(saved["surviving_pids"], [123])
            for private in (str(root), str(Path.home()), "/repo", "private-host-details",
                            "private-binary-digest", "private-configuration"):
                self.assertNotIn(private, raw)

    def test_case_cleanup_failure_is_retained_and_redacted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "fixture"
            self.fixture(root)
            report = root / "presence/report.json"
            source = json.loads(report.read_text())
            source["cases"][0]["cleanup_error"] = f"cleanup failed at {root}/home"
            report.write_text(json.dumps(source))
            output = Path(directory) / "out"
            with redirect_stderr(io.StringIO()):
                HARNESS.save_diagnostics(root, output, Path("/repo"), RuntimeError("failed"))
            result = json.loads((output / "diagnostics.json").read_text())
            self.assertEqual(result["cases"][0]["cleanup_error"], "cleanup failed at <fixture>/home")

    def test_archive_is_extracted_once_and_reused_by_the_matrix_and_consumers(self):
        args = Namespace(binary=Path("/candidate"), agent=Path("/agent"), firmware=Path("/firmware"),
                         workspace=Path("/repo"), archive=Path("/tests.tar.zst"), test_binary=None,
                         previous_writer=Path("/old"), image=Path("/image.tar"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "tests/target"
            with unittest.mock.patch.object(HARNESS.subprocess, "run") as run, \
                    unittest.mock.patch.object(HARNESS, "launch_qualification") as matrix, \
                    unittest.mock.patch.object(HARNESS, "command_receipts"):
                HARNESS.run(args, root)
            self.assertTrue(target.parent.is_dir())
            matrix.assert_called_once_with(args, root, args.image, target)
            commands = [call.args[0] for call in run.call_args_list]
            extracts = [command for command in commands if "--archive-file" in command]
            self.assertEqual(len(extracts), 1)
            self.assertEqual(extracts[0][:3], ["cargo-nextest", "nextest", "list"])
            self.assertEqual(extracts[0][extracts[0].index("--extract-to") + 1], target.parent)
            consumers = [command for command in commands if command[:3] == ["cargo-nextest", "nextest", "run"]]
            self.assertEqual(len(consumers), len(HARNESS.TESTS))
            for command, test in zip(consumers, HARNESS.TESTS):
                self.assertNotIn("--archive-file", command)
                self.assertEqual(command[command.index("--cargo-metadata") + 1], target / "nextest/cargo-metadata.json")
                self.assertEqual(command[command.index("--binaries-metadata") + 1], target / "nextest/binaries-metadata.json")
                self.assertEqual(command[command.index("--target-dir-remap") + 1], target)
                self.assertEqual(command[command.index("--no-tests") + 1], "fail")
                self.assertEqual(command[-1], f"test(={test})")

    def test_failed_archive_extraction_stops_before_any_runtime_fixture(self):
        args = Namespace(test_binary=None, archive=Path("/missing"), workspace=Path("/repo"))
        with tempfile.TemporaryDirectory() as directory, \
                unittest.mock.patch.object(HARNESS.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "extract")), \
                unittest.mock.patch.object(HARNESS, "launch_qualification") as matrix:
            with self.assertRaises(subprocess.CalledProcessError):
                HARNESS.run(args, Path(directory))
        matrix.assert_not_called()

    def test_direct_test_binary_does_not_extract_an_archive(self):
        with unittest.mock.patch.object(HARNESS.subprocess, "run") as run:
            self.assertIsNone(HARNESS.extract_tests(Namespace(test_binary=Path("/tests")), Path("/fixture")))
        run.assert_not_called()

    def test_security_capability_changes_do_not_silently_change_matrix_expectations(self):
        args = Namespace(binary=Path("/candidate"))
        for label, advertised in (("candidate", False), ("0.7.12", False), ("0.7.11", True)):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with unittest.mock.patch.object(HARNESS.subprocess, "check_output", return_value=json.dumps({
                        "protocols": [2], "protected_guest_state": advertised})), \
                        unittest.mock.patch.object(HARNESS.evidence, "Runner") as runner:
                    with self.assertRaisesRegex(ValueError, "unexpected protected-storage capability"):
                        HARNESS.qualify_launch_runtime(args, root, root / "image", label,
                                                       root / "msb", root / "firmware", root / "agent")
                    runner.assert_not_called()

    def test_one_failed_release_does_not_skip_other_pairings_or_hide_failure(self):
        args = Namespace(binary=Path("/candidate"), firmware=Path("/firmware"), agent=Path("/agent"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with unittest.mock.patch.object(HARNESS, "LAUNCH_RELEASES", ("0.7.12", "0.7.13")), \
                    unittest.mock.patch.object(HARNESS, "released_launch_runtime", side_effect=[
                        RuntimeError("checksum mismatch"), (Path("/old"), Path("/old-fw"), Path("/old-agent"))]), \
                    unittest.mock.patch.object(HARNESS, "qualify_launch_runtime") as qualify, redirect_stderr(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError, "runtime qualification failed: 0.7.12"):
                    HARNESS.launch_qualification(args, root, root / "image")
            self.assertEqual([call.args[3] for call in qualify.call_args_list], ["0.7.13", "candidate"])
            report = json.loads((root / "launch-0.7.12-logs/report.json").read_text())
            self.assertEqual(report["cases"][0]["status"], "failed")
            self.assertEqual(report["cases"][0]["error"], "checksum mismatch")

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
