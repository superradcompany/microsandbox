"""VM-free coverage for the CI fixture scheduler and environment isolation."""

import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import unittest.mock as mock


SPEC = importlib.util.spec_from_file_location(
    "checkpoint_integration", Path(__file__).with_name("checkpoint-integration.py"))
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)


class CheckpointIntegrationTests(unittest.TestCase):
    def test_all_fixture_tests_and_injection_modes_are_selected_exactly(self):
        self.assertEqual(len(HARNESS.CASES), 6)
        self.assertEqual([mode for _, _, mode in HARNESS.CASES if mode],
                         ["delay", "error", "cancel"])
        self.assertEqual(HARNESS.CASES[-1][1],
                         "cancelled_backing_preparation_reaps_and_reconciles")
        for binary, test, _ in HARNESS.CASES:
            command = HARNESS.test_command(Path("/archive"), Path("/workspace"), binary, test)
            self.assertEqual(command[-1], f"binary(={binary}) & test(={test})")
            self.assertIn("--run-ignored=only", command)
            self.assertEqual(command[command.index("--no-tests") + 1], "fail")

    def test_ambient_home_and_fault_injection_do_not_leak_into_fixture(self):
        with mock.patch.dict(os.environ, {"MSB_HOME": "/caller", "MSB_CONFIG_PATH": "/config",
                                         "MSB_TEST_ISOLATE_HOME": "1", "LD_PRELOAD": "/shim",
                                         "MSB_TEST_EAGER_MODE": "error"}):
            env = HARNESS.fixture_environment("/fixture", "/msb", "/agent", "/firmware")
        self.assertEqual(env["MSB_HOME"], "/fixture")
        self.assertEqual(env["MSB_PATH"], "/msb")
        for key in ("MSB_CONFIG_PATH", "MSB_TEST_ISOLATE_HOME", "LD_PRELOAD",
                    "MSB_TEST_EAGER_MODE"):
            self.assertNotIn(key, env)

    def test_case_failure_does_not_skip_remaining_modes_and_always_cleans(self):
        suite = object.__new__(HARNESS.Suite)
        suite.args = SimpleNamespace(workspace=Path("/repo"), archive=Path("/archive"), image="alpine")
        suite.output = Path("/output")
        suite.home = Path("/tmp/cbh-test/home")
        suite.env = {"MSB_PROGRESS_SNAPSHOT": "ci-progress:baseline"}
        suite.msb = mock.Mock()
        suite.cleanup = mock.Mock()

        def run(label, command, **kwargs):
            if label.endswith("-error"):
                raise HARNESS.subprocess.CalledProcessError(1, command)

        suite.run = mock.Mock(side_effect=run)
        with self.assertRaisesRegex(RuntimeError, "fixture cases failed"):
            suite.execute()
        self.assertEqual(suite.run.call_count, 7)  # shim + all six cases
        self.assertEqual(suite.cleanup.call_count, 2)  # failure cleanup and final cleanup
        cancel = suite.run.call_args_list[-2]
        self.assertEqual(cancel.kwargs["env"]["MSB_TEST_EAGER_MODE"], "cancel")
        self.assertNotIn("LD_PRELOAD", suite.run.call_args_list[-1].kwargs["env"])

    def test_timeout_reaps_private_runner_group_before_vm_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            suite = object.__new__(HARNESS.Suite)
            suite.output = Path(directory)
            suite.home = Path(directory) / "home"
            suite.env = {}
            suite.records = []
            child = mock.MagicMock()
            child.pid = 876543
            child.wait.side_effect = [HARNESS.subprocess.TimeoutExpired("test", 1), 0]
            with mock.patch.object(HARNESS.subprocess, "Popen") as popen, \
                    mock.patch.object(HARNESS.os, "killpg") as kill:
                popen.return_value.__enter__.return_value = child
                with self.assertRaises(HARNESS.subprocess.TimeoutExpired):
                    suite.run("timeout", ["test"], timeout=1)
                self.assertTrue(popen.call_args.kwargs["start_new_session"])
                kill.assert_called_once_with(child.pid, HARNESS.signal.SIGTERM)
                self.assertEqual(child.wait.call_count, 2)


if __name__ == "__main__":
    unittest.main()
