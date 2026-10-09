"""VM-free checks that managed-job CI cannot silently omit tests or reuse failed VMs."""

import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
import unittest.mock


SPEC = importlib.util.spec_from_file_location(
    "managed_job_integration", Path(__file__).with_name("managed-job-integration.py"))
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)


class ManagedJobIntegrationTests(unittest.TestCase):
    def test_every_rust_vm_test_has_a_provisioned_ci_case(self):
        root = Path(__file__).resolve().parents[3]
        source = (root / "sdk/rust/tests/jobs.rs").read_text()
        tests = re.findall(r"#\[tokio::test\]\s*(?:#\[[^\]]*\]\s*)*async fn (\w+)", source)
        self.assertTrue(tests)
        self.assertCountEqual(HARNESS.CASES, tests)
        for test in tests:
            command = HARNESS.test_command(Path("/archive"), Path("/workspace"), test)
            self.assertIn("--run-ignored=only", command)
            self.assertEqual(command[command.index("--no-tests") + 1], "fail")
            self.assertEqual(command[-1], f"binary(=jobs) & test(={test})")

    def test_candidate_artifacts_and_home_replace_ambient_settings(self):
        with unittest.mock.patch.dict(os.environ, {
            "MSB_HOME": "/caller", "MSB_BACKEND": "cloud", "MSB_JOB_TEST_RESTART": "1",
            "MSB_TEST_ISOLATE_HOME": "1", "MSB_CONFIG_PATH": "/caller/config",
            "MSB_TEST_EAGER_MODE": "error", "LD_PRELOAD": "/shim",
        }):
            env = HARNESS.fixture_environment(Path("/fixture"), Path("/msb"),
                                               Path("/agent"), Path("/libs/firmware"))
        self.assertEqual(env["MSB_HOME"], "/fixture")
        self.assertEqual(env["MSB_PATH"], "/msb")
        self.assertEqual(env["LD_LIBRARY_PATH"], "/libs")
        self.assertEqual(env["MSB_BACKEND"], "local")
        for key in ("MSB_JOB_TEST_RESTART", "MSB_TEST_ISOLATE_HOME", "MSB_CONFIG_PATH",
                    "MSB_TEST_EAGER_MODE", "LD_PRELOAD"):
            self.assertNotIn(key, env)

    def suite(self):
        suite = object.__new__(HARNESS.Suite)
        suite.args = SimpleNamespace(workspace=Path("/repo"), archive=Path("/archive"),
                                     binary=Path("/msb"), image="alpine", python=None, python_only=False)
        suite.env = {"MSB_HOME": "/private-fixture"}
        suite.cleanup = unittest.mock.Mock()
        return suite

    def test_failure_is_reported_but_remaining_cases_get_fresh_fixtures(self):
        suite = self.suite()

        def run(label, command, **kwargs):
            if label == HARNESS.CASES[0]:
                raise subprocess.CalledProcessError(1, command)

        suite.run = unittest.mock.Mock(side_effect=run)
        with self.assertRaisesRegex(RuntimeError, "managed-job fixture cases failed"):
            suite.execute()
        cases = [call for call in suite.run.call_args_list
                 if not call.args[0].endswith("-create")]
        self.assertEqual(len(cases), len(HARNESS.CASES) + 2)
        self.assertEqual(len({call.kwargs["env"]["MSB_JOB_TEST_SANDBOX"] for call in cases}), len(cases))
        self.assertEqual(suite.cleanup.call_count, len(cases) + 1)
        restart_cases = {call.args[0] for call in cases
                         if call.kwargs["env"].get("MSB_JOB_TEST_RESTART") == "1"}
        self.assertEqual(restart_cases, {"managed_job_zz_saturated_shutdown", "managed-jobs"})

    def test_cleanup_failure_stops_provisioning(self):
        suite = self.suite()
        suite.run = unittest.mock.Mock()
        suite.cleanup.side_effect = RuntimeError("cleanup failed")
        with self.assertRaisesRegex(RuntimeError, "cleanup failed"):
            suite.execute()
        self.assertEqual(suite.run.call_count, 2)

    def test_python_regression_gets_an_explicit_disposable_sandbox(self):
        suite = self.suite()
        suite.args.python = Path("/venv/bin/python")
        suite.args.python_only = True
        suite.run = unittest.mock.Mock()
        suite.execute()
        create, test = suite.run.call_args_list
        self.assertEqual(create.args[0], "python-managed-jobs-create")
        self.assertEqual(test.args[1][0], "/venv/bin/python")
        self.assertIn("/repo/sdk/python/tests/test_jobs_integration.py", test.args[1])
        self.assertEqual(test.kwargs["env"]["MSB_JOB_TEST_SANDBOX"], "ci-jobs-0")
        self.assertEqual(test.kwargs["env"]["MSB_HOME"], "/private-fixture")
        self.assertEqual(suite.cleanup.call_count, 2)

    def test_timeout_reaps_runner_and_records_failure_for_ci_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            suite = self.suite()
            suite.root = suite.output = Path(directory)
            suite.records = []
            child = unittest.mock.MagicMock()
            child.pid = 876543
            child.wait.side_effect = [subprocess.TimeoutExpired("test", 1), 0]
            with unittest.mock.patch.object(HARNESS.subprocess, "Popen") as popen, \
                    unittest.mock.patch.object(HARNESS.os, "killpg") as kill:
                popen.return_value.__enter__.return_value = child
                with self.assertRaises(subprocess.TimeoutExpired):
                    suite.run("timeout", ["test"], timeout=1)
                self.assertTrue(popen.call_args.kwargs["start_new_session"])
                kill.assert_called_once_with(child.pid, HARNESS.signal.SIGTERM)
            record = json.loads((suite.output / "results.json").read_text())["cases"][0]
            self.assertIn("timed out", record["error"])


if __name__ == "__main__":
    unittest.main()
