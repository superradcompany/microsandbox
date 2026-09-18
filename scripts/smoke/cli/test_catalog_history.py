#!/usr/bin/env python3
"""VM-free regression tests for historical catalog CI provisioning."""

import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest
import unittest.mock


SPEC = importlib.util.spec_from_file_location("catalog_history", Path(__file__).with_name("catalog-history.py"))
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)


class CatalogHistoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.archive = self.root / HARNESS.BUNDLE
        self.destination = self.root / "release"
        self.destination.mkdir()

    def bundle(self, symlink=False):
        with tarfile.open(self.archive, "w:gz") as archive:
            for name in ("msb", HARNESS.FIRMWARE):
                member = tarfile.TarInfo(name)
                if name == "msb" and symlink:
                    member.type = tarfile.SYMTYPE
                    member.linkname = "/outside"
                    archive.addfile(member)
                else:
                    member.size = 4
                    archive.addfile(member, io.BytesIO(b"data"))
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        return f"{digest}  {HARNESS.BUNDLE}\n"

    def test_verified_bundle_extracts_only_expected_regular_files(self):
        HARNESS.unpack_verified_release(self.archive, self.bundle(), self.destination)
        self.assertEqual((self.destination / "msb").read_bytes(), b"data")
        self.assertTrue(os.access(self.destination / "msb", os.X_OK))
        self.assertEqual(sorted(p.name for p in self.destination.iterdir()), sorted(["msb", HARNESS.FIRMWARE]))

    def test_bad_missing_and_duplicate_checksums_fail_before_extraction(self):
        checksums = self.bundle()
        for invalid in ("", "0" * 64 + f"  {HARNESS.BUNDLE}\n", checksums * 2):
            with self.subTest(checksums=invalid), self.assertRaises(ValueError):
                HARNESS.unpack_verified_release(self.archive, invalid, self.destination)
            self.assertEqual(list(self.destination.iterdir()), [])

    def test_release_symlink_is_rejected(self):
        checksums = self.bundle(symlink=True)
        with self.assertRaisesRegex(ValueError, "regular release file"):
            HARNESS.unpack_verified_release(self.archive, checksums, self.destination)

    def test_environment_does_not_borrow_candidate_or_cloud_configuration(self):
        with unittest.mock.patch.dict(os.environ, {
            "MSB_AGENTD_PATH": "/candidate/agentd", "MSB_API_KEY": "not-a-real-key",
            "MSB_BACKEND": "cloud", "MSB_CONFIG_PATH": "/caller/config.json",
            "MSB_HOME": "/caller/home", "LD_LIBRARY_PATH": "/candidate/lib",
        }):
            env = HARNESS.fixture_environment(self.root, self.destination)
        self.assertNotIn("MSB_AGENTD_PATH", env)
        self.assertNotIn("MSB_API_KEY", env)
        self.assertEqual(env["MSB_BACKEND"], "local")
        self.assertEqual(env["MSB_HOME"], env["MSB_CATALOG_TEST_HOME"])
        self.assertEqual(env["MSB_PATH"], str(self.destination / "msb"))
        self.assertEqual(env["MSB_LIBKRUNFW_PATH"], str(self.destination / HARNESS.FIRMWARE))
        self.assertEqual(env["LD_LIBRARY_PATH"], str(self.destination))
        self.assertEqual(env["MSB_CONFIG_PATH"], str(self.root / "config.json"))

    def test_cleanup_stops_only_active_sandboxes_then_removes_all_fixture_records(self):
        inventory = [{"name": "a", "status": "Running"}, {"name": "b", "status": "Stopped"}]
        replies = [json.dumps(inventory), "", "", "", "[]"]
        with unittest.mock.patch.object(HARNESS.subprocess, "run") as run:
            run.side_effect = [subprocess.CompletedProcess([], 0, reply, "") for reply in replies]
            HARNESS.cleanup_catalog(HARNESS.fixture_environment(self.root, self.destination), self.root, io.StringIO())
        self.assertEqual([call.args[0][1:] for call in run.call_args_list], [
            ["list", "--format", "json"], ["stop", "a"], ["rm", "a"], ["rm", "b"], ["list", "--format", "json"],
        ])
        for call in run.call_args_list:
            self.assertEqual(call.kwargs["env"]["MSB_HOME"], str(self.root / "home"))

    def test_cleanup_failure_does_not_skip_other_sandboxes(self):
        inventory = [{"name": "a", "status": "Running"}, {"name": "b", "status": "Stopped"}]
        ok = subprocess.CompletedProcess([], 0, "", "")
        with unittest.mock.patch.object(HARNESS.subprocess, "run") as run:
            run.side_effect = [subprocess.CompletedProcess([], 0, json.dumps(inventory), ""),
                               subprocess.CalledProcessError(1, ["stop", "a"]), ok,
                               subprocess.CompletedProcess([], 0, "[]", "")]
            with self.assertRaisesRegex(RuntimeError, "cleanup failed"):
                HARNESS.cleanup_catalog(HARNESS.fixture_environment(self.root, self.destination), self.root, io.StringIO())
        self.assertIn(["rm", "b"], [call.args[0][1:] for call in run.call_args_list])

    def test_failed_candidate_cleanup_retries_candidate_but_still_fails(self):
        env = HARNESS.fixture_environment(self.root, self.destination)
        candidate = self.root / "candidate-msb"
        inventory = [{"name": "orphan", "status": "Running"}]
        replies = [subprocess.CompletedProcess([], 1, "", "catalog too new\n"),
                   subprocess.CompletedProcess([], 0, json.dumps(inventory), ""),
                   subprocess.CompletedProcess([], 0, "stopped\n", ""),
                   subprocess.CompletedProcess([], 0, "removed\n", ""),
                   subprocess.CompletedProcess([], 0, "[]", "")]
        log = io.StringIO()
        with unittest.mock.patch.object(HARNESS.subprocess, "run", side_effect=replies) as run:
            with self.assertRaises(subprocess.CalledProcessError) as raised:
                HARNESS.cleanup(env, self.root, log, candidate)
        self.assertIn("recovered", raised.exception.__notes__[0])
        self.assertIn("catalog too new", log.getvalue())
        self.assertEqual(run.call_args_list[0].args[0][0], str(candidate))
        self.assertEqual([call.args[0][1:] for call in run.call_args_list[1:]], [
            ["list", "--format", "json"], ["stop", "orphan"], ["rm", "orphan"], ["list", "--format", "json"],
        ])
        for call in run.call_args_list[1:]:
            self.assertEqual(call.args[0][0], str(candidate))
            self.assertEqual(call.kwargs["env"], dict(env, MSB_PATH=str(candidate)))
            self.assertEqual(call.kwargs["cwd"], self.root)
        self.assertEqual(env["MSB_PATH"], str(self.destination / "msb"))

    def test_malformed_candidate_inventory_retries_candidate_cleanup(self):
        log = io.StringIO()
        replies = [subprocess.CompletedProcess([], 0, "not JSON", ""),
                   subprocess.CompletedProcess([], 0, "[]", ""),
                   subprocess.CompletedProcess([], 0, "[]", "")]
        with unittest.mock.patch.object(HARNESS.subprocess, "run", side_effect=replies) as run:
            with self.assertRaises(json.JSONDecodeError):
                HARNESS.cleanup(HARNESS.fixture_environment(self.root, self.destination),
                                self.root, log, self.root / "candidate-msb")
        self.assertEqual(run.call_count, 3)
        self.assertIn("Retrying cleanup", log.getvalue())

    def test_failed_fallback_preserves_original_cleanup_error_and_logs_both(self):
        candidate_error = subprocess.CalledProcessError(1, ["candidate-msb", "list"])
        retry_error = RuntimeError("candidate cannot read catalog either")
        historical_error = RuntimeError("old reader rejects upgraded catalog")
        log = io.StringIO()
        with unittest.mock.patch.object(HARNESS, "cleanup_catalog", side_effect=[candidate_error, retry_error, historical_error]):
            with self.assertRaises(subprocess.CalledProcessError) as raised:
                HARNESS.cleanup(HARNESS.fixture_environment(self.root, self.destination),
                                self.root, log, self.root / "candidate-msb")
        self.assertIs(raised.exception, candidate_error)
        self.assertIn("candidate cannot read", raised.exception.__notes__[0])
        self.assertIn("old reader rejects", log.getvalue())
        self.assertIn("candidate cannot read", log.getvalue())

    def test_partial_cleanup_retries_fresh_inventory_with_current_reader(self):
        candidate = self.root / "candidate-msb"
        env = HARNESS.fixture_environment(self.root, self.destination)
        inventory = [{"name": "removed", "status": "Stopped"},
                     {"name": "remaining", "status": "Running"}]
        remaining = inventory[1:]
        replies = [json.dumps(inventory), "", None, json.dumps(remaining),
                   json.dumps(remaining), "", "", "[]"]
        results = [subprocess.CompletedProcess([], 0, reply, "") if reply is not None
                   else subprocess.CalledProcessError(1, ["stop", "remaining"])
                   for reply in replies]
        with unittest.mock.patch.object(HARNESS.subprocess, "run", side_effect=results) as run:
            with self.assertRaisesRegex(RuntimeError, "cleanup failed"):
                HARNESS.cleanup(env, self.root, io.StringIO(), candidate)
        self.assertEqual([call.args[0][1:] for call in run.call_args_list], [
            ["list", "--format", "json"], ["rm", "removed"], ["stop", "remaining"],
            ["list", "--format", "json"], ["list", "--format", "json"],
            ["stop", "remaining"], ["rm", "remaining"], ["list", "--format", "json"],
        ])
        self.assertTrue(all(call.args[0][0] == str(candidate) for call in run.call_args_list))

    def test_pre_upgrade_fallback_runs_only_after_candidate_retry_fails(self):
        original = RuntimeError("candidate unavailable")
        env = HARNESS.fixture_environment(self.root, self.destination)
        candidate = self.root / "candidate-msb"
        with unittest.mock.patch.object(HARNESS, "cleanup_catalog", side_effect=[original, OSError("retry unavailable"), None]) as cleanup:
            with self.assertRaises(RuntimeError) as raised:
                HARNESS.cleanup(env, self.root, io.StringIO(), candidate)
        self.assertIs(raised.exception, original)
        self.assertEqual([call.args[0]["MSB_PATH"] for call in cleanup.call_args_list],
                         [str(candidate), str(candidate), env["MSB_PATH"]])

    def test_cleanup_timeout_retains_partial_diagnostics(self):
        error = subprocess.TimeoutExpired(["old-msb", "list"], 30,
                                          output=b"partial stdout\n", stderr=b"partial stderr\n")
        log = io.StringIO()
        with unittest.mock.patch.object(HARNESS.subprocess, "run", side_effect=error):
            with self.assertRaises(subprocess.TimeoutExpired):
                HARNESS.cleanup_catalog(HARNESS.fixture_environment(self.root, self.destination), self.root, log)
        self.assertIn("partial stdout", log.getvalue())
        self.assertIn("partial stderr", log.getvalue())

    def test_successful_candidate_cleanup_does_not_use_historical_reader(self):
        with unittest.mock.patch.object(HARNESS, "cleanup_catalog") as cleanup:
            env = HARNESS.fixture_environment(self.root, self.destination)
            log = io.StringIO()
            HARNESS.cleanup(env, self.root, log, self.root / "candidate-msb")
        cleanup.assert_called_once_with(dict(env, MSB_PATH=str(self.root / "candidate-msb")), self.root, log)

    def execute_with_failures(self, test_failure, cleanup_failure):
        checksums = self.bundle()
        fixture = self.root / "fixture"
        fixture.mkdir()
        args = argparse.Namespace(archive=self.archive, workspace=self.root,
                                  output=self.root / "output", cleanup_binary=self.archive)
        with unittest.mock.patch.object(HARNESS.tempfile, "mkdtemp", return_value=str(fixture)), \
                unittest.mock.patch.object(HARNESS.urllib.request, "urlopen", side_effect=[io.BytesIO(self.archive.read_bytes()), io.BytesIO(checksums.encode())]), \
                unittest.mock.patch.object(HARNESS.subprocess, "run", side_effect=test_failure), \
                unittest.mock.patch.object(HARNESS, "cleanup", side_effect=cleanup_failure) as cleanup, \
                unittest.mock.patch.object(HARNESS.sys, "stderr", new_callable=io.StringIO) as stderr:
            with self.assertRaises(BaseException) as raised:
                HARNESS.execute(args)
        cleanup.assert_called_once()
        self.assertIn("cleanup broke", (args.output / "cleanup.log").read_text())
        if test_failure is not None:
            self.assertIn("cleanup broke", stderr.getvalue())
            self.assertIn("cleanup broke", raised.exception.__notes__[0])
        return raised.exception

    def test_test_failure_is_not_replaced_by_cleanup_failure(self):
        error = subprocess.CalledProcessError(100, ["nextest"])
        self.assertIs(self.execute_with_failures(error, RuntimeError("cleanup broke")), error)

    def test_interrupted_test_is_not_replaced_by_cleanup_failure(self):
        error = KeyboardInterrupt("interrupted test")
        self.assertIs(self.execute_with_failures(error, RuntimeError("cleanup broke")), error)

    def test_timeout_is_not_replaced_by_cleanup_failure(self):
        error = subprocess.CalledProcessError(124, ["timeout", "nextest"])
        self.assertIs(self.execute_with_failures(error, RuntimeError("cleanup broke")), error)

    def test_cleanup_failure_after_success_still_fails(self):
        error = RuntimeError("cleanup broke")
        self.assertIs(self.execute_with_failures(None, error), error)

    def test_failed_fixture_still_cleans_up_and_remains_a_failure(self):
        checksums = self.bundle()
        fixture = self.root / "fixture"
        fixture.mkdir()
        args = argparse.Namespace(archive=self.archive, workspace=self.root, output=self.root / "output", cleanup_binary=self.archive)
        with unittest.mock.patch.object(HARNESS.tempfile, "mkdtemp", return_value=str(fixture)), \
                unittest.mock.patch.object(HARNESS.urllib.request, "urlopen", side_effect=[io.BytesIO(self.archive.read_bytes()), io.BytesIO(checksums.encode())]), \
                unittest.mock.patch.object(HARNESS.subprocess, "run", side_effect=subprocess.CalledProcessError(100, ["nextest"])) as run, \
                unittest.mock.patch.object(HARNESS, "cleanup") as cleanup:
            with self.assertRaises(subprocess.CalledProcessError):
                HARNESS.execute(args)
        cleanup.assert_called_once()
        command = run.call_args.args[0]
        self.assertEqual(command[:4], ["timeout", "--kill-after=10s", "180s", "cargo-nextest"])
        self.assertIn(f"test(={HARNESS.TEST})", command)
        self.assertEqual(command[-2:], ["--test-threads", "1"])

    def test_workflow_excludes_exact_fixture_and_runs_dedicated_step(self):
        workflow = (Path(__file__).resolve().parents[3] / ".github/workflows/check.yml").read_text()
        exclusion = f"test(/^{HARNESS.TEST}$/)"
        self.assertEqual(workflow.count(exclusion), 1)
        self.assertIsNotNone(re.fullmatch(HARNESS.TEST, HARNESS.TEST))
        self.assertIsNone(re.fullmatch(HARNESS.TEST, "backend::local::catalog::tests::historical_config_survives_catalog_upgrade"))
        self.assertIn("python3 scripts/smoke/cli/catalog-history.py", workflow)
        self.assertIn("name: Historical catalog compatibility (v0.6.18)", workflow)
        self.assertIn("--cleanup-binary build/msb", workflow)


if __name__ == "__main__":
    unittest.main()
