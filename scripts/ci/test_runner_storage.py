import importlib.util
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "runner_storage", Path(__file__).with_name("runner-storage.py"))
storage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(storage)


class RunnerStorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()

    def cache(self, relative):
        path = self.home / relative
        path.mkdir(parents=True)
        (path / "cached").write_bytes(b"data" * 2048)
        return path

    def test_only_oversized_allowlisted_caches_are_removed(self):
        uv = self.cache(".cache/uv")
        npm = self.cache(".npm/_cacache")
        logs = self.cache(".npm/_logs")
        toolchain = self.cache(".rustup")
        with patch.object(storage, "CACHE_LIMITS", {".cache/uv": 1,
                                                     ".npm/_cacache": storage.GIB}):
            storage.prune_caches(self.home)
        self.assertFalse(uv.exists())
        for kept in (npm, logs, toolchain):
            self.assertTrue((kept / "cached").exists())

    def test_missing_caches_are_allowed(self):
        storage.prune_caches(self.home)

    def test_symlinked_parent_is_rejected(self):
        target = self.home / "elsewhere"
        target.mkdir()
        (self.home / ".cache").symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlinked"):
            storage.prune_caches(self.home)

    def test_internal_symlink_is_not_followed_during_eviction(self):
        uv = self.cache(".cache/uv")
        preserved = self.cache("source")
        (uv / "link").symlink_to(preserved, target_is_directory=True)
        with patch.object(storage, "CACHE_LIMITS", {".cache/uv": 1}):
            storage.prune_caches(self.home)
        self.assertTrue((preserved / "cached").exists())

    def test_headroom_threshold(self):
        for free, accepted in [(0, False), (25 * storage.GIB - 1, False),
                               (25 * storage.GIB, True)]:
            with self.subTest(free=free), patch.object(storage.shutil, "disk_usage") as usage:
                usage.return_value.free = free
                if accepted:
                    storage.check_headroom(self.home, 25)
                else:
                    with self.assertRaisesRegex(RuntimeError, "at least 25"):
                        storage.check_headroom(self.home, 25)

    def test_finish_prunes_but_does_not_gate_completed_job(self):
        env = {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(self.home)}
        with patch.dict(os.environ, env, clear=True), patch("sys.argv", ["storage", "--finish"]), \
                patch.object(storage, "prune_caches") as prune, \
                patch.object(storage, "check_headroom") as check:
            self.assertEqual(storage.main(), 0)
            prune.assert_called_once()
            check.assert_not_called()

    def test_refuses_developer_home_outside_actions(self):
        with patch.dict(os.environ, {}, clear=True), patch("sys.argv", ["storage"]), \
                patch.object(storage, "prune_caches") as prune:
            self.assertEqual(storage.main(), 1)
            prune.assert_not_called()

    def test_startup_fails_when_headroom_is_insufficient(self):
        env = {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(self.home)}
        with patch.dict(os.environ, env, clear=True), patch("sys.argv", ["storage"]), \
                patch.object(storage, "prune_caches"), \
                patch.object(storage.shutil, "disk_usage") as usage:
            usage.return_value.free = 13 * storage.GIB
            self.assertEqual(storage.main(), 1)

    def test_invalid_threshold_does_not_clean(self):
        env = {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(self.home),
               "MSB_CI_MIN_FREE_GIB": "0"}
        with patch.dict(os.environ, env, clear=True), patch("sys.argv", ["storage"]), \
                patch.object(storage, "prune_caches") as prune:
            self.assertEqual(storage.main(), 1)
            prune.assert_not_called()

    def test_rejects_another_users_home(self):
        with patch.object(storage.os, "getuid", return_value=os.getuid() + 1):
            with self.assertRaisesRegex(ValueError, "owned"):
                storage.prune_caches(self.home)


@unittest.skipUnless(sys.platform == "linux", "cleanup wrapper requires GNU realpath/find")
class CleanupWrapperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name).resolve()
        self.home = root / "home"
        self.runner = self.home / "_work" / "project"
        self.workspace = self.runner / "project"
        self.workspace.mkdir(parents=True)
        self.artifact = self.workspace / "build" / "artifact"
        self.artifact.parent.mkdir()
        self.artifact.write_text("rebuildable")
        self.protected = self.home / "keep"
        self.protected.write_text("preserved")
        bin_dir = root / "bin"
        bin_dir.mkdir()
        # Do not scan or delete real /tmp entries during a wrapper test.
        for name in ("find", "du"):
            executable = bin_dir / name
            executable.write_text("#!/bin/sh\nexit 0\n")
            executable.chmod(0o755)
        self.env = {**os.environ, "HOME": str(self.home), "GITHUB_ACTIONS": "true",
                    "GITHUB_WORKSPACE": str(self.workspace),
                    "RUNNER_WORKSPACE": str(self.runner),
                    "PATH": f"{bin_dir}:{os.environ['PATH']}",
                    "MSB_CI_MIN_FREE_GIB": "999999"}

    def run_cleanup(self, *args):
        script = Path(__file__).with_name("clean-runner-disk.sh")
        return subprocess.run(["bash", str(script), *args], env=self.env,
                              capture_output=True, text=True, timeout=10)

    def test_low_disk_fails_before_work_but_after_reclaiming_artifacts(self):
        result = self.run_cleanup()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("GiB is required", result.stderr)
        self.assertFalse(self.artifact.exists())
        self.assertTrue(self.protected.exists())

    def test_finish_does_not_fail_on_low_disk(self):
        result = self.run_cleanup("--finish")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.artifact.exists())
        self.assertTrue(self.protected.exists())

    def test_parent_workspace_cannot_be_deleted(self):
        self.env["RUNNER_WORKSPACE"] = str(self.workspace)
        result = self.run_cleanup()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.artifact.exists())

    def test_invalid_arguments_do_not_delete_artifacts(self):
        result = self.run_cleanup("--unknown")
        self.assertEqual(result.returncode, 2)
        self.assertTrue(self.artifact.exists())


if __name__ == "__main__":
    unittest.main()
