"""Reader fixture admission must not execute ambiguous or mismatched release bytes."""

import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest.mock


SPEC = importlib.util.spec_from_file_location(
    "snapshot_compatibility", Path(__file__).with_name("snapshot-compatibility.py"))
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)


class SnapshotCompatibilityTests(unittest.TestCase):
    def test_checksum_refusal_never_marks_unverified_bytes_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "msb"
            binary.write_bytes(b"candidate bytes")
            binary.chmod(0o600)
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            valid = f"{digest}  msb-linux-x86_64\n"
            for checksums in ("", "0" * 64 + "  msb-linux-x86_64\n", valid + valid,
                              f"{digest}  msb-linux-aarch64\n"):
                with self.subTest(checksums=checksums):
                    with self.assertRaisesRegex(ValueError, "checksum"):
                        HARNESS.verify_download(binary, checksums, "msb-linux-x86_64")
                    self.assertEqual(binary.stat().st_mode & 0o777, 0o600)
            HARNESS.verify_download(binary, valid, "msb-linux-x86_64")
            self.assertEqual(binary.stat().st_mode & 0o777, 0o700)

    def test_environment_does_not_turn_historical_reader_into_candidate_runtime(self):
        with unittest.mock.patch.dict(os.environ, {"MSB_HOME": "/caller", "MSB_BACKEND": "cloud",
                                          "MSB_PATH": "/candidate", "MSB_AGENTD_PATH": "/agent",
                                          "MSB_CONFIG_PATH": "/caller.json", "LD_PRELOAD": "/shim",
                                          "DYLD_INSERT_LIBRARIES": "/shim"}):
            env = HARNESS.fixture_environment(Path("/fixture"), Path("/released"))
        self.assertEqual(env["MSB_HOME"], "/fixture/home")
        self.assertEqual(env["MSB_BACKEND"], "local")
        self.assertEqual(env["MSB_ARCHIVE_LEGACY_CLI"], "/released")
        self.assertEqual(env["MSB_TEST_LEGACY_CLI"], "/released")
        for key in ("MSB_PATH", "MSB_AGENTD_PATH", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES"):
            self.assertNotIn(key, env)

    def test_timeout_reaps_publisher_process_group(self):
        child = unittest.mock.MagicMock()
        child.pid = 876543
        child.wait.side_effect = [HARNESS.subprocess.TimeoutExpired("test", 180), 0, 0]
        with unittest.mock.patch.object(HARNESS.subprocess, "Popen") as popen, \
                unittest.mock.patch.object(HARNESS.os, "killpg") as kill:
            popen.return_value.__enter__.return_value = child
            with self.assertRaises(HARNESS.subprocess.TimeoutExpired):
                HARNESS.run_test(["test"], {}, Path("/fixture"), unittest.mock.Mock())
            self.assertTrue(popen.call_args.kwargs["start_new_session"])
            self.assertEqual(kill.call_args_list, [unittest.mock.call(child.pid, HARNESS.signal.SIGTERM),
                                                  unittest.mock.call(child.pid, HARNESS.signal.SIGKILL)])
            self.assertEqual(child.wait.call_count, 3)


if __name__ == "__main__":
    unittest.main()
