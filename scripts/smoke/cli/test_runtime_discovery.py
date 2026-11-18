"""The discovery smoke must tolerate transient Windows locks, never permanent errors."""

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch


spec = importlib.util.spec_from_file_location(
    "runtime_discovery", Path(__file__).with_name("runtime-discovery.py")
)
discovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(discovery)


def windows_error(code):
    error = PermissionError("fixture file lock")
    error.winerror = code
    return error


class RuntimeDiscoveryCleanupTests(unittest.TestCase):
    def exercise(self, side_effect, clock, platform="win32"):
        temporary = Mock(name="temporary installation")
        temporary.name = "fixture-installation"
        temporary.cleanup.side_effect = side_effect
        with patch.object(discovery.tempfile, "TemporaryDirectory", return_value=temporary), \
                patch.object(discovery.sys, "platform", platform), \
                patch.object(discovery.time, "monotonic", side_effect=clock), \
                patch.object(discovery.time, "sleep") as sleep:
            with discovery.runtime_install_directory() as directory:
                self.assertEqual(directory, "fixture-installation")
            return temporary.cleanup.call_count, sleep.call_count

    def test_retries_a_transient_windows_sharing_violation(self):
        self.assertEqual(self.exercise([windows_error(32), None], [0, 0.1]), (2, 1))

    def test_persistent_sharing_violation_still_fails_at_the_deadline(self):
        with self.assertRaises(PermissionError):
            self.exercise(windows_error(32), [0, 5])

    def test_access_denied_is_not_treated_as_a_transient_lock(self):
        with self.assertRaises(PermissionError):
            self.exercise(windows_error(5), [0])

    def test_non_windows_cleanup_errors_are_not_retried(self):
        with self.assertRaises(PermissionError):
            self.exercise(windows_error(32), [0], platform="linux")


if __name__ == "__main__":
    unittest.main()
