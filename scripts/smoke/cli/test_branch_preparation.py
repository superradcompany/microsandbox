"""VM-free checks for the branch-preparation smoke fixture and its assertions."""

import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    "branch_preparation", Path(__file__).with_name("branch-preparation.py"))
SMOKE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SMOKE)


class PreparationChecks(unittest.TestCase):
    def state(self):
        return dict(nonce="live", generation=2, tag="child", extra_bytes=0,
                    disk_marker=dict(nonce="live", generation=2, tag="child"))

    def test_guest_scripts_compile_without_executing(self):
        compile(SMOKE.WORKER, "branch-worker.py", "exec")
        compile(SMOKE.COLD_CHECK, "cold-check.py", "exec")

    def test_matching_fresh_state(self):
        SMOKE.check_state(self.state(), "live", 2, "child")

    def test_stale_branch_revision_rejected(self):
        with self.assertRaises(AssertionError):
            SMOKE.check_state(self.state(), "live", 3, "child")

    def test_cold_boot_identity_rejected(self):
        with self.assertRaises(AssertionError):
            SMOKE.check_state(self.state(), "other", 2, "child")

    def test_disk_memory_disagreement_rejected(self):
        state = self.state()
        state["disk_marker"]["tag"] = "source"
        with self.assertRaises(AssertionError):
            SMOKE.check_state(state, "live", 2, "child")

    def test_missing_grown_memory_rejected(self):
        with self.assertRaises(AssertionError):
            SMOKE.check_state(self.state(), "live", 2, "child", 256 * 1048576)


if __name__ == "__main__":
    unittest.main()
