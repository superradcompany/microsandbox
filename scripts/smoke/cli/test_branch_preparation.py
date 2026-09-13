"""VM-free checks for the branch-preparation smoke fixture and its assertions."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


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

    def test_first_descendant_must_actually_be_incremental(self):
        fixture = object.__new__(SMOKE.PreparationSmoke)
        fixture.report = {"runtime_phases": {"child": []}}
        fixture.harvest_phases = lambda _name: None
        fixture.persist = lambda: None
        for phases in ([], ['operation="local_memory_capture" incremental=false']):
            fixture.report["runtime_phases"]["child"] = phases
            with self.assertRaises(AssertionError):
                fixture.require_first_incremental("child")
        fixture.report["runtime_phases"]["child"] = [
            'operation="local_memory_capture" incremental=true']
        fixture.require_first_incremental("child")
        self.assertIn("child", fixture.report["inherited_baseline"])

    def capacity_fixture(self, states):
        fixture = object.__new__(SMOKE.PreparationSmoke)
        fixture.args = SimpleNamespace(timeout=90)
        fixture.report = {}
        fixture.persist = Mock()
        fixture.run = Mock(side_effect=[(json.dumps(state), "") for state in states])
        return fixture

    def test_wait_for_guest_memory_and_cpu_capacity(self):
        fixture = self.capacity_fixture([
            dict(memory_bytes=230 * 1048576, cpus=1),
            dict(memory_bytes=480 * 1048576, cpus=1),
            dict(memory_bytes=480 * 1048576, cpus=2)])
        with patch.object(SMOKE.time, "sleep"):
            fixture.wait_guest_capacity("source", 512, 2)
        self.assertEqual(fixture.run.call_count, 3)
        self.assertEqual(fixture.report["guest_capacity_checks"][0]["observed"]["cpus"], 2)
        compile(fixture.run.call_args.args[-1], "capacity-probe.py", "exec")

    def test_guest_capacity_timeout_is_not_a_pass(self):
        fixture = self.capacity_fixture([dict(memory_bytes=230 * 1048576, cpus=1)])
        with patch.object(SMOKE.time, "monotonic", side_effect=[0, 31]):
            with self.assertRaisesRegex(AssertionError, "did not converge"):
                fixture.wait_guest_capacity("source", 512, 2)
        fixture.persist.assert_not_called()


if __name__ == "__main__":
    unittest.main()
