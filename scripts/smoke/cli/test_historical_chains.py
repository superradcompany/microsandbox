"""Reject fixtures that do not exercise the claimed historical dependency mode."""

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("historical_chains", Path(__file__).with_name("historical-chains.py"))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class HistoricalChainTests(unittest.TestCase):
    def inventory(self, *kinds):
        return {"completeness": "dependent", "entries": [{"kind": kind, "included": False, "path": "objects/ram"} for kind in kinds]}

    def test_file_archive_uses_historical_file_payload_inventory_kind(self):
        smoke.require_dependent(self.inventory("file-payload"), full=False)
        with self.assertRaisesRegex(RuntimeError, "disk layer"):
            smoke.require_dependent(self.inventory("checkpoint-object"), full=False)

    def test_full_dependency_must_exercise_both_disk_and_memory_omission(self):
        smoke.require_dependent(self.inventory("checkpoint-disk-layer", "checkpoint-object"), full=True)
        with self.assertRaisesRegex(RuntimeError, "RAM objects"):
            smoke.require_dependent(self.inventory("checkpoint-disk-layer"), full=True)
        with self.assertRaisesRegex(RuntimeError, "disk layer"):
            smoke.require_dependent(self.inventory("checkpoint-object"), full=True)

    def test_chain_selects_the_member_with_actual_ram_dependencies(self):
        members = [{"inventory": self.inventory()},
                   {"inventory": self.inventory("checkpoint-disk-layer", "checkpoint-object")},
                   {"inventory": self.inventory("checkpoint-disk-layer")}]
        for i, member in enumerate(members):
            member["id"] = "snap" + str(i)
        with patch.object(smoke, "ram_object_ids", return_value={"sha256:ram"}):
            self.assertEqual(smoke.memory_dependency_member(members, Path("members")), 1)
            with self.assertRaisesRegex(RuntimeError, "no omitted RAM"):
                smoke.memory_dependency_member([members[0], members[2]], Path("members"))
        with patch.object(smoke, "ram_object_ids", return_value={"sha256:different-ram"}):
            with self.assertRaisesRegex(RuntimeError, "no omitted RAM"):
                smoke.memory_dependency_member(members, Path("members"))

    def test_standalone_or_included_payloads_cannot_count_as_dependency_coverage(self):
        inv = self.inventory("file-payload")
        inv["completeness"] = "boot-complete"
        with self.assertRaisesRegex(RuntimeError, "dependent archive"):
            smoke.require_dependent(inv, full=False)
        inv["completeness"] = "dependent"
        inv["entries"][0]["included"] = True
        with self.assertRaisesRegex(RuntimeError, "disk layer"):
            smoke.require_dependent(inv, full=False)


if __name__ == "__main__":
    unittest.main()
