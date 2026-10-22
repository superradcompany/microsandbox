"""Failure-accounting checks for the installed historical-artifact qualification."""

import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("historical_installed", Path(__file__).with_name("historical-installed.py"))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class InstalledHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        fixture = self.root / "fixture"
        originals = fixture / "originals"
        originals.mkdir(parents=True)
        (originals / "fixture.msb").write_bytes(b"fixture" * 20)
        (fixture / "fixture.json").write_text(json.dumps({
            "status": "produced", "producer_version": "0.6.0",
            "originals": smoke.history.inventory(originals)}))
        for name in ("msb", "firmware"):
            (self.root / name).write_bytes(b"test binary identity")
        self.args = SimpleNamespace(fixture=fixture, candidate=self.root / "msb",
                                    firmware=self.root / "firmware", agent=None,
                                    output=self.root / "out", temp_root=self.root)
        self.commands = []

    def run_fake(self, label, *args, required=True):
        self.commands.append((label, args))
        if label == "load":
            home = next(self.root.glob("msb-hi-*"))
            member = home / "snapshots/historical-installed/snap_123"
            member.mkdir(parents=True)
            (member / "snapshot.json").write_text('{"immutable":"descriptor"}')
            (member / "group-member.json").write_text('{"name":"fixture"}')
            (member.parent / "group.json").write_text('{"head":"snap_123"}')
        return 1 if label.startswith("bad-batch-") else 0

    def test_harness_uses_all_selectors_after_removing_only_working_archives(self):
        def run(label, *args, **kwargs):
            if label.endswith("-create"):
                self.assertFalse((self.args.output / "input.msb").exists())
                self.assertTrue((self.args.fixture / "originals/fixture.msb").is_file())
                self.assertIn("--pull", args)
                self.assertIn("never", args)
            return self.run_fake(label, *args, **kwargs)
        with patch.object(smoke.history, "Runner") as runner:
            runner.return_value.run.side_effect = run
            smoke.qualify(self.args)
        report = json.loads((self.args.output / "report.json").read_text())
        self.assertEqual(report["status"], "passed")
        self.assertEqual([row["kind"] for row in report["cases"]], ["head", "id", "name"])
        self.assertTrue(report["originals_unchanged"])
        commands = dict(self.commands)
        self.assertEqual(commands["id-create"][-2:], ("--checkpoint", "snap_123"))
        self.assertEqual(commands["name-create"][-2:], ("--checkpoint", "fixture"))

    def test_unnamed_historical_member_keeps_id_and_head_without_inventing_alias(self):
        def run(label, *args, **kwargs):
            code = self.run_fake(label, *args, **kwargs)
            if label == "load":
                home = next(self.root.glob("msb-hi-*"))
                (home / "snapshots/historical-installed/snap_123/group-member.json").unlink()
            return code
        with patch.object(smoke.history, "Runner") as runner:
            runner.return_value.run.side_effect = run
            smoke.qualify(self.args)
        report = json.loads((self.args.output / "report.json").read_text())
        self.assertEqual(report["status"], "passed")
        self.assertEqual([r["kind"] for r in report["cases"]], ["head", "id"])
        self.assertTrue(report["name_selection"].startswith("unavailable:"))

    def test_unexpected_success_for_broken_batch_cannot_count_as_pass(self):
        def run(label, *args, **kwargs):
            return 0 if label.startswith("bad-batch-") else self.run_fake(label, *args, **kwargs)
        with patch.object(smoke.history, "Runner") as runner:
            runner.return_value.run.side_effect = run
            with self.assertRaisesRegex(RuntimeError, "unexpectedly succeeded"):
                smoke.qualify(self.args)
        report = json.loads((self.args.output / "report.json").read_text())
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["cases"], [])

    def test_cleanup_failure_is_reported_and_does_not_skip_other_selectors(self):
        def run(label, *args, **kwargs):
            return 1 if label == "head-cleanup-rm" else self.run_fake(label, *args, **kwargs)
        with patch.object(smoke.history, "Runner") as runner:
            runner.return_value.run.side_effect = run
            with self.assertRaisesRegex(RuntimeError, "selectors failed"):
                smoke.qualify(self.args)
        report = json.loads((self.args.output / "report.json").read_text())
        self.assertEqual(report["status"], "failed")
        self.assertEqual([r["status"] for r in report["cases"]], ["failed", "passed", "passed"])

    def test_changed_originals_cannot_count_as_success(self):
        def run(label, *args, **kwargs):
            if label == "name-persistent":
                (self.args.fixture / "originals/fixture.msb").write_bytes(b"changed")
            return self.run_fake(label, *args, **kwargs)
        with patch.object(smoke.history, "Runner") as runner:
            runner.return_value.run.side_effect = run
            with self.assertRaisesRegex(RuntimeError, "originals changed"):
                smoke.qualify(self.args)
        report = json.loads((self.args.output / "report.json").read_text())
        self.assertFalse(report["originals_unchanged"])
        self.assertEqual(report["status"], "failed")


if __name__ == "__main__":
    unittest.main()
