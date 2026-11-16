"""The evidence ledger must not manufacture successful parity."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "parity_report", Path(__file__).with_name("report.py")
)
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)


class EvidenceTests(unittest.TestCase):
    def test_resolution_cannot_hide_a_failed_candidate(self):
        with self.assertRaises(ValueError):
            report.resolved_verdict(
                {"verdict": "FIX VERIFIED", "reason": "explicit None conversion"},
                {},
                {"status": "FAIL"},
            )

    def test_fixture_resolution_requires_both_versions(self):
        resolution = {
            "verdict": "FIXTURE CORRECTED — both pass",
            "reason": "explicit TCP-capable resolver",
            "requires_old_pass": True,
        }
        with self.assertRaises(ValueError):
            report.resolved_verdict(resolution, {}, {"status": "PASS"})
        self.assertEqual(
            report.resolved_verdict(resolution, {"status": "PASS"}, {"status": "PASS"}),
            resolution["verdict"],
        )

    def test_equal_failures_are_not_parity(self):
        self.assertEqual(
            report.verdict({"status": "FAIL"}, {"status": "FAIL"}), "FAIL BOTH"
        )

    def test_missing_baseline_is_not_parity(self):
        self.assertEqual(
            report.verdict({}, {"status": "PASS"}), "NEW PASS / NO OLD PASS"
        )

    def test_incomplete_run_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            (path / "rust-new.jsonl").write_text(
                '{"type":"test","event":"started","name":"interrupted"}\n'
            )
            (path / "ruby-new.log").write_text("  test_interrupted:\n")
            self.assertEqual(
                [row["status"] for row in report.read_attempts(path)],
                ["INCOMPLETE"] * 2,
            )

    def test_harness_correction_preserves_original_failure(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            for suffix, action in [("", "fail"), ("-corrected", "pass")]:
                (path / f"go-new{suffix}.jsonl").write_text(
                    f'{{"Test":"TestCancellation","Action":"{action}"}}\n'
                )
            rows = report.read_attempts(path)
            self.assertEqual([row["status"] for row in rows], ["FAIL", "PASS"])
            self.assertEqual([row["corrected"] for row in rows], [False, True])

    def test_accepted_changed_assertions_are_not_unchanged_parity(self):
        self.assertEqual(
            report.verdict(
                {"status": "PASS"},
                {"status": "PASS"},
                "Go",
                "TestOwnsLifecycleAfterDetachOrConnect",
            ),
            "ACCEPTED CHANGE — new passes",
        )


if __name__ == "__main__":
    unittest.main()
