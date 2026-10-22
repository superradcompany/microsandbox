"""Ensure cross-host qualification cannot mistake partial success for compatibility."""

import importlib.util
import json
from pathlib import Path
import platform
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "historical_cross_host", Path(__file__).with_name("historical-cross-host.py"))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class CrossHostTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.native_arch = smoke.architecture(platform.machine())
        self.foreign_arch = "x86_64" if self.native_arch == "aarch64" else "aarch64"
        for label, filename in (("disk-060", "fixture.msb"), ("disk-078", "fixture.msb"),
                                ("full-078", "cp1.msb")):
            self.fixture(self.root / "transferred" / label, filename, self.foreign_arch)
        self.fixture(self.root / "native", "fixture.msb", self.native_arch, native=True)
        for filename in ("msb", "firmware", "agent"):
            (self.root / filename).write_bytes(b"binary")
        self.args = SimpleNamespace(
            transferred=self.root / "transferred", native_fixture=self.root / "native",
            candidate=self.root / "msb", firmware=self.root / "firmware", agent=self.root / "agent",
            output=self.root / "out", temp_root=self.root)
        self.mode = "safe"
        self.commands = []

    def fixture(self, root, filename, arch, native=False):
        location = root / "originals" if native else root
        location.mkdir(parents=True)
        path = location / filename
        path.write_bytes(b"historical archive")
        (root / "fixture.json").write_text(json.dumps({
            "status": "produced", "architecture": arch,
            "originals": {filename: {"bytes": path.stat().st_size,
                                      "sha256": smoke.history.digest(path)}}}))

    def runner(self, binary, env, output):
        output.mkdir(parents=True)
        home = Path(env["MSB_HOME"])

        def run(label, *args, required=True):
            self.commands.append((output.name, label, args))
            text, code = "", 0
            if label in ("load", "native-load"):
                group = "native" if label == "native-load" else "transferred"
                member = home / "snapshots" / group / "snap_test"
                member.mkdir(parents=True)
                (member / "snapshot.json").write_text("{}")
                (member.parent / "group.json").write_text('{"head":"snap_test"}')
                if label == "native-load":
                    cache = home / "cache"
                    (cache / "manifests").mkdir(parents=True)
                    (cache / "manifests/image.json").write_text('{"z":1,"a":2}')
                    (cache / "layers").mkdir()
                    (cache / "layers/test.erofs").write_bytes(b"extent")
                    (cache / "vmdk").mkdir()
                    (cache / "vmdk/image.vmdk").write_text(
                        f'RW 1 FLAT "{cache / "layers/test.erofs"}" 0\n')
            if label == "create":
                code = 1
                text = f"checkpoint architecture {self.foreign_arch} cannot restore on {self.native_arch}"
                if self.mode == "generic-error":
                    text = "archive could not be parsed"
                if self.mode == "guest-failure" and output.name.startswith("disk"):
                    code = 0
                if self.mode == "lost-ram" and output.name == "full-078":
                    code = 0
            if label == "guest" and self.mode == "guest-failure":
                code, text = 126, "Exec format error"
            if label == "guest" and self.mode == "lost-ram" and "ram-checksum" in args[-1]:
                code, text = 1, "captured RAM is missing"
            if label == "before-cleanup" and self.mode == "audit-failure":
                raise TimeoutError("initial list timed out")
            if label == "foreign-load":
                code, text = 1, "cache target already exists with different content"
                if self.mode == "partial-publication":
                    (home / "snapshots" / "foreign").mkdir()
            if label == "native-guest" and self.mode == "native-corruption":
                code, text = 1, "checksum mismatch"
            (output / (label + ".stderr")).write_text(text)
            stdout = "[]"
            if label == "before-cleanup" and self.mode == "invalid-audit":
                stdout = "{}"
            (output / (label + ".stdout")).write_text(stdout)
            if required and code:
                raise RuntimeError(text)
            return code
        return SimpleNamespace(output=output, run=run)

    def qualify(self):
        with patch.object(smoke.history, "Runner", side_effect=self.runner):
            smoke.qualify(self.args)

    def report(self):
        return json.loads((self.args.output / "report.json").read_text())

    def test_precise_refusal_and_native_guest_verification_pass(self):
        self.qualify()
        report = self.report()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(len(report["cases"]), 4)
        self.assertTrue(report["archives_unchanged"])
        self.assertTrue(all(row["catalog_empty"] for row in report["cases"]))
        self.assertIn("native-guest", [label for _, label, _ in self.commands])
        self.assertTrue(report["cases"][-1]["reordered_metadata_preserved"])
        for _, label, args in self.commands:
            if label in ("create", "native-create"):
                self.assertEqual(args[-2:], ("--pull", "never"))

    def test_unrelated_launch_error_cannot_count_as_architecture_refusal(self):
        self.mode = "generic-error"
        with self.assertRaisesRegex(RuntimeError, "qualification has failures"):
            self.qualify()
        self.assertEqual(self.report()["cases"][0]["status"], "failed")

    def test_public_architecture_diagnostic_is_specific_without_private_details(self):
        self.assertTrue(smoke.architecture_refusal(
            "snapshot integrity check failed: checkpoint architecture cannot restore on this host",
            self.foreign_arch, self.native_arch))
        self.assertFalse(smoke.architecture_refusal("snapshot integrity check failed",
                                                  self.foreign_arch, self.native_arch))

    def test_native_agent_without_working_guest_binaries_does_not_pass(self):
        self.mode = "guest-failure"
        with self.assertRaisesRegex(RuntimeError, "qualification has failures"):
            self.qualify()
        rows = self.report()["cases"]
        self.assertEqual(rows[0]["launch"], "guest-execution-failed")
        self.assertEqual(rows[0]["status"], "failed")
        self.assertEqual(rows[-1]["status"], "passed")

    def test_conflict_cannot_publish_new_group(self):
        self.mode = "partial-publication"
        with self.assertRaisesRegex(RuntimeError, "qualification has failures"):
            self.qualify()
        self.assertEqual(self.report()["cases"][-1]["error"], "rejected import published its group")

    def test_refusal_does_not_hide_damage_to_existing_guest(self):
        self.mode = "native-corruption"
        with self.assertRaisesRegex(RuntimeError, "qualification has failures"):
            self.qualify()
        self.assertEqual(self.report()["cases"][-1]["error"], "checksum mismatch")

    def test_full_memory_success_requires_captured_ram(self):
        self.mode = "lost-ram"
        with self.assertRaisesRegex(RuntimeError, "qualification has failures"):
            self.qualify()
        row = self.report()["cases"][2]
        self.assertEqual(row["status"], "failed")
        verify = next(args[-1] for kind, label, args in self.commands
                      if kind == "full-078" and label == "guest")
        self.assertIn("/dev/shm/history-generation", verify)
        self.assertIn("ram-checksum", verify)

    def test_initial_audit_failure_still_cleans_known_sandbox_and_rechecks(self):
        self.mode = "audit-failure"
        with self.assertRaisesRegex(RuntimeError, "qualification has failures"):
            self.qualify()
        for row in self.report()["cases"]:
            self.assertEqual(row["status"], "failed")
            self.assertIn("initial list timed out", row["cleanup_error"])
            self.assertTrue(row["catalog_empty"])
        for kind in ("disk-060", "disk-078", "full-078", "cache-conflict"):
            labels = [label for group, label, _ in self.commands if group == kind]
            self.assertIn("cross-host-cleanup-stop", labels)
            self.assertIn("cross-host-cleanup-rm", labels)
            self.assertIn("after-cleanup", labels)

    def test_non_list_audit_cannot_skip_cleanup(self):
        self.mode = "invalid-audit"
        with self.assertRaisesRegex(RuntimeError, "qualification has failures"):
            self.qualify()
        for row in self.report()["cases"]:
            self.assertIn("did not return a list", row["cleanup_error"])
            self.assertEqual(row["cleanup"], {"stop": 0, "rm": 0})

    def test_corrupted_transfer_is_rejected_before_cli_dispatch(self):
        (self.args.transferred / "disk-060/fixture.msb").write_bytes(b"substituted")
        with self.assertRaisesRegex(RuntimeError, "producer inventory"):
            self.qualify()
        self.assertEqual(self.commands, [])
        self.assertEqual(self.report()["status"], "failed")

    def test_vmdk_extent_outside_destination_cache_is_rejected(self):
        home = self.root / "bad-vmdk"
        (home / "cache/vmdk").mkdir(parents=True)
        foreign = self.root / "foreign.erofs"
        foreign.write_bytes(b"exists, but not in the destination cache")
        (home / "cache/vmdk/image.vmdk").write_text(f'RW 1 FLAT "{foreign}" 0\n')
        with self.assertRaisesRegex(RuntimeError, "foreign extent"):
            smoke.local_vmdk_extents(home)

    def test_reorder_preserves_oci_json_strings_and_semantic_values(self):
        home = self.root / "metadata"
        (home / "cache/manifests").mkdir(parents=True)
        path = home / "cache/manifests/image.json"
        original = {"z": {"b": 2, "a": 1}, "raw_config_json": '{"z":1,"a":2}'}
        path.write_text(json.dumps(original))
        before = path.read_bytes()
        changed = smoke.reorder_cache_metadata(home)
        self.assertNotEqual(path.read_bytes(), before)
        self.assertEqual(json.loads(path.read_text()), original)
        self.assertEqual(changed["cache/manifests/image.json"], smoke.history.digest(path))


if __name__ == "__main__":
    unittest.main()
