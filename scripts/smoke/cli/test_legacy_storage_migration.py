"""VM-free checks for fixture isolation and evidence integrity in the migration smoke."""

import json
import os
from pathlib import Path
import queue
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import legacy_storage_migration as smoke
import legacy_storage_preview as terminal


class LegacyStorageMigrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.binary = self.root / "msb"
        self.firmware = self.root / "firmware"
        self.binary.write_bytes(b"test binary")
        self.firmware.write_bytes(b"test firmware")

    def test_ambient_runtime_agent_cloud_and_profile_are_excluded(self):
        with patch.dict(os.environ, {"MSB_AGENTD_PATH": "/foreign-agent", "MSB_HOME": "/real-home",
                                     "MSB_BACKEND": "cloud", "MSB_PROFILE": "production"}):
            result = smoke.environment(self.binary, self.firmware, self.root / "home")
        self.assertEqual(result["MSB_PATH"], str(self.binary))
        self.assertEqual(result["MSB_LIBKRUNFW_PATH"], str(self.firmware))
        self.assertEqual(result["MSB_HOME"], str(self.root / "home"))
        self.assertEqual(result["MSB_BACKEND"], "local")
        self.assertNotIn("MSB_AGENTD_PATH", result)
        self.assertNotIn("MSB_PROFILE", result)

    def test_existing_output_is_never_repurposed(self):
        output = self.root / "fixture"
        output.mkdir()
        sentinel = output / "not-ours"
        sentinel.write_bytes(b"preserve")
        with self.assertRaises(FileExistsError):
            smoke.reserve_output(output)
        self.assertEqual(sentinel.read_bytes(), b"preserve")
        self.assertFalse((output / "fixture-owner.json").exists())

    def test_relocated_fixture_refuses_instead_of_rewriting_absolute_disk_paths(self):
        output = self.root / "fixture"
        smoke.reserve_output(output)
        manifest = {"schema": smoke.SCHEMA, "output": str(output.resolve()), "cases": []}
        (output / "fixtures.json").write_text(json.dumps(manifest))
        self.assertEqual(smoke.read_manifest(output), manifest)
        moved = self.root / "moved"
        output.rename(moved)
        with self.assertRaisesRegex(ValueError, "absolute location"):
            smoke.read_manifest(moved)

    def test_disk_inventory_includes_external_bytes_and_never_follows_links(self):
        sandbox = self.root / "sandbox"
        sandbox.mkdir()
        (sandbox / "upper.ext4").write_bytes(b"guest data")
        external = self.root / "external.raw"
        external.write_bytes(b"authorized external")
        expected = {"upper.ext4": smoke.digest(sandbox / "upper.ext4"),
                    "external:" + str(external): smoke.digest(external)}
        self.assertEqual(smoke.inventory(sandbox, [str(external)]), expected)
        if os.name != "nt":
            (sandbox / "trap.qcow2").symlink_to(self.root / "missing")
            (sandbox / "linked-directory").symlink_to(self.root, target_is_directory=True)
            os.mkfifo(sandbox / "pipe.raw")
            self.assertEqual(smoke.inventory(sandbox, [str(external)]), expected)
        external.write_bytes(b"changed outside sandbox")
        self.assertNotEqual(smoke.inventory(sandbox, [str(external)]), expected)

    def test_checks_require_exact_latest_values_metadata_and_each_owned_disk(self):
        script = smoke.guest_check("after-restore", ("/data", "/logs"), True)
        self.assertIn("after-restore", script)
        self.assertIn("1001:1002:640:1577934245", script)
        self.assertIn("after-restore:/data", script)
        self.assertIn("after-restore:/logs", script)
        self.assertIn("test ! -e /.msb/root-disk.json", script)
        self.assertIn("test ! -e /.msb/owned-disks", script)
        self.assertNotIn("/dev/shm", script, "a cold-start check must not imply execution restore")

    def test_timeout_and_duplicate_labels_preserve_separate_evidence(self):
        harness = smoke.Harness(self.root, self.binary, self.firmware, "test-run")
        timeout = subprocess.TimeoutExpired([str(self.binary)], 1, output=b"partial", stderr=b"waiting")
        with patch.object(smoke.subprocess, "run", side_effect=timeout):
            result = harness.run("stop", "stop", "test", required=False, timeout=1)
        self.assertEqual(result.returncode, 124)
        self.assertIn("HARNESS TIMEOUT", result.stderr)
        with patch.object(smoke.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "done", "")) as run:
            harness.run("stop", "stop", "test")
        self.assertEqual(run.call_args.kwargs["cwd"], self.root.resolve())
        self.assertEqual(run.call_args.kwargs["env"]["MSB_HOME"], str(self.root.resolve() / "home"))
        self.assertEqual((harness.log / "000-stop.stdout").read_text(), "partial")
        self.assertEqual((harness.log / "001-stop.stdout").read_text(), "done")
        commands = json.loads((harness.log / "commands.json").read_text())
        self.assertEqual([command["exit"] for command in commands], [124, 0])

    def test_refused_transplanted_fixture_never_authorizes_stop_or_cleanup(self):
        for expected in ("start", "refuse"):
            with self.subTest(expected=expected):
                output = self.root / expected
                smoke.reserve_output(output)
                manifest = {"schema": smoke.SCHEMA, "output": str(output.resolve()),
                            "producer": str(self.binary), "firmware": str(self.firmware),
                            "cases": [{"name": "transplanted", "expected": expected, "external": []}]}
                (output / "fixtures.json").write_text(json.dumps(manifest))
                args = SimpleNamespace(output=output, candidate=self.binary,
                                       candidate_firmware=self.firmware, label="verify",
                                       unrelated_live=False, storage_operations=False, execution_restore=False,
                                       legacy_writers_stopped=True)

                def execute(command, **_):
                    if command[1] == "start" or command[1:3] == ["self", "repair"]:
                        return subprocess.CompletedProcess(command, 1, "", "storage upgrade required")
                    return subprocess.CompletedProcess(command, 0, "", "")

                refused = subprocess.CompletedProcess([], 1, "", "storage upgrade required")
                with patch.object(smoke.subprocess, "run", side_effect=execute) as run, \
                        patch.object(terminal, "repair_in_terminal", return_value=refused):
                    if expected == "start":
                        with self.assertRaises(SystemExit):
                            smoke.verify(args)
                    else:
                        smoke.verify(args)
                self.assertFalse(any(call.args[0][1] in ("stop", "kill") for call in run.call_args_list))

    def test_mac_confirmation_needs_test_operator_opt_in_and_is_not_a_cli_argument(self):
        with patch.object(smoke.sys, "platform", "darwin"):
            for args in (SimpleNamespace(), SimpleNamespace(legacy_writers_stopped=False)):
                with self.assertRaisesRegex(ValueError, "maintenance"):
                    smoke.maintenance_confirmed(args)
            self.assertIs(smoke.maintenance_confirmed(SimpleNamespace(legacy_writers_stopped=True)), True)
        with patch.object(smoke.sys, "platform", "linux"):
            self.assertIs(smoke.maintenance_confirmed(SimpleNamespace()), False)

    def test_terminal_exit_after_a_prompt_can_be_waited_without_reading_eof_twice(self):
        wizard = terminal.Terminal.__new__(terminal.Terminal)
        wizard.finished = False
        wizard.pending = ""
        wizard.transcript = ""
        wizard.chunks = queue.Queue()
        wizard.chunks.put("repaired; ready to start\r\n")
        wizard.chunks.put(None)
        wizard.tty = MagicMock()
        wizard.tty.wait.return_value = 0
        self.assertIsNone(wizard.expect("enter select · esc back", allow_exit=True))
        self.assertEqual(wizard.wait(), 0)
        self.assertIn("repaired; ready to start", wizard.transcript)

    def test_terminal_repair_uses_real_confirmation_without_forwarding_removed_flags(self):
        wizard = MagicMock()
        wizard.__enter__.return_value = wizard
        wizard.expect.side_effect = ["Confirm storage repairs", "macOS maintenance confirmation", None]
        wizard.wait.return_value = 0
        wizard.transcript = "repaired; ready to start"
        with patch.object(terminal, "Terminal", return_value=wizard) as spawn:
            result = terminal.repair_in_terminal("fixture", "repair", "app", maintenance=True)
        self.assertEqual(spawn.call_args.args, ("fixture", "repair", ["self", "repair", "--sandbox", "app"]))
        self.assertEqual([call.args[0] for call in wizard.send_key.call_args_list], ["y", "y"])
        self.assertEqual(result.returncode, 0)

    def test_terminal_repair_never_guesses_maintenance_or_stop_consent(self):
        for prompt, exception in (("macOS maintenance confirmation", ValueError),
                                  ("Stop 'another-vm' gracefully?", AssertionError)):
            with self.subTest(prompt=prompt):
                wizard = MagicMock()
                wizard.__enter__.return_value = wizard
                wizard.expect.side_effect = ["Confirm storage repairs", prompt]
                with patch.object(terminal, "Terminal", return_value=wizard):
                    with self.assertRaises(exception):
                        terminal.repair_in_terminal("fixture", "repair", "app")
                replies = [call.args[0] for call in wizard.send_key.call_args_list]
                self.assertEqual(replies.count("y"), 1, "only the initial fixture repair may be approved")
                if exception is ValueError:
                    self.assertEqual(replies[-1], "\x1b")

    def test_terminal_investigation_does_not_choose_a_disk_or_confirm_maintenance(self):
        wizard = MagicMock()
        wizard.__enter__.return_value = wizard
        wizard.expect.side_effect = ["Couldn't safely repair 'app'.", "Repair results", None]
        wizard.wait.return_value = 2
        wizard.transcript = "needs investigation"
        with patch.object(terminal, "Terminal", return_value=wizard):
            result = terminal.repair_in_terminal("fixture", "investigate", "app")
        self.assertEqual(result.returncode, 2)
        self.assertEqual([call.args[0] for call in wizard.send_key.call_args_list], ["\x1b", "\x1b"])

    def test_failed_post_migration_start_never_stops_a_copied_fixture(self):
        harness = smoke.Harness(self.root, self.binary, self.firmware, "post-start-refused")
        manifest = {"cases": [{"name": "simple", "owned": [], "value": "latest"}]}
        results = [{"case": "simple", "passed": True}]
        refused = subprocess.CompletedProcess([], 1, "", "storage still has a recorded process")
        with patch.object(smoke.subprocess, "run", return_value=refused) as run:
            smoke.storage_operations(harness, manifest, results, lambda *args, **kwargs: None)
            harness.shutdown()
        self.assertEqual(harness.names, [])
        self.assertFalse(any(call.args[0][1] in ("stop", "kill") for call in run.call_args_list))

    def test_growth_target_exceeds_restored_four_gibibyte_head(self):
        disk = self.root / "head.qcow2"
        disk.write_bytes(b"QFI\xfb" + b"\0" * 20 + (4 * 1024**3).to_bytes(8, "big"))
        (self.root / "root-disk.json").write_text(json.dumps({
            "layers": [{"path": str(disk), "format": "qcow2"}]
        }))
        self.assertEqual(smoke.growth_target(self.root), "4160M")
        disk.write_bytes(b"QFI\xfb" + b"\0" * 20 + (256 * 1024**2).to_bytes(8, "big"))
        self.assertEqual(smoke.growth_target(self.root, configured_mib=4096), "4160M")
        disk.write_bytes(b"not-a-qcow-header")
        with self.assertRaisesRegex(ValueError, "invalid QCOW"):
            smoke.growth_target(self.root)

    def test_refused_mixed_runtime_never_stops_existing_fixture(self):
        output = self.root / "mixed-refusal"
        smoke.reserve_output(output)
        manifest = {"schema": smoke.SCHEMA, "output": str(output.resolve()),
                    "cases": [{"name": name, "owned": [], "value": "latest"}
                              for name in ("simple", "owned-child")]}
        (output / "fixtures.json").write_text(json.dumps(manifest))
        args = SimpleNamespace(output=output, candidate=self.binary, runtime=self.binary,
                               runtime_firmware=self.firmware, label="verify")
        refused = subprocess.CompletedProcess([], 1, "", "runtime upgrade required")
        with patch.object(smoke.subprocess, "run", return_value=refused) as run:
            with self.assertRaises(SystemExit):
                smoke.mixed_runtime(args)
        self.assertFalse(any(call.args[0][1] in ("stop", "kill") for call in run.call_args_list))

    def test_mixed_runtime_selects_and_records_the_distinct_runtime(self):
        old = self.root / "old-msb"
        old.write_bytes(b"historical runtime")
        harness = smoke.Harness(self.root, self.binary, self.firmware, "mixed", runtime=old)
        with patch.object(smoke.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            harness.run("start", "start", "test")
        self.assertEqual(run.call_args.args[0][0], str(self.binary.resolve()))
        self.assertEqual(run.call_args.kwargs["env"]["MSB_PATH"], str(old.resolve()))
        artifacts = json.loads((harness.log / "artifacts.json").read_text())
        self.assertEqual(artifacts["runtime_sha256"], smoke.digest(old))
        self.assertEqual(artifacts["binary_sha256"], smoke.digest(self.binary))


if __name__ == "__main__":
    unittest.main()
