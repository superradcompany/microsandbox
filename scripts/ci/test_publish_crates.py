"""Regression coverage for release dependency ordering and registry visibility."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "publish_crates", Path(__file__).with_name("publish-crates.py")
)
publisher = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = publisher
spec.loader.exec_module(publisher)


class PublicationOrderTests(unittest.TestCase):
    def test_publish_handles_index_lag_without_retrying_other_failures(self):
        dependency = publisher.Package("microsandbox-image", "0.7.4", frozenset())
        consumer = publisher.Package("microsandbox-runtime", "0.7.4", frozenset({dependency.name}))
        missing = 'error: failed to select a version for the requirement `microsandbox-image = "=0.7.4"`'
        cases = [
            ("package", missing, 1, True),
            ("publish", missing, 1, True),
            ("publish", missing, 100, False),
            ("publish", "error: token rejected", 1, False),
            ("package", missing.replace("0.7.4", "0.7.5"), 1, False),
            ("package", missing.replace("microsandbox-image", "unrelated-crate"), 1, False),
        ]
        for stage, failure, failures, succeeds in cases:
            with self.subTest(stage=stage, failure=failure, failures=failures):
                attempts = 0
                uploaded = []
                now = 0

                def sleep(delay):
                    nonlocal now
                    now += delay

                def cargo(command, **kwargs):
                    nonlocal attempts
                    package = command[command.index("-p") + 1]
                    if package == consumer.name and command[1] == stage:
                        attempts += 1
                        if attempts <= failures:
                            result = subprocess.CompletedProcess(command, 101, failure)
                            if kwargs.get("check"):
                                result.check_returncode()
                            return result
                    if command[1] == "publish":
                        uploaded.append(package)
                    return subprocess.CompletedProcess(command, 0, "")

                with (
                    patch.object(publisher.subprocess, "run", side_effect=cargo),
                    patch.object(publisher, "registry_checksum", return_value=None),
                    patch.object(publisher, "wait_until_indexed"),
                    patch.object(publisher.time, "monotonic", side_effect=lambda: now),
                    patch.object(publisher.time, "sleep", side_effect=sleep),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    if succeeds:
                        publisher.publish([[dependency], [consumer]], timeout=3)
                        self.assertEqual(uploaded, [dependency.name, consumer.name])
                        self.assertEqual(attempts, 2)
                    else:
                        with self.assertRaises(subprocess.CalledProcessError):
                            publisher.publish([[dependency], [consumer]], timeout=3)
                        self.assertEqual(uploaded, [dependency.name])
                        self.assertEqual(attempts, 3 if failures == 100 else 1)

    def test_versioned_dev_dependencies_precede_consumers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["collector", "migration", "helper"]\nresolver = "3"\n'
                '[workspace.dependencies]\nmigration = { path = "migration", version = "=1.0.0" }\n'
            )
            manifests = {
                "collector": '[dev-dependencies]\nmigration.workspace = true\nhelper = { path = "../helper" }\n',
                "migration": "",
                "helper": "",
            }
            for name, dependencies in manifests.items():
                package = root / name
                (package / "src").mkdir(parents=True)
                (package / "src/lib.rs").write_text("")
                (package / "Cargo.toml").write_text(
                    f'[package]\nname = "{name}"\nversion = "1.0.0"\nedition = "2024"\n' + dependencies
                )
            metadata = json.loads(
                subprocess.check_output(
                    ["cargo", "metadata", "--no-deps", "--format-version", "1"],
                    cwd=root,
                    text=True,
                )
            )
            waves = publisher.dependency_waves(
                publisher.publication_closure(metadata, ("collector",))
            )
            self.assertEqual(
                [[p.name for p in wave] for wave in waves], [["migration"], ["collector"]]
            )


if __name__ == "__main__":
    unittest.main()
