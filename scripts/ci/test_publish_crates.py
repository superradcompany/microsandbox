"""Regression coverage for Cargo's versioned development dependencies."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "publish_crates", Path(__file__).with_name("publish-crates.py")
)
publisher = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = publisher
spec.loader.exec_module(publisher)


class PublicationOrderTests(unittest.TestCase):
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
