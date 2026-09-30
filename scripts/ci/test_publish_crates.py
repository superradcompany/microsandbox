"""Regression coverage for release dependency ordering and registry visibility."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
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
        missing_package = 'error: no matching package named `microsandbox-image` found'
        cases = [
            ("package", missing, 1, True),
            ("publish", missing, 1, True),
            ("package", missing_package, 1, True),
            ("publish", missing_package, 1, True),
            ("publish", missing, 100, False),
            ("publish", missing_package, 100, False),
            ("publish", "error: token rejected", 1, False),
            ("package", missing.replace("0.7.4", "0.7.5"), 1, False),
            ("package", missing.replace("microsandbox-image", "unrelated-crate"), 1, False),
            ("package", missing_package.replace("microsandbox-image", "unrelated-crate"), 1, False),
        ]
        for stage, failure, failures, succeeds in cases:
            with (
                self.subTest(stage=stage, failure=failure, failures=failures),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                state_path = root / "state.json"
                state_path.write_text(json.dumps({"attempts": 0, "uploaded": []}))
                cargo = root / "cargo"
                cargo.write_text(f"#!{sys.executable}\n" + textwrap.dedent(f"""\
                    import json
                    from pathlib import Path
                    import sys

                    state_path = Path({str(state_path)!r})
                    state = json.loads(state_path.read_text())
                    package = sys.argv[sys.argv.index('-p') + 1]
                    failed = False
                    if package == {consumer.name!r} and sys.argv[1] == {stage!r}:
                        state['attempts'] += 1
                        failed = state['attempts'] <= {failures}
                    if sys.argv[1] == 'publish' and not failed:
                        state['uploaded'].append(package)
                    state_path.write_text(json.dumps(state))
                    if failed:
                        print({failure!r}, file=sys.stderr)
                        sys.exit(101)
                    """))
                cargo.chmod(0o755)
                now = 0

                def sleep(delay):
                    nonlocal now
                    now += delay

                with (
                    patch.dict(os.environ, {"PATH": str(root) + os.pathsep + os.environ["PATH"]}),
                    patch.object(publisher, "registry_checksum", return_value=None),
                    patch.object(publisher, "wait_until_indexed"),
                    patch.object(publisher.time, "monotonic", side_effect=lambda: now),
                    patch.object(publisher.time, "sleep", side_effect=sleep),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    if succeeds:
                        publisher.publish([[dependency], [consumer]], timeout=3)
                    else:
                        with self.assertRaises(subprocess.CalledProcessError):
                            publisher.publish([[dependency], [consumer]], timeout=3)
                state = json.loads(state_path.read_text())
                self.assertEqual(
                    state["uploaded"], [dependency.name, consumer.name] if succeeds else [dependency.name]
                )
                self.assertEqual(state["attempts"], 2 if succeeds else 3 if failures == 100 else 1)

    def test_cargo_progress_is_visible_before_process_exits(self):
        with tempfile.TemporaryDirectory() as directory:
            acknowledged = Path(directory) / "acknowledged"

            class ProgressOutput(io.StringIO):
                def write(self, message):
                    if "Packaging microsandbox-runtime" in message:
                        acknowledged.touch()
                    return super().write(message)

            # The child cannot finish successfully until its progress reaches
            # the caller. A buffered implementation times out instead.
            script = textwrap.dedent(f"""\
                from pathlib import Path
                import sys
                import time

                print('Packaging microsandbox-runtime', file=sys.stderr, flush=True)
                deadline = time.monotonic() + 5
                while not Path({str(acknowledged)!r}).exists():
                    if time.monotonic() >= deadline:
                        sys.exit(1)
                    time.sleep(0.01)
                """)
            with contextlib.redirect_stdout(ProgressOutput()):
                publisher.run_with_index_retry([sys.executable, "-c", script], [], timeout=10)

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
