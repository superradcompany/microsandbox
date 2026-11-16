"""Promotion must reject incomplete or corrupted provider releases."""
import hashlib
import importlib.util
import json
import re
import runpy
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("provider_release", Path(__file__).with_name("validate-provider-release.py"))
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class ProviderReleaseTests(unittest.TestCase):
    def test_macos_wheel_floor_matches_release_build(self):
        root = Path(__file__).resolve().parents[2]
        staging = runpy.run_path(str(root / "scripts/ci/stage-sdk-providers.py"))
        workflow = (root / ".github/workflows/release-macos.yml").read_text()
        floor = re.search(r'MACOSX_DEPLOYMENT_TARGET: "([0-9.]+)"', workflow).group(1)
        self.assertEqual(staging["TARGETS"]["aarch64-apple-darwin"][1],
                         f"macosx_{floor.replace('.', '_')}_arm64")

    def fixture(self, root):
        for triple, (release, platform) in VALIDATOR.TARGETS.items():
            for sdk, directory in (("go", root / "go" / f"go-providers-{release}"), ("node", root / "node" / f"node-providers-{platform}")):
                directory.mkdir(parents=True)
                entries = []
                for kind in ("local", "remote"):
                    data = f"{sdk}-{kind}-{triple}".encode()
                    filename = f"{kind}.native"
                    artifact = directory / filename if sdk == "go" else directory / "npm" / f"{kind}-{platform}" / f"microsandbox-{kind}.node"
                    artifact.parent.mkdir(parents=True, exist_ok=True)
                    artifact.write_bytes(data)
                    entries.append(dict(sdk=sdk, provider=kind, target=triple, version="1.0.0", profile="release", file=filename, bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
                (directory / "native-manifest.json").write_text(json.dumps({"artifacts": entries}))
                if sdk == "node":
                    for package in ("core", "local", "remote", "full", f"local-{platform}", f"remote-{platform}"):
                        path = directory / "npm" / package
                        path.mkdir(exist_ok=True)
                        (path / "package.json").write_text(json.dumps({"version": "1.0.0"}))

    def test_complete_release_and_missing_variant(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.fixture(root)
            VALIDATOR.validate(root / "node", root / "go", "1.0.0")
            (root / "go/go-providers-darwin-aarch64/remote.native").unlink()
            with self.assertRaisesRegex(SystemExit, "missing artifact"):
                VALIDATOR.validate(root / "node", root / "go", "1.0.0")

    def test_integrity_and_runtime_leak_block_promotion(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.fixture(root)
            (root / "go/go-providers-darwin-aarch64/remote.native").write_bytes(b"corrupt")
            (root / "node/node-providers-darwin-arm64/npm/local/msb").write_bytes(b"runtime")
            with self.assertRaisesRegex(SystemExit, "integrity mismatch"):
                VALIDATOR.validate(root / "node", root / "go", "1.0.0")
            with self.assertRaisesRegex(SystemExit, "runtime in lean package"):
                VALIDATOR.validate(root / "node", root / "go", "1.0.0")


if __name__ == "__main__":
    unittest.main()
