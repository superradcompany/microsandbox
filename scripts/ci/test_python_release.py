"""Exercise release artifact collisions, project routing and publication retries."""

import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
import zipfile

from scripts.ci import python_release as release


PLATFORMS = {
    "darwin-aarch64": "macosx_14_0_arm64",
    "linux-aarch64": "manylinux_2_28_aarch64",
    "linux-x86_64": "manylinux_2_28_x86_64",
    "windows-aarch64": "win_arm64",
    "windows-x86_64": "win_amd64",
}


def wheel(directory, package, platform="any", version="0.8.2", payload=b"payload"):
    directory.mkdir(parents=True, exist_ok=True)
    name = package.replace("-", "_")
    tag = "py3-none-any" if platform == "any" else f"cp310-abi3-{platform}"
    path = directory / f"{name}-{version}-{tag}.whl"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr(f"{name}-{version}.dist-info/METADATA", f"Name: {package}\nVersion: {version}\n")
        archive.writestr(f"{name}/payload", payload)
    return path


def artifacts(root):
    for target, platform in PLATFORMS.items():
        directory = root / f"python-sdk-{target}"
        for package in release.PACKAGES:
            # Model byte-different core builds sharing exactly the same name.
            wheel(directory, package, "any" if package == release.CORE else platform,
                  payload=target.encode())


class CollectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "download"
        self.out = self.root / "wheels"
        artifacts(self.source)

    def test_selects_canonical_core_and_preserves_all_native_wheel_bytes(self):
        names = release.collect(self.source, self.out)
        self.assertEqual(len(names), 16)
        for path in self.out.glob("*.whl"):
            if path.name.startswith("microsandbox_core-"):
                original = self.source / "python-sdk-darwin-aarch64" / path.name
            else:
                original, = self.source.glob(f"*/{path.name}")
            self.assertEqual(path.read_bytes(), original.read_bytes())
        # Identical output regardless of directory traversal or previous builds.
        other = self.root / "second"
        self.assertEqual(release.collect(self.source, other), names)
        for name in names:
            self.assertEqual((self.out / name).read_bytes(), (other / name).read_bytes())

    def test_missing_target_or_provider_fails_before_copy(self):
        directory = self.source / "python-sdk-linux-aarch64"
        for path in directory.iterdir():
            path.unlink()
        with self.assertRaisesRegex(ValueError, "missing packages"):
            release.collect(self.source, self.out)
        directory.rmdir()
        with self.assertRaisesRegex(ValueError, "five isolated"):
            release.collect(self.source, self.out)
        self.assertFalse(self.out.exists())

    def test_corrupt_unselected_core_also_blocks_release(self):
        core, = (self.source / "python-sdk-windows-x86_64").glob("microsandbox_core-*")
        data = core.read_bytes().replace(b"windows-x86_64", b"damaged-x86_64")
        core.write_bytes(data)
        with self.assertRaises(zipfile.BadZipFile):
            # testzip returns the damaged entry; inspect_wheel raises ValueError.
            with zipfile.ZipFile(core) as archive:
                archive.read("microsandbox_core/payload")
        with self.assertRaisesRegex(ValueError, "corrupt wheel member"):
            release.collect(self.source, self.out)
        self.assertFalse(self.out.exists())

    def test_overlapping_write_style_zip_damage_blocks_release(self):
        core, = (self.source / "python-sdk-darwin-aarch64").glob("microsandbox_core-*")
        core.write_bytes(core.read_bytes()[:50])
        with self.assertRaises(zipfile.BadZipFile):
            release.collect(self.source, self.out)
        self.assertFalse(self.out.exists())

    def test_duplicate_native_filename_is_not_silently_overwritten(self):
        source, = (self.source / "python-sdk-linux-x86_64").glob("microsandbox_local-*")
        dest, = (self.source / "python-sdk-windows-x86_64").glob("microsandbox_local-*")
        dest.unlink()
        (dest.parent / source.name).write_bytes(source.read_bytes())
        with self.assertRaisesRegex(ValueError, "duplicate platform"):
            release.collect(self.source, self.out)

    def test_mixed_native_versions_fail_before_copy(self):
        native, = (self.source / "python-sdk-windows-x86_64").glob("microsandbox_local-*")
        native.unlink()
        wheel(native.parent, "microsandbox-local", "win_amd64", "0.8.1")
        with self.assertRaisesRegex(ValueError, "mixed versions"):
            release.collect(self.source, self.out)
        self.assertFalse(self.out.exists())

    def test_different_core_version_and_stale_output_fail(self):
        core, = (self.source / "python-sdk-windows-x86_64").glob("microsandbox_core-*")
        core.unlink()
        wheel(core.parent, release.CORE, version="0.8.1")
        with self.assertRaisesRegex(ValueError, "core wheel filenames differ"):
            release.collect(self.source, self.out)
        self.out.mkdir()
        (self.out / "old.whl").write_bytes(b"old")
        with self.assertRaisesRegex(ValueError, "must be empty"):
            release.collect(self.source, self.out)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        artifacts(self.root / "download")
        self.dist = self.root / "dist"
        release.collect(self.root / "download", self.dist)

    def test_every_project_uploads_only_its_own_wheels_and_waits(self):
        for package in release.PACKAGES:
            with self.subTest(package=package), patch.object(release.subprocess, "run") as run, patch.object(release, "wait_for_index") as wait:
                release.publish(self.dist, package)
                args = run.call_args.args[0]
                self.assertEqual(args[:6], ["uv", "publish", "--trusted-publishing", "always", "--check-url", "https://pypi.org/simple/"])
                self.assertTrue(run.call_args.kwargs["check"])
                expected, version = release.package_wheels(self.dist, package)
                self.assertEqual(args[6:], list(map(str, expected)))
                wait.assert_called_once_with(package, version, expected)

    def test_failed_upload_never_reports_success(self):
        with patch.object(release.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "uv")), patch.object(release, "wait_for_index") as wait:
            with self.assertRaises(subprocess.CalledProcessError):
                release.publish(self.dist, release.CORE)
            wait.assert_not_called()

    def test_missing_or_mixed_versions_fail_before_upload(self):
        target, = self.dist.glob("microsandbox_local-*win_amd64.whl")
        target.unlink()
        with patch.object(release.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "expected 5"):
                release.publish(self.dist, "microsandbox-local")
            wheel(self.dist, "microsandbox-local", "win_amd64", "0.8.1")
            with self.assertRaisesRegex(ValueError, "mixed package names or versions"):
                release.publish(self.dist, "microsandbox-local")
            run.assert_not_called()

    def test_metadata_cannot_route_another_project_through_core_identity(self):
        core, = self.dist.glob("microsandbox_core-*")
        forged = wheel(self.root, "microsandbox-remote")
        core.write_bytes(forged.read_bytes())
        with patch.object(release.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "filename/metadata"):
                release.publish(self.dist, release.CORE)
            run.assert_not_called()

    def test_prerelease_metadata_is_preserved(self):
        root = self.root / "rc"
        wheel(root, release.CORE, version="0.8.2rc1")
        with patch.object(release.subprocess, "run"), patch.object(release, "wait_for_index") as wait:
            release.publish(root, release.CORE)
        self.assertEqual(wait.call_args.args[1], "0.8.2rc1")

    def test_index_wait_retries_missing_files_and_checks_exact_hashes(self):
        wheels, version = release.package_wheels(self.dist, release.CORE)
        item = {"filename": wheels[0].name, "digests": {"sha256": release.hashlib.sha256(wheels[0].read_bytes()).hexdigest()}}
        responses = [HTTPError("url", 404, "not indexed", {}, None), io.BytesIO(b'{"urls": []}'), io.BytesIO(json.dumps({"urls": [item]}).encode())]
        with patch.object(release, "urlopen", side_effect=responses) as request, patch.object(release.time, "sleep") as sleep:
            release.wait_for_index(release.CORE, version, wheels, attempts=3)
            self.assertEqual(request.call_count, 3)
            self.assertEqual(sleep.call_count, 2)
            self.assertEqual(request.call_args.args[0], "https://pypi.org/pypi/microsandbox-core/0.8.2/json")
        item["digests"]["sha256"] = "wrong"
        with patch.object(release, "urlopen", return_value=io.BytesIO(json.dumps({"urls": [item]}).encode())):
            with self.assertRaisesRegex(ValueError, "different bytes"):
                release.wait_for_index(release.CORE, version, wheels)

    def test_index_timeout_and_auth_failure_are_visible(self):
        wheels, version = release.package_wheels(self.dist, release.CORE)
        with patch.object(release, "urlopen", side_effect=HTTPError("url", 404, "missing", {}, None)), patch.object(release.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "after 2 checks"):
                release.wait_for_index(release.CORE, version, wheels, attempts=2)
        with patch.object(release, "urlopen", side_effect=HTTPError("url", 403, "forbidden", {}, None)):
            with self.assertRaises(HTTPError):
                release.wait_for_index(release.CORE, version, wheels)


if __name__ == "__main__":
    unittest.main()
