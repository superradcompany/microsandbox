"""VM-free coverage for release-bundle provisioning and catalog upgrade checks."""

import hashlib
import io
import os
from pathlib import Path
import sqlite3
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import previous_release_upgrade as smoke


class PreviousReleaseUpgradeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.archive = self.root / "bundle.tar.gz"
        self.destination = self.root / "runtime"
        self.destination.mkdir()

    def bundle(self, bad_firmware=None):
        with tarfile.open(self.archive, "w:gz") as bundle:
            for name in ["msb", smoke.firmware_name(), "../unwanted"]:
                member = tarfile.TarInfo(name)
                member.size = 4
                if name == smoke.firmware_name() and bad_firmware == "symlink":
                    member.type = tarfile.SYMTYPE
                    member.linkname = "/outside"
                    bundle.addfile(member)
                elif name != smoke.firmware_name() or bad_firmware != "missing":
                    bundle.addfile(member, io.BytesIO(b"data"))
                    if name == smoke.firmware_name() and bad_firmware == "duplicate":
                        bundle.addfile(member, io.BytesIO(b"data"))
        return f"{hashlib.sha256(self.archive.read_bytes()).hexdigest()}  {self.archive.name}\n"

    def test_platform_selects_bundle_not_standalone_binary(self):
        for system, machine, expected in [
            ("Darwin", "arm64", "microsandbox-darwin-aarch64.tar.gz"),
            ("Linux", "x86_64", "microsandbox-linux-x86_64.tar.gz"),
        ]:
            with self.subTest(system=system), patch.object(smoke.platform, "system", return_value=system), patch.object(smoke.platform, "machine", return_value=machine):
                self.assertEqual(smoke.platform_asset(), expected)

    def test_extracts_verified_runtime_pair_and_ignores_other_paths(self):
        smoke.unpack_release(self.archive, self.bundle(), self.destination)
        self.assertEqual(sorted(p.name for p in self.destination.iterdir()), sorted(["msb", smoke.firmware_name()]))
        self.assertTrue(os.access(self.destination / "msb", os.X_OK))
        self.assertEqual((self.destination / smoke.firmware_name()).read_bytes(), b"data")
        self.assertFalse((self.root / "unwanted").exists())

    def test_checksum_failure_precedes_extraction(self):
        checksums = self.bundle()
        for invalid in ["", checksums * 2, "0" * 64 + f"  {self.archive.name}\n"]:
            with self.subTest(checksums=invalid), self.assertRaisesRegex(smoke.SmokeError, "checksum"):
                smoke.unpack_release(self.archive, invalid, self.destination)
            self.assertEqual(list(self.destination.iterdir()), [])

    def test_missing_duplicate_or_symlinked_firmware_never_leaves_partial_pair(self):
        for invalid in ["missing", "duplicate", "symlink"]:
            with self.subTest(firmware=invalid), self.assertRaisesRegex(smoke.SmokeError, "regular release file"):
                smoke.unpack_release(self.archive, self.bundle(invalid), self.destination)
            self.assertEqual(list(self.destination.iterdir()), [])

    def test_download_requests_bundle_and_checksums(self):
        checksums = self.bundle()
        assets = [{"name": name, "browser_download_url": f"https://example.invalid/{name}"}
                  for name in [self.archive.name, "checksums.sha256"]]
        with patch.object(smoke, "platform_asset", return_value=self.archive.name), patch.object(smoke, "load_json", return_value={"assets": assets}), patch.object(smoke.urllib.request, "urlopen", side_effect=[io.BytesIO(self.archive.read_bytes()), io.BytesIO(checksums.encode())]) as download:
            smoke.download_release_binary("owner/repo", "v0.7.1", self.destination / "msb")
        self.assertEqual(download.call_count, 2)
        self.assertTrue((self.destination / smoke.firmware_name()).is_file())

    def test_fixture_uses_its_own_runtime_and_configuration(self):
        binary = self.destination / "msb"
        home = self.root / "home"
        with patch.dict(os.environ, {"MSB_BACKEND": "cloud", "MSB_AGENTD_PATH": "/wrong/agentd", "MSB_LIBKRUNFW_PATH": "/wrong/fw"}), patch.object(smoke.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            smoke.run_msb(binary, "list", home=home)
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["cwd"], home)
        self.assertEqual(kwargs["timeout"], 60)
        self.assertEqual(kwargs["env"]["MSB_PATH"], str(binary))
        self.assertEqual(kwargs["env"]["MSB_BACKEND"], "local")
        self.assertEqual(kwargs["env"]["MSB_LIBKRUNFW_PATH"], str(self.destination / smoke.firmware_name()))
        self.assertNotIn("MSB_AGENTD_PATH", kwargs["env"])

    def migration_database(self, migrations):
        path = self.root / "catalog.db"
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS seaql_migrations (version TEXT)")
            db.execute("DELETE FROM seaql_migrations")
            db.executemany("INSERT INTO seaql_migrations VALUES (?)", [(name,) for name in migrations])
        return path

    def test_upgrade_requires_candidate_migrations_not_preserved_old_schema(self):
        old, current = {"migrations": ["old"]}, {"migrations": ["old", "new"]}
        smoke.verify_migration_set("old", old, current, self.migration_database(["old", "new"]))
        with self.assertRaisesRegex(smoke.SmokeError, "candidate migration set"):
            smoke.verify_migration_set("old", old, current, self.migration_database(["old"]))

    def test_removed_duplicate_and_unexpected_migrations_are_rejected(self):
        for old, current, applied in [
            (["old"], ["new"], ["new"]),
            (["old", "old"], ["old"], ["old"]),
            (["old"], ["old", "old"], ["old"]),
            (["old"], ["old"], ["old", "surprise"]),
        ]:
            with self.subTest(old=old, current=current, applied=applied), self.assertRaises(smoke.SmokeError):
                smoke.verify_migration_set("old", {"migrations": old}, {"migrations": current}, self.migration_database(applied))


if __name__ == "__main__":
    unittest.main()
