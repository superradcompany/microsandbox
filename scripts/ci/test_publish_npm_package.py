#!/usr/bin/env python3
"""Tests for idempotent npm package publication."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.ci import publish_npm_package


class PublishNpmPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.directory = Path(self.temporary_directory.name)
        (self.directory / "package.json").write_text(
            json.dumps({"name": "@example/package", "version": "1.2.3"})
        )
        self.package = publish_npm_package.load_package(self.directory)

    def test_load_package_reads_identity(self) -> None:
        self.assertEqual(self.package.name, "@example/package")
        self.assertEqual(self.package.version, "1.2.3")
        self.assertEqual(self.package.spec, "@example/package@1.2.3")

    @mock.patch.object(publish_npm_package.subprocess, "run")
    @mock.patch.object(publish_npm_package, "registry_integrity", return_value=None)
    @mock.patch.object(
        publish_npm_package, "pack_integrity", return_value="sha512-local"
    )
    def test_missing_package_is_published(
        self,
        _pack_integrity: mock.Mock,
        _registry_integrity: mock.Mock,
        run: mock.Mock,
    ) -> None:
        publish_npm_package.publish_package(self.package)

        run.assert_called_once_with(
            ["npm", "publish", "--access", "public"],
            cwd=self.directory,
            check=True,
        )

    @mock.patch.object(publish_npm_package.subprocess, "run")
    @mock.patch.object(
        publish_npm_package,
        "registry_integrity",
        return_value="sha512-matching",
    )
    @mock.patch.object(
        publish_npm_package,
        "pack_integrity",
        return_value="sha512-matching",
    )
    def test_matching_package_is_skipped(
        self,
        _pack_integrity: mock.Mock,
        _registry_integrity: mock.Mock,
        run: mock.Mock,
    ) -> None:
        publish_npm_package.publish_package(self.package)

        run.assert_not_called()

    @mock.patch.object(
        publish_npm_package,
        "registry_integrity",
        return_value="sha512-remote",
    )
    @mock.patch.object(
        publish_npm_package,
        "pack_integrity",
        return_value="sha512-local",
    )
    def test_mismatched_package_fails(
        self,
        _pack_integrity: mock.Mock,
        _registry_integrity: mock.Mock,
    ) -> None:
        with self.assertRaisesRegex(
            SystemExit,
            "@example/package@1.2.3 exists with different contents",
        ):
            publish_npm_package.publish_package(self.package)

    @mock.patch.object(publish_npm_package.subprocess, "run")
    def test_pack_integrity_validates_identity(self, run: mock.Mock) -> None:
        run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "name": "another-package",
                        "version": "1.2.3",
                        "integrity": "sha512-local",
                    }
                ]
            ),
        )

        with self.assertRaisesRegex(SystemExit, "npm pack identity mismatch"):
            publish_npm_package.pack_integrity(self.package)


if __name__ == "__main__":
    unittest.main()
