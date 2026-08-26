#!/usr/bin/env python3
"""Tests for executable-mode validation in release archives."""

from __future__ import annotations

import importlib.util
import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path


# The release validator keeps its CLI-oriented hyphenated filename, so load it
# directly instead of importing it as a normal Python module.
VALIDATOR_PATH = Path(__file__).with_name("validate-release-artifacts.py")
VALIDATOR_SPEC = importlib.util.spec_from_file_location(
    "validate_release_artifacts", VALIDATOR_PATH
)
assert VALIDATOR_SPEC is not None and VALIDATOR_SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(VALIDATOR_SPEC)
VALIDATOR_SPEC.loader.exec_module(VALIDATOR)

WHEEL_MSB_PATH = VALIDATOR.WHEEL_MSB_PATH
validate_bundle_executable = VALIDATOR.validate_bundle_executable
validate_wheel_executable = VALIDATOR.validate_wheel_executable


class ValidateReleaseArtifactModesTests(unittest.TestCase):
    def test_wheel_accepts_executable_msb(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wheel = Path(directory) / "microsandbox.whl"
            self.write_wheel(wheel, 0o755)
            errors: list[str] = []

            validate_wheel_executable(wheel, errors)

            self.assertEqual(errors, [])

    def test_wheel_rejects_non_executable_msb(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wheel = Path(directory) / "microsandbox.whl"
            self.write_wheel(wheel, 0o644)
            errors: list[str] = []

            validate_wheel_executable(wheel, errors)

            self.assertEqual(
                errors,
                [
                    "non-executable microsandbox/_bundled/bin/msb in "
                    "microsandbox.whl: mode 0o644"
                ],
            )

    def test_bundle_accepts_executable_msb(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "microsandbox-linux-x86_64.tar.gz"
            self.write_bundle(bundle, 0o755)
            errors: list[str] = []

            validate_bundle_executable(bundle, errors)

            self.assertEqual(errors, [])

    def test_bundle_rejects_non_executable_msb(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "microsandbox-linux-x86_64.tar.gz"
            self.write_bundle(bundle, 0o644)
            errors: list[str] = []

            validate_bundle_executable(bundle, errors)

            self.assertEqual(
                errors,
                [
                    "non-executable msb in microsandbox-linux-x86_64.tar.gz: "
                    "mode 0o644"
                ],
            )

    @staticmethod
    def write_wheel(path: Path, mode: int) -> None:
        member = zipfile.ZipInfo(WHEEL_MSB_PATH)
        member.external_attr = mode << 16
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(member, b"msb")

    @staticmethod
    def write_bundle(path: Path, mode: int) -> None:
        payload = b"msb"
        member = tarfile.TarInfo("msb")
        member.mode = mode
        member.size = len(payload)
        with tarfile.open(path, "w:gz") as archive:
            archive.addfile(member, io.BytesIO(payload))


if __name__ == "__main__":
    unittest.main()
