#!/usr/bin/env python3
"""Tests for the Linux glibc release-artifact validator."""

from __future__ import annotations

import unittest

from scripts.ci.validate_linux_glibc import (
    parse_glibc_versions,
    parse_version,
    validate_installer_baseline,
    version_key,
)


class ValidateLinuxGlibcTests(unittest.TestCase):
    def test_parse_glibc_versions_collects_required_and_weak_versions(self) -> None:
        output = """
          0x0010: Name: GLIBC_2.17  Flags: none  Version: 6
          0x0030: Name: GLIBC_2.28  Flags: none  Version: 4
          0x0050: Name: GLIBC_2.39  Flags: WEAK  Version: 3
          0x0070: Name: GLIBCXX_3.4.29  Flags: none  Version: 2
        """

        self.assertEqual(
            parse_glibc_versions(output),
            {(2, 17), (2, 28), (2, 39)},
        )

    def test_version_key_treats_trailing_zeroes_as_equal(self) -> None:
        self.assertEqual(
            version_key(parse_version("2.28")), version_key(parse_version("2.28.0"))
        )

    def test_version_key_orders_newer_glibc_versions(self) -> None:
        self.assertGreater(
            version_key(parse_version("2.38")), version_key(parse_version("2.28"))
        )

    def test_parse_version_rejects_non_numeric_values(self) -> None:
        with self.assertRaises(ValueError):
            parse_version("GLIBC_2.28")

    def test_installer_baseline_matches_release_artifacts(self) -> None:
        installer = 'LINUX_GLIBC_MIN_VERSION="2.28"\n'

        self.assertEqual(validate_installer_baseline(installer, (2, 28)), (2, 28))

    def test_installer_baseline_rejects_drift(self) -> None:
        installer = 'LINUX_GLIBC_MIN_VERSION="2.39"\n'

        with self.assertRaisesRegex(
            ValueError,
            "installer requires glibc 2.39, but release artifacts are audited "
            "against glibc 2.28",
        ):
            validate_installer_baseline(installer, (2, 28))


if __name__ == "__main__":
    unittest.main()
