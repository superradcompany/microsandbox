"""Exercise the real bump script in a disposable, registry-independent checkout."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "bump-version.sh"


class BumpVersionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="msb-bump-unit-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "scripts").mkdir()
        shutil.copyfile(SCRIPT, self.root / "scripts/bump-version.sh")
        for directory in ("crates", "packages", "sdk/ruby/ext/microsandbox",
                          "sdk/ruby/lib/microsandbox"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        self.cargo = self.root / "Cargo.toml"
        self.extension = self.root / "sdk/ruby/ext/microsandbox/Cargo.toml"
        self.ruby = self.root / "sdk/ruby/lib/microsandbox/version.rb"
        self.cargo.write_text('[workspace.package]\nversion = "0.6.18"\n')
        self.extension.write_text(
            '[package]\nname = "microsandbox-ruby"\nversion = "0.6.18"\n'
            '[dependencies]\nmicrosandbox_core = { package = "microsandbox", '
            'version = "=0.6.18" }\n')
        self.ruby.write_text('module Microsandbox\n  VERSION = "0.6.18"\nend\n')
        # Registry lockfiles are not fabricated by this metadata-only script.
        self.lock = self.root / "sdk/ruby/ext/microsandbox/Cargo.lock"
        self.lock.write_text('# published registry graph remains unchanged\n')

    def bump(self, *versions):
        return subprocess.run(
            ["bash", str(self.root / "scripts/bump-version.sh"), *versions],
            cwd=self.root, capture_output=True, text=True, check=True, timeout=10,
        )

    def assert_aligned(self):
        self.assertIn('version = "0.7.0"', self.cargo.read_text())
        self.assertIn('version = "0.7.0"', self.extension.read_text())
        self.assertIn('version = "=0.7.0"', self.extension.read_text())
        self.assertEqual(self.ruby.read_text(), 'module Microsandbox\n  VERSION = "0.7.0"\nend\n')
        self.assertEqual(self.lock.read_text(), '# published registry graph remains unchanged\n')
        self.assertFalse(list(self.root.rglob("*.bak")))

    def test_bump_keeps_ruby_and_rust_versions_aligned(self):
        self.bump("0.7.0")
        self.assert_aligned()

    def test_repeated_bump_is_an_unchanged_early_noop(self):
        self.bump("0.7.0")
        before = {path: path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        result = self.bump("0.7.0")
        self.assertIn("version already at 0.7.0, nothing to do", result.stdout)
        after = {path: path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        self.assertEqual(before, after)
        self.assert_aligned()

    def test_explicit_old_version_repairs_a_partial_bump(self):
        self.cargo.write_text('[workspace.package]\nversion = "0.7.0"\n')
        self.bump("0.7.0", "0.6.18")
        self.assert_aligned()

    def test_checkout_without_ruby_constant_remains_supported(self):
        self.ruby.unlink()
        self.bump("0.7.0")
        self.assertIn('version = "0.7.0"', self.cargo.read_text())
        self.assertFalse(self.ruby.exists())


if __name__ == "__main__":
    unittest.main()
