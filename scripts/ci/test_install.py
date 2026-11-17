"""Exercise the real installer with inert, strictly offline release fixtures."""

import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import tempfile
import unittest


INSTALLER = Path(__file__).resolve().parents[1] / "install.sh"


@unittest.skipUnless(platform.system() in ("Linux", "Darwin"), "Unix installer only")
class InstallTests(unittest.TestCase):
    def run_case(self, case, *, args=(), releases=None, expected_version="v0.7.8",
                 expected_error=None, broken_bundle=False, missing_bundle=False, overrides=None):
        system = platform.system()
        machine = platform.machine()
        if system == "Darwin" and machine != "arm64":
            self.skipTest("macOS installer requires Apple Silicon")
        architectures = {"x86_64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}
        if machine not in architectures:
            self.skipTest("unsupported release architecture")
        target_name = f"{system.lower()}-{architectures[machine]}"
        library = "libkrunfw.so.5.6.1" if system == "Linux" else "libkrunfw.5.dylib"
        library_links = ({"libkrunfw.so.5": library, "libkrunfw.so": "libkrunfw.so.5"}
                         if system == "Linux" else {"libkrunfw.dylib": library})
        source = INSTALLER.read_bytes()
        with tempfile.TemporaryDirectory(prefix="msb-install-test-") as temporary:
            root = Path(temporary).resolve()
            home, work, fixture, fake, temp, payload = [root / name for name in
                ("home", "work", "fixture", "fake-bin", "temp", "payload")]
            for directory in (home, work, fixture, fake, temp, payload):
                directory.mkdir()
            binary_bytes = b"inert fixture, never executed\n"
            library_bytes = b"inert library fixture\n"
            (payload / "msb").write_bytes(binary_bytes)
            (payload / library).write_bytes(library_bytes)
            bundle = fixture / f"microsandbox-{target_name}.tar.gz"
            with tarfile.open(bundle, "w:gz") as archive:
                for entry in payload.iterdir():
                    archive.add(entry, arcname=entry.name)
            (fixture / "checksums.sha256").write_text(
                hashlib.sha256(bundle.read_bytes()).hexdigest() + "  " + bundle.name + "\n")
            if broken_bundle:
                bundle.write_bytes(b"corrupt archive")
            (fixture / "releases.json").write_text(json.dumps(releases or []))
            # This replacement has no networking code and rejects every unknown URL.
            curl = fake / "curl"
            curl.write_text(f"#!{sys.executable}\n" + '''import json, os, pathlib, shutil, sys
args = sys.argv[1:]
urls = [value for value in args if value.startswith("https://")]
assert len(urls) == 1, args
url = urls[0]
if url == "https://api.github.com/repos/superradcompany/microsandbox/releases/latest":
    assert args == ["-fsSL", url], args
    print('{"tag_name":"v0.7.8"}')
elif url.startswith("https://api.github.com/repos/superradcompany/microsandbox/releases?per_page=100&page="):
    page = int(url.rsplit("=", 1)[1])
    releases = json.loads((pathlib.Path(os.environ["FIXTURE"]) / "releases.json").read_text())
    print(json.dumps(releases[(page-1)*100:page*100]))
else:
    prefix = "https://github.com/superradcompany/microsandbox/releases/download/" + os.environ["EXPECTED_VERSION"] + "/"
    assert url.startswith(prefix), url
    name = url[len(prefix):]
    assert name in (os.environ["FIXTURE_BUNDLE"], "checksums.sha256"), name
    if args == ["-fsSLI", url]:
        sys.exit(0)
    assert len(args) == 4 and args[:3] == ["-fsSL", url, "-o"], args
    if os.environ["MISSING_BUNDLE"] == "1": sys.exit(22)
    shutil.copyfile(pathlib.Path(os.environ["FIXTURE"]) / name, args[3])
''')
            curl.chmod(0o755)
            env = dict(HOME=str(home), TMPDIR=str(temp),
                       PATH=str(fake) + ":/usr/bin:/bin:/usr/sbin:/sbin",
                       FIXTURE=str(fixture), FIXTURE_BUNDLE=bundle.name, EXPECTED_VERSION=expected_version,
                       MISSING_BUNDLE="1" if missing_bundle else "0")
            env.update(overrides or {})
            target = home / ".microsandbox"
            cwd = work
            if case == "absolute":
                target = root / "absolute"
                env["MSB_HOME"] = str(target)
            elif case in ("relative", "relative-spaces", "symlink-cwd"):
                name = "custom home" if case == "relative-spaces" else "custom-home"
                env["MSB_HOME"] = "./" + name
                target = work / name
                if case == "symlink-cwd":
                    cwd = root / "work-alias"
                    cwd.symlink_to(work, target_is_directory=True)
                    env["PWD"] = str(cwd)
            elif case == "parent":
                env["MSB_HOME"] = "../custom-home"
                target = root / "custom-home"
            elif case == "symlink-parent":
                (root / "physical" / "nested").mkdir(parents=True)
                (work / "alias").symlink_to(root / "physical" / "nested",
                                           target_is_directory=True)
                env["MSB_HOME"] = "alias/../custom-home"
                target = root / "physical" / "custom-home"
            if expected_error:
                (target / "bin").mkdir(parents=True)
                (target / "bin/msb").write_bytes(b"existing binary")
                (target / "lib").mkdir()
                (target / "lib" / library).write_bytes(b"existing library")
            process = subprocess.run(["/bin/sh", str(INSTALLER), *args], cwd=cwd, env=env,
                                     text=True, capture_output=True, timeout=10)
            if expected_error:
                self.assertNotEqual(process.returncode, 0, process.stdout + process.stderr)
                self.assertIn(expected_error, process.stdout + process.stderr)
                self.assertEqual((target / "bin/msb").read_bytes(), b"existing binary")
                self.assertEqual((target / "lib" / library).read_bytes(), b"existing library")
                self.assertFalse((home / ".local/bin/msb").exists())
                self.assertEqual(list(temp.iterdir()), [])
                return
            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
            self.assertEqual(list(temp.iterdir()), [], "installer temporary directory leaked")
            self.assertEqual(INSTALLER.read_bytes(), source, "installer source changed")
            for path, expected in ((target / "bin/msb", binary_bytes),
                                   (target / "lib" / library, library_bytes)):
                self.assertFalse(path.is_symlink(), str(path))
                self.assertTrue(path.is_file(), str(path))
                self.assertEqual(path.read_bytes(), expected)
            aliases = {target / "bin/microsandbox": "msb"}
            aliases.update({target / "lib" / name: value
                            for name, value in library_links.items()})
            for path, expected in aliases.items():
                self.assertTrue(path.is_symlink(), str(path))
                self.assertEqual(os.readlink(path), expected)
                expected_bytes = binary_bytes if path.parent.name == "bin" else library_bytes
                self.assertEqual(path.read_bytes(), expected_bytes)
            for command in ("msb", "microsandbox"):
                link = home / ".local/bin" / command
                self.assertTrue(link.is_symlink(), str(link))
                self.assertTrue(Path(os.readlink(link)).is_absolute(), str(link))
                self.assertEqual(link.resolve(strict=True), (target / "bin/msb").resolve())
                self.assertEqual(link.read_bytes(), binary_bytes)

    def test_default_home(self):
        self.run_case("default")

    def test_absolute_home(self):
        self.run_case("absolute")

    def test_relative_home(self):
        self.run_case("relative")

    def test_relative_home_with_spaces(self):
        self.run_case("relative-spaces")

    def test_parent_home(self):
        self.run_case("parent")

    def test_symlink_parent_home(self):
        self.run_case("symlink-parent")

    def test_symlink_working_directory(self):
        self.run_case("symlink-cwd")

    def test_explicit_stable_channel(self):
        self.run_case("default", args=["--channel", "stable"])

    def test_exact_version_accepts_optional_v_and_old_candidates(self):
        for version in ["0.8.0-rc.1", "v0.8.0-rc.1", "0.6.0"]:
            with self.subTest(version=version):
                self.run_case("default", args=["--version", version], expected_version="v" + version.removeprefix("v"))

    def test_environment_selection_and_flag_override(self):
        self.run_case("default", overrides={"MSB_INSTALL_VERSION": "0.8.0-rc.1"}, expected_version="v0.8.0-rc.1")
        self.run_case("default", args=["--version", "0.7.8"], overrides={"MSB_INSTALL_VERSION": "0.8.0-rc.1"})
        self.run_case("default", args=["--channel", "stable"], overrides={"MSB_INSTALL_CHANNEL": "rc"})

    def test_rc_selects_numeric_highest_and_ignores_drafts_and_betas(self):
        releases = [release("v0.8.0-rc.9"), release("v0.8.0-rc.10"),
                    release("v0.9.0-rc.1", draft=True), release("v0.9.0-beta.1"),
                    release("v0.7.14", prerelease=False), release("v0.8.0-rc.11", prerelease=False)]
        self.run_case("default", args=["--channel", "rc"], releases=releases, expected_version="v0.8.0-rc.10")

    def test_rc_paginates_and_compares_release_trains(self):
        releases = [release("v0.8.0-rc.1")] * 100 + [release("v0.10.0-rc.1"), release("v0.9.0-rc.20")]
        self.run_case("default", overrides={"MSB_INSTALL_CHANNEL": "rc"}, releases=releases, expected_version="v0.10.0-rc.1")

    def test_final_release_retires_candidates_across_pages(self):
        releases = [release("v0.8.0-rc.1")] * 100 + [release("v0.8.0", prerelease=False)]
        self.run_case("default", args=["--channel", "rc"], releases=releases, expected_error="No active RC")

    def test_no_candidate_never_falls_back_or_changes_existing_install(self):
        self.run_case("default", args=["--channel", "rc"], expected_error="No active RC")

    def test_invalid_selection_never_changes_existing_install(self):
        for args in [["--channel", "nightly"], ["--version"], ["--version", "../../evil"],
                     ["--version", "0.8.0-rc.01"], ["--channel", "rc", "--version", "0.8.0-rc.1"], ["--bogus"]]:
            with self.subTest(args=args):
                self.run_case("default", args=args, expected_error="error")

    def test_checksum_failure_preserves_existing_install(self):
        self.run_case("default", args=["--version", "0.8.0-rc.1"], expected_version="v0.8.0-rc.1",
                      broken_bundle=True, expected_error="Checksum verification failed")

    def test_missing_platform_bundle_preserves_existing_install(self):
        self.run_case("default", args=["--channel", "rc"], releases=[release("v0.8.0-rc.1")],
                      expected_version="v0.8.0-rc.1", missing_bundle=True, expected_error="Failed to download")


def release(tag, *, draft=False, prerelease=True):
    return {"tag_name": tag, "draft": draft, "prerelease": prerelease,
            "body": 'notes with \"tag_name\": \"v99.0.0-rc.1\" and braces {}',
            "assets": [{"tag_name": "v99.0.0-rc.1"}]}


if __name__ == "__main__":
    unittest.main()
