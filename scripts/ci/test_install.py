"""Exercise the real installer with inert, strictly offline release fixtures."""

import hashlib
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
    def run_case(self, case, *, umask=0o022, existing_mode=None):
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
            # This replacement has no networking code and rejects every unknown URL.
            curl = fake / "curl"
            curl.write_text(f"#!{sys.executable}\n" + '''import os, pathlib, shutil, sys
args = sys.argv[1:]
urls = [value for value in args if value.startswith("https://")]
assert len(urls) == 1, args
url = urls[0]
if url == "https://api.github.com/repos/superradcompany/microsandbox/releases/latest":
    assert args == ["-fsSL", url], args
    print('{"tag_name":"v0.7.8"}')
else:
    prefix = "https://github.com/superradcompany/microsandbox/releases/download/v0.7.8/"
    assert url.startswith(prefix), url
    name = url[len(prefix):]
    assert name in (os.environ["FIXTURE_BUNDLE"], "checksums.sha256"), name
    if args == ["-fsSLI", url]:
        sys.exit(0)
    assert len(args) == 4 and args[:3] == ["-fsSL", url, "-o"], args
    shutil.copyfile(pathlib.Path(os.environ["FIXTURE"]) / name, args[3])
''')
            curl.chmod(0o755)
            env = dict(HOME=str(home), TMPDIR=str(temp),
                       PATH=str(fake) + ":/usr/bin:/bin:/usr/sbin:/sbin",
                       FIXTURE=str(fixture), FIXTURE_BUNDLE=bundle.name)
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
            if case == "existing-symlink":
                physical = root / "shared home"
                physical.mkdir()
                target.symlink_to(physical, target_is_directory=True)
            if existing_mode is not None:
                target.mkdir(parents=True, exist_ok=True)
                target.chmod(existing_mode)
                # Upgrades must keep existing user data and its permissions intact.
                sentinel = target / "existing-data"
                sentinel.write_text("keep me")
                sentinel.chmod(0o640)
            process = subprocess.run(["/bin/sh", str(INSTALLER)], cwd=cwd, env=env,
                                     text=True, capture_output=True, timeout=10, umask=umask)
            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
            expected_mode = 0o700 if existing_mode is None else existing_mode
            self.assertEqual(target.stat().st_mode & 0o777, expected_mode)
            if existing_mode is not None:
                self.assertEqual(sentinel.read_text(), "keep me")
                self.assertEqual(sentinel.stat().st_mode & 0o777, 0o640)
            if existing_mode is not None and existing_mode & 0o022:
                self.assertIn("group or world writable", process.stdout)
                warning = next(line for line in process.stdout.splitlines()
                               if " is group or world writable" in line)
                warned_path = warning.removeprefix("warn ").split(" is group or world writable", 1)[0]
                self.assertTrue(Path(warned_path).samefile(target))
                self.assertIn("chmod 700", process.stdout)
            else:
                self.assertNotIn("group or world writable", process.stdout)
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

    def test_fresh_home_is_private_under_each_umask(self):
        for case in ("default", "absolute", "relative-spaces"):
            for mask in (0o000, 0o002, 0o022, 0o077):
                with self.subTest(case=case, umask=oct(mask)):
                    self.run_case(case, umask=mask)

    def test_existing_home_permissions_and_data_are_preserved(self):
        for case in ("default", "absolute", "relative-spaces"):
            for mode in (0o700, 0o755, 0o775, 0o777):
                with self.subTest(case=case, mode=oct(mode)):
                    self.run_case(case, umask=0o002, existing_mode=mode)

    def test_existing_symlink_target_is_not_chmodded(self):
        self.run_case("existing-symlink", umask=0o002, existing_mode=0o775)

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


if __name__ == "__main__":
    unittest.main()
