import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("apt_fallback", SCRIPTS / "prepare-apt-fallback.py")
fallback = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fallback)

SOURCES = """Types: deb deb-src
URIs: mirror+file:/etc/apt/apt-mirrors.txt
Suites: resolute resolute-updates resolute-backports resolute-security
Components: main restricted universe multiverse
Architectures: amd64 amd64v3
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
Check-Valid-Until: yes
"""


class SourceTests(unittest.TestCase):
    def test_runner_mirrorlist_preserves_all_source_options(self):
        result, count = fallback.rewrite_sources(SOURCES, True, fallback.MIRRORS["amd64"])
        self.assertEqual(count, 1)
        self.assertEqual(result, SOURCES.replace("mirror+file:/etc/apt/apt-mirrors.txt",
                                                 fallback.MIRRORS["amd64"]))

    def test_arm_and_multiline_uris(self):
        text = """Types: deb
URIs: http://ports.ubuntu.com/ubuntu-ports/
 https://ports.ubuntu.com/ubuntu-ports
Suites: noble noble-updates noble-security
Architectures: arm64
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
"""
        result, count = fallback.rewrite_sources(text, True, fallback.MIRRORS["arm64"])
        self.assertEqual(count, 2)
        self.assertNotIn("ports.ubuntu.com", result)
        self.assertEqual(result[result.index("Suites:"):], text[text.index("Suites:"):])

    def test_deb822_field_names_are_case_insensitive(self):
        text = SOURCES.replace("URIs:", "Uris:")
        result, count = fallback.rewrite_sources(text, True, fallback.MIRRORS["amd64"])
        self.assertEqual(count, 1)
        self.assertIn("Uris: " + fallback.MIRRORS["amd64"], result)

    def test_legacy_sources_preserve_options_and_third_party(self):
        text = """# deb http://archive.ubuntu.com/ubuntu noble main
deb [arch=amd64 signed-by=/keys/ubuntu.gpg] http://us.archive.ubuntu.com/ubuntu noble main universe
deb-src https://security.ubuntu.com/ubuntu/ noble-security main
deb [signed-by=/keys/microsoft.gpg] https://packages.microsoft.com/ubuntu/24.04/prod noble main
"""
        result, count = fallback.rewrite_sources(text, False, fallback.MIRRORS["amd64"])
        self.assertEqual(count, 2)
        expected = text.replace("http://us.archive.ubuntu.com/ubuntu", fallback.MIRRORS["amd64"])
        expected = expected.replace("https://security.ubuntu.com/ubuntu/", fallback.MIRRORS["amd64"])
        self.assertEqual(result, expected)

    def test_only_known_ubuntu_uri_values_are_rewritten(self):
        for uri in ["https://archive.ubuntu.com.evil.example/ubuntu",
                    "https://evil.example/ubuntu", "https://archive.ubuntu.com/other",
                    "mirror+file:/etc/apt/custom-mirrors.txt", "https://archive.ubuntu.com/ubuntu?other"]:
            with self.subTest(uri=uri):
                self.assertFalse(fallback.ubuntu_uri(uri))
        text = "# http://archive.ubuntu.com/ubuntu\nSigned-By: https://archive.ubuntu.com/ubuntu\n"
        self.assertEqual(fallback.rewrite_sources(text, True, "https://mirror.example/"), (text, 0))

    def test_copy_keeps_originals_and_starts_with_empty_indexes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources, output = root / "apt", root / "output"
            (sources / "sources.list.d").mkdir(parents=True)
            output.mkdir()
            ubuntu = sources / "sources.list.d/ubuntu.sources"
            ubuntu.write_text(SOURCES)
            third_party = sources / "sources.list.d/microsoft.list"
            third_party.write_text("deb https://packages.microsoft.com/ubuntu/26.04/prod resolute main\n")
            (sources / "sources.list.d/ignored.save").write_text("not an apt source")
            fallback.prepare_sources(sources, output, "amd64")
            self.assertEqual(ubuntu.read_text(), SOURCES)
            self.assertEqual((output / "sources.list.d/microsoft.list").read_text(), third_party.read_text())
            self.assertEqual((output / "sources.list").read_text(), "")
            self.assertEqual(list((output / "lists").iterdir()), [])
            self.assertFalse((output / "sources.list.d/ignored.save").exists())
            self.assertEqual((output / "sources.list.d/ubuntu.sources").stat().st_mode & 0o777, 0o644)

    def test_missing_ubuntu_sources_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "No recognized Ubuntu sources"):
                fallback.prepare_sources(root / "missing", root, "amd64")

    def test_unsupported_architecture_fails_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "No Ubuntu fallback"):
                fallback.prepare_sources(root, root, "riscv64")
            self.assertEqual(list(root.iterdir()), [])


class InstallerTests(unittest.TestCase):
    """Exercise the actual shell control flow without root or network access."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.scripts = self.root / "artifact with spaces"
        self.scripts.mkdir()
        self.installer = self.scripts / "install-apt-packages.sh"
        shutil.copyfile(SCRIPTS / "install-apt-packages.sh", self.installer)
        self.sources = self.root / "apt"
        (self.sources / "sources.list.d").mkdir(parents=True)
        (self.sources / "sources.list.d/ubuntu.sources").write_text(SOURCES)
        self.log = self.root / "apt-calls.jsonl"
        # Use the real source rewriter against fixtures. Downloads restore
        # files without execute bits, so invoke the installer via bash.
        (self.scripts / "prepare-apt-fallback.py").write_text(
            "import os,sys,runpy\nfrom pathlib import Path\n"
            f"module = runpy.run_path({str(SCRIPTS / 'prepare-apt-fallback.py')!r})\n"
            "module['prepare_sources'](Path(os.environ['FAKE_SOURCES']), Path(sys.argv[1]), sys.argv[2])\n")
        self.command("sudo", '#!/bin/sh\nexec "$@"\n')
        self.command("timeout", '#!/bin/sh\nshift 2\nexec "$@"\n')
        self.command("sleep", '#!/bin/sh\nexit 0\n')
        self.command("dpkg", '#!/bin/sh\nprintf "%s\\n" "$FAKE_ARCH"\n')
        self.command("apt-get", """#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
log = Path(os.environ['FAKE_LOG'])
calls = log.read_text().splitlines() if log.exists() else []
record = {'args': sys.argv[1:]}
for arg in sys.argv[1:]:
    if arg.startswith('Dir::Etc::sourceparts='):
        parts = Path(arg.split('=', 1)[1])
        record['sources'] = {p.name: p.read_text() for p in parts.iterdir()}
with log.open('a') as output:
    output.write(json.dumps(record) + '\\n')
statuses = json.loads(os.environ['FAKE_STATUSES'])
sys.exit(statuses[len(calls)] if len(calls) < len(statuses) else 99)
""")

    def command(self, name, contents):
        path = self.bin / name
        path.write_text(contents)
        path.chmod(0o755)

    def run_installer(self, statuses, architecture="amd64", packages=("musl-tools", "libcap-ng-dev")):
        env = {**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}",
               "FAKE_LOG": str(self.log), "FAKE_SOURCES": str(self.sources),
               "FAKE_STATUSES": json.dumps(statuses), "FAKE_ARCH": architecture}
        result = subprocess.run(["bash", str(self.installer), *packages], cwd=self.root,
                                env=env, capture_output=True, text=True, timeout=15)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        return result, calls

    def assert_fallback(self, calls, architecture="amd64"):
        for call in calls:
            self.assertTrue(any(arg.startswith("Dir::State::lists=") for arg in call["args"]))
            self.assertIn(fallback.MIRRORS[architecture], call["sources"]["ubuntu.sources"])
            self.assertIn("Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg", call["sources"]["ubuntu.sources"])
            self.assertNotIn("--allow-unauthenticated", call["args"])
            self.assertNotIn("--allow-downgrades", call["args"])

    def test_healthy_primary_never_uses_fallback(self):
        result, calls = self.run_installer([0, 0])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 2)
        self.assertIn("APT::Update::Error-Mode=any", calls[0]["args"])
        self.assertNotIn("sources", calls[1])

    def test_transient_primary_failure_retries_without_fallback(self):
        result, calls = self.run_installer([100, 0, 0])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 3)
        self.assertTrue(all("sources" not in call for call in calls))

    def test_failed_update_uses_fallback_without_installing_stale_primary(self):
        result, calls = self.run_installer([100, 100, 0, 0])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 4)
        self.assertTrue(all("update" in call["args"] for call in calls[:3]))
        self.assert_fallback(calls[2:])
        self.assertIn("APT::Update::Error-Mode=any", calls[2]["args"])
        self.assertIn("Using Ubuntu fallback mirror", result.stdout)

    def test_failed_package_download_refreshes_fallback_indexes(self):
        result, calls = self.run_installer([0, 100, 100, 0, 0])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 5)
        self.assertIn("update", calls[3]["args"])
        self.assert_fallback(calls[3:])

    def test_timeout_uses_same_bounded_fallback(self):
        result, calls = self.run_installer([124, 124, 0, 0])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("exceeded 120s", result.stdout)
        self.assert_fallback(calls[2:])

    def test_bad_fallback_indexes_never_reach_install(self):
        result, calls = self.run_installer([100, 100, 100, 100])
        self.assertEqual(result.returncode, 100)
        self.assertEqual(len(calls), 4)
        self.assertTrue(all("install" not in call["args"] for call in calls))

    def test_failed_fallback_install_propagates_failure(self):
        result, calls = self.run_installer([100, 100, 0, 100, 100])
        self.assertEqual(result.returncode, 100)
        self.assertEqual(len(calls), 5)

    def test_arm_uses_ports_mirror(self):
        result, calls = self.run_installer([100, 100, 0, 0], architecture="arm64")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_fallback(calls[2:], "arm64")

    def test_missing_packages_fail_before_apt(self):
        result, calls = self.run_installer([], packages=())
        self.assertEqual(result.returncode, 2)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
