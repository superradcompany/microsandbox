"""VM-free contract tests for compatibility provisioning and qualification."""

import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import baseline
import prepare
import run as matrix
import verify_runtime


FIRMWARE = "libkrunfw.so.5.0.0"
COMMIT = "a" * 40
DIGEST = hashlib.sha256(b"runtime").hexdigest()


def archive_bytes(entries):
    """Build controlled archives, including entries extraction must reject."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data, kind in entries:
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind == tarfile.REGTYPE:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            else:
                info.linkname = "../../outside"
                archive.addfile(info)
    return buffer.getvalue()


def runtime_archive():
    return archive_bytes([("msb", b"runtime", tarfile.REGTYPE),
                          (FIRMWARE, b"firmware", tarfile.REGTYPE)])


def seed_catalog(home):
    database = home / "db/msb.db"
    database.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("CREATE TABLE IF NOT EXISTS seaql_migrations (version TEXT)")
        connection.execute("CREATE TABLE IF NOT EXISTS sandboxes (name TEXT)")
        if not connection.execute("SELECT count(*) FROM seaql_migrations").fetchone()[0]:
            connection.execute("INSERT INTO seaql_migrations VALUES ('released-schema')")


def valid_report():
    return {"status": "passed", "cases": [{"case": "exec", "status": "passed", "checks": ["guest exec"]}]}


def valid_evidence(digest=DIGEST, executable="/selected/msb"):
    return [json.dumps({"sandbox": "fixture", "runtimes": [
        {"pid": 123, "executable": executable, "sha256": digest}]})]


class BaselineTests(unittest.TestCase):
    def test_checksum_requires_one_exact_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            asset = Path(directory) / "asset.so"
            asset.write_bytes(b"asset")
            checksum = baseline.sha256(asset)
            baseline.verify(asset, f"{checksum} *asset.so\n")
            for invalid in ("", f"{checksum} other.so\n", f"{'0' * 64} asset.so\n",
                            f"{checksum} asset.so\n{checksum} asset.so\n"):
                with self.subTest(checksums=invalid), self.assertRaises(ValueError):
                    baseline.verify(asset, invalid)

    def test_unpack_only_copies_the_two_selected_regular_files(self):
        entries = [("msb", b"runtime", tarfile.REGTYPE),
                   (FIRMWARE, b"firmware", tarfile.REGTYPE),
                   ("../outside", b"escape", tarfile.REGTYPE),
                   ("ignored-link", b"", tarfile.SYMTYPE)]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle, destination = root / "bundle.tar.gz", root / "runtime"
            destination.mkdir()
            bundle.write_bytes(archive_bytes(entries))
            self.assertEqual(baseline.unpack_runtime(bundle, destination), FIRMWARE)
            self.assertEqual({path.name for path in destination.iterdir()}, {"msb", FIRMWARE})
            self.assertFalse((root / "outside").exists())
            self.assertEqual((destination / "msb").stat().st_mode & 0o777, 0o700)
            self.assertEqual((destination / FIRMWARE).stat().st_mode & 0o777, 0o600)

    def test_unpack_rejects_ambiguous_or_linked_runtime_files(self):
        regular = [("msb", b"runtime", tarfile.REGTYPE),
                   (FIRMWARE, b"firmware", tarfile.REGTYPE)]
        invalid = [regular + [regular[0]], regular + [regular[1]],
                   regular + [("libkrunfw.so.6.0.0", b"other", tarfile.REGTYPE)],
                   [("msb", b"", tarfile.SYMTYPE), regular[1]],
                   [regular[0], (FIRMWARE, b"", tarfile.LNKTYPE)], [regular[1]]]
        for entries in invalid:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "destination").mkdir()
                (root / "bundle.tar.gz").write_bytes(archive_bytes(entries))
                with self.assertRaises(ValueError):
                    baseline.unpack_runtime(root / "bundle.tar.gz", root / "destination")

    def resolve_fixture(self, directory, *, modern=True, duplicate=False, wrong_ruby=False):
        prefix = f"https://github.com/{baseline.REPOSITORY}/releases/download/v0.7.0/"
        assets = {baseline.BUNDLE: runtime_archive(), baseline.GO_FFI: b"ffi"}
        assets["checksums.sha256"] = "".join(
            f"{hashlib.sha256(content).hexdigest()} {name}\n" for name, content in assets.items()
        ).encode()
        release = {"tag_name": "v0.7.0", "draft": False, "prerelease": False,
                   "html_url": prefix.rstrip("/"), "assets": [
                       {"name": name, "browser_download_url": prefix + name} for name in assets]}
        if duplicate:
            release["assets"].append(dict(release["assets"][0]))
        urls = []

        def read_json(url):
            urls.append(url)
            if url.endswith("/releases/latest"):
                return release
            if "/git/ref/tags/" in url:
                return {"object": {"type": "tag", "sha": "b" * 40}}
            if "/git/tags/" in url:
                return {"object": {"type": "commit", "sha": COMMIT}}
            if url.startswith("https://rubygems.org/"):
                return [{"number": "0.7.1" if wrong_ruby else "0.7.0"}] if modern else [{"number": "0.1.0"}]
            raise AssertionError(f"unexpected request: {url}")

        with mock.patch.object(baseline, "read_json", side_effect=read_json), \
                mock.patch.object(baseline, "request", side_effect=lambda url: io.BytesIO(assets[url.rsplit("/", 1)[1]])), \
                contextlib.redirect_stdout(io.StringIO()):
            baseline.resolve(Path(directory) / "baseline")
        return json.loads((Path(directory) / "baseline/baseline.json").read_text()), urls

    def test_resolution_pins_tag_commit_and_download_hashes_once(self):
        with tempfile.TemporaryDirectory() as directory:
            record, urls = self.resolve_fixture(directory)
            self.assertEqual(record["tag"], "v0.7.0")
            self.assertEqual(record["commit"], COMMIT)
            self.assertEqual(record["hashes"]["msb"], DIGEST)
            self.assertEqual(sum(url.endswith("/releases/latest") for url in urls), 1)
            self.assertTrue(record["ruby_released"])

    def test_missing_matching_modern_ruby_release_is_an_error(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, "Ruby"):
            self.resolve_fixture(directory, wrong_ruby=True)

    def test_legacy_only_ruby_is_explicitly_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            record, _ = self.resolve_fixture(directory, modern=False)
            self.assertFalse(record["ruby_released"])

    def test_duplicate_release_asset_names_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
            self.resolve_fixture(directory, duplicate=True)


class EnvironmentTests(unittest.TestCase):
    def test_explicit_environment_replaces_ambient_runtime_and_language_settings(self):
        ambient = {"PATH": "/usr/bin", "MSB_HOME": "/ambient", "MSB_PATH": "/ambient/msb",
                   "MSB_PROFILE": "cloud", "MICROSANDBOX_FFI_PATH": "/wrong.so", "PYTHONPATH": "/wrong",
                   "PYTHONHOME": "/wrong", "RUBYOPT": "-rwrong", "GEM_HOME": "/wrong", "GEM_PATH": "/wrong",
                   "NODE_OPTIONS": "--require wrong", "NODE_PATH": "/wrong", "NAPI_RS_NATIVE_LIBRARY_PATH": "/wrong.node",
                   "LD_PRELOAD": "/wrong.so",
                   "LD_LIBRARY_PATH": "/wrong", "UNRELATED": "retained"}
        with mock.patch.dict(os.environ, ambient, clear=True):
            env = matrix.environment(Path("/isolated"), Path("/selected/msb"), Path("/selected/lib/fw"), True)
        self.assertEqual(env["MSB_HOME"], "/isolated")
        self.assertEqual(env["MSB_PATH"], "/selected/msb")
        self.assertEqual(env["MSB_BACKEND"], "local")
        self.assertEqual(env["LD_LIBRARY_PATH"], "/selected/lib")
        self.assertEqual(env["PATH"], "/isolated/bin:/usr/bin")
        self.assertEqual(env["UNRELATED"], "retained")
        for key in ("MSB_PROFILE", "MICROSANDBOX_FFI_PATH", "PYTHONPATH", "PYTHONHOME", "RUBYOPT",
                    "GEM_HOME", "GEM_PATH", "NODE_OPTIONS", "NODE_PATH", "NAPI_RS_NATIVE_LIBRARY_PATH", "LD_PRELOAD"):
            self.assertNotIn(key, env)

    def test_installed_home_does_not_set_half_an_explicit_runtime_pair(self):
        with mock.patch.dict(os.environ, {"PATH": "/usr/bin", "MSB_PATH": "/ambient",
                                          "MSB_LIBKRUNFW_PATH": "/ambient.so"}, clear=True):
            env = matrix.environment(Path("/isolated"), Path("/selected/msb"), Path("/isolated/lib/fw"), False)
        self.assertNotIn("MSB_PATH", env)
        self.assertNotIn("MSB_LIBKRUNFW_PATH", env)


class RuntimeProvenanceTests(unittest.TestCase):
    def add_process(self, proc, pid, *, home="/fixture", executable=b"runtime", command=b"machine",
                    sandbox="fixture"):
        entry = proc / str(pid)
        entry.mkdir()
        (entry / "environ").write_bytes(f"MSB_HOME={home}\0PATH=/usr/bin\0".encode())
        (entry / "cmdline").write_bytes(b"msb\0" + command + b"\0--name\0" + os.fsencode(sandbox) + b"\0")
        (entry / "exe").write_bytes(executable)
        return entry

    def test_only_owned_machine_processes_supply_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            self.add_process(proc, 1)
            self.add_process(proc, 2, home="/another", executable=b"different")
            self.add_process(proc, 3, command=b"list", executable=b"different")
            self.add_process(proc, 4, sandbox="control")
            (proc / "self").mkdir()
            result = verify_runtime.verify("/fixture", DIGEST, "fixture", proc)
            self.assertEqual([entry["pid"] for entry in result], [1])
            self.assertEqual(result[0]["sha256"], DIGEST)

    def test_wrong_owned_runtime_fails_even_when_another_one_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            self.add_process(proc, 1)
            self.add_process(proc, 2, executable=b"bundled-wrong-runtime", sandbox="control")
            with self.assertRaisesRegex(RuntimeError, "unexpected runtime"):
                verify_runtime.verify("/fixture", DIGEST, "fixture", proc)

    def test_control_vm_cannot_substitute_for_missing_requested_sandbox(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            self.add_process(proc, 1, sandbox="control")
            self.add_process(proc, 2, sandbox="fixture-other")
            with self.assertRaisesRegex(RuntimeError, "no live VM for sandbox 'fixture'"):
                verify_runtime.verify("/fixture", DIGEST, "fixture", proc)

    def test_requested_name_must_be_the_unique_name_option(self):
        invalid = (b"msb\0machine\0--sandbox-id\0fixture\0",
                   b"msb\0machine\0--name\0control\0--sandbox-id\0fixture\0",
                   b"msb\0machine\0--name\0fixture\0--name\0control\0")
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            entry = self.add_process(proc, 1)
            for args in invalid:
                with self.subTest(args=args), self.assertRaisesRegex(RuntimeError, "no live VM"):
                    (entry / "cmdline").write_bytes(args)
                    verify_runtime.verify("/fixture", DIGEST, "fixture", proc)

    def test_restore_flags_before_requested_name_are_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            entry = self.add_process(proc, 1)
            (entry / "cmdline").write_bytes(
                b"msb\0machine\0--restore\0--name\0fixture\0--sandbox-id\0restored-id\0")
            result = verify_runtime.verify("/fixture", DIGEST, "fixture", proc)
            self.assertEqual([entry["pid"] for entry in result], [1])

    def test_missing_or_exited_runtime_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            self.add_process(proc, 1, home="/other")
            (proc / "2").mkdir()
            with self.assertRaisesRegex(RuntimeError, "no live VM"):
                verify_runtime.verify("/fixture", DIGEST, "fixture", proc)


class ReportTests(unittest.TestCase):
    def test_structured_pass_and_live_evidence_are_accepted(self):
        matrix.validate_report(valid_report(), valid_evidence())

    def test_incomplete_failed_skipped_or_empty_coverage_is_rejected(self):
        invalid = [{}, {"status": "passed"}, {"status": "passed", "cases": []},
                   {"status": "failed", "cases": [{"case": "exec", "status": "passed"}]},
                   {"status": "passed", "cases": [{"case": "exec", "status": "failed"}]},
                   {"status": "passed", "cases": [{"case": "exec", "status": "skipped"}]},
                   {"status": "passed", "cases": [{"case": "exec"}]},
                   {"status": "passed", "cases": ["skipped"]},
                   {"status": "passed", "cases": [{"case": "exec", "status": "passed", "checks": []}]},
                   {"status": "passed", "passed": []},
                   {"status": "passed", "passed": [None]}]
        for report in invalid:
            with self.subTest(report=report), self.assertRaises(ValueError):
                matrix.validate_report(report, valid_evidence())

    def test_missing_or_malformed_runtime_evidence_is_rejected(self):
        for evidence in ([], ["garbage"], ["{}"], [json.dumps({"runtimes": []})]):
            with self.subTest(evidence=evidence), self.assertRaises(ValueError):
                matrix.validate_report(valid_report(), evidence)

    def test_flat_go_and_ruby_checks_require_nonempty_passed_items(self):
        matrix.validate_report({"status": "passed", "passed": ["guest exec"]}, valid_evidence())

    def test_evidence_must_match_the_selected_runtime_hash(self):
        with self.assertRaises(ValueError):
            matrix.validate_report(valid_report(), valid_evidence("0" * 64), expected_hash=DIGEST)

    def test_incomplete_runtime_identity_is_rejected(self):
        for runtime in ({"pid": 0, "sha256": DIGEST}, {"pid": 12, "sha256": "bad"}, {"sha256": DIGEST}):
            evidence = [json.dumps({"sandbox": "fixture", "runtimes": [runtime]})]
            with self.subTest(runtime=runtime), self.assertRaises(ValueError):
                matrix.validate_report(valid_report(), evidence)


class ManifestAndProcessTests(unittest.TestCase):
    def test_missing_required_generations_and_empty_inventories_fail(self):
        for sdks in ({}, {"candidate": {"files": {"scenario": DIGEST}}},
                     {"candidate": {"files": {}}, "released": {"files": {"scenario": DIGEST}}}):
            manifest = {"language": "rust", "baseline": {"ruby_released": False}, "sdks": sdks}
            with self.subTest(sdks=sdks), self.assertRaises(ValueError):
                matrix.validate_manifest(manifest)

    def test_ruby_publication_exception_requires_an_explicit_reason(self):
        manifest = {"language": "ruby", "baseline": {"ruby_released": False},
                    "sdks": {"candidate": {"files": {"fixture.gem": DIGEST}}}}
        with self.assertRaises(ValueError):
            matrix.validate_manifest(manifest)
        manifest["unavailable"] = "Modern Ruby SDK has not been published."
        matrix.validate_manifest(manifest)

    def test_nonzero_subprocess_is_a_failure(self):
        process = mock.MagicMock()
        process.__enter__.return_value = process
        process.wait.return_value = 7
        with mock.patch.object(matrix.subprocess, "Popen", return_value=process), \
                self.assertRaises(subprocess.CalledProcessError):
            matrix.run(["fixture"], {}, Path("/tmp"), io.StringIO())

    def test_timeout_reaps_the_entire_process_group_and_preserves_timeout(self):
        process = mock.MagicMock(pid=123)
        process.__enter__.return_value = process
        process.wait.side_effect = [subprocess.TimeoutExpired("fixture", 1),
                                    subprocess.TimeoutExpired("fixture", 5), None]
        with mock.patch.object(matrix.subprocess, "Popen", return_value=process), \
                mock.patch.object(matrix.os, "killpg") as killpg, \
                self.assertRaises(subprocess.TimeoutExpired):
            matrix.run(["fixture"], {}, Path("/tmp"), io.StringIO(), timeout=1)
        self.assertEqual(killpg.call_args_list, [mock.call(123, matrix.signal.SIGTERM),
                                                mock.call(123, matrix.signal.SIGKILL)])

class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.payload, self.release_root, self.current = [self.root / name for name in ("payload", "baseline", "current")]
        for directory in (self.payload, self.release_root, self.current):
            directory.mkdir()
        for directory in (self.release_root, self.current):
            (directory / "msb").write_bytes(b"runtime")
            (directory / FIRMWARE).write_bytes(b"firmware")
        self.release = {"version": "0.7.0", "commit": "b" * 40, "ruby_released": False,
                        "firmware": FIRMWARE, "hashes": {"msb": DIGEST, FIRMWARE: baseline.sha256(self.release_root / FIRMWARE)}}
        (self.release_root / "baseline.json").write_text(json.dumps(self.release))
        self.manifest = {"language": "rust", "candidate_commit": COMMIT, "baseline": self.release, "sdks": {}}
        for generation in ("candidate", "released"):
            directory = self.payload / generation
            directory.mkdir()
            (directory / "scenario").write_bytes(b"fixture")
            self.manifest["sdks"][generation] = {"version": "0.7.0", "generation": generation,
                                                "files": {"scenario": baseline.sha256(directory / "scenario")}}
        self.args = argparse.Namespace(payload=self.payload, baseline=self.release_root, runtime=self.current,
                                       output=self.root / "results", commit=COMMIT, image="fixture-image")
        self.write_manifest()

    def write_manifest(self):
        (self.payload / "manifest.json").write_text(json.dumps(self.manifest))

    def run_fixture(self, *, fail=False, cleanup_fail=False, omit_report=False, mutate_schema=False):
        def allocate(**_kwargs):
            root = self.root / f"fixture-{len(list(self.root.glob('fixture-*')))}"
            root.mkdir()
            return str(root)

        def command(command, env, cwd, log, *args, **kwargs):
            home = Path(env["MSB_HOME"])
            if command[0] != "scenario-command":
                seed_catalog(home)
                return
            if fail:
                raise RuntimeError("original scenario failure")
            if mutate_schema and (home / "db/msb.db").exists():
                with contextlib.closing(sqlite3.connect(home / "db/msb.db")) as connection, connection:
                    connection.execute("ALTER TABLE sandboxes ADD COLUMN unexpected TEXT")
            if not omit_report:
                Path(env["MSB_COMPAT_REPORT"]).write_text(json.dumps(valid_report()))
            Path(env["MSB_COMPAT_RUNTIME_REPORT"]).write_text("\n".join(valid_evidence(
                env["MSB_COMPAT_RUNTIME_SHA256"], env["MSB_COMPAT_CLI"])) + "\n")

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(matrix.platform, "system", return_value="Linux"))
            stack.enter_context(mock.patch.object(matrix.platform, "machine", return_value="x86_64"))
            stack.enter_context(mock.patch.object(matrix.os, "access", return_value=True))
            stack.enter_context(mock.patch.object(matrix.tempfile, "mkdtemp", side_effect=allocate))
            stack.enter_context(mock.patch.object(matrix, "installed_sdk", return_value=(["scenario-command"], {}, self.payload)))
            stack.enter_context(mock.patch.object(matrix, "run", side_effect=command))
            stack.enter_context(mock.patch.object(matrix, "cleanup", side_effect=RuntimeError("cleanup failure") if cleanup_fail else None))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            matrix.execute(self.args)

    def test_complete_matrix_has_both_directions_controls_and_home_modes(self):
        self.run_fixture()
        report = json.loads((self.args.output / "results.json").read_text())
        self.assertEqual(len(report["cases"]), 8)
        self.assertTrue(all(case["status"] == "passed" for case in report["cases"]))
        self.assertFalse(list(self.root.glob("fixture-*")))

    def test_missing_kvm_is_an_error_not_a_skip(self):
        with mock.patch.object(matrix.platform, "system", return_value="Linux"), \
                mock.patch.object(matrix.platform, "machine", return_value="x86_64"), \
                mock.patch.object(matrix.os, "access", return_value=False), \
                self.assertRaisesRegex(RuntimeError, "cannot be skipped"):
            matrix.execute(self.args)

    def test_candidate_commit_and_baseline_manifest_are_bound(self):
        for field in ("candidate_commit", "baseline"):
            with self.subTest(field=field):
                original = self.manifest[field]
                self.manifest[field] = "wrong"
                self.write_manifest()
                self.args.output = self.root / f"mismatch-{field}"
                with self.assertRaisesRegex(ValueError, "do not match"):
                    self.run_fixture()
                self.manifest[field] = original

    def test_tampered_runtime_and_sdk_payloads_fail_before_scenarios(self):
        for target in (self.release_root / "msb", self.payload / "candidate/scenario"):
            with self.subTest(target=target):
                original = target.read_bytes()
                target.write_bytes(b"tampered")
                self.args.output = self.root / f"tampered-{target.parent.name}"
                with self.assertRaisesRegex(ValueError, "artifact changed"):
                    self.run_fixture()
                target.write_bytes(original)

    def test_ruby_without_a_published_sdk_still_requires_candidate_coverage(self):
        self.manifest.update(language="ruby", sdks={})
        self.write_manifest()
        with self.assertRaises((ValueError, RuntimeError)):
            self.run_fixture()

    def test_absent_report_is_a_failed_matrix_cell(self):
        with self.assertRaises(RuntimeError):
            self.run_fixture(omit_report=True)
        report = json.loads((self.args.output / "results.json").read_text())
        self.assertTrue(all(case["status"] == "failed" for case in report["cases"]))

    def test_cleanup_preserves_primary_failure_and_diagnostic_home(self):
        with self.assertRaises(RuntimeError):
            self.run_fixture(fail=True, cleanup_fail=True)
        report = json.loads((self.args.output / "results.json").read_text())
        for case in report["cases"]:
            self.assertEqual(case["status"], "failed")
            self.assertIn("original scenario failure", case["error"])
            self.assertIn("cleanup failure", case["cleanup_error"])
            self.assertTrue(Path(case["home"]).exists())

    def test_existing_catalog_schema_mutation_fails_even_if_fixture_reports_pass(self):
        with self.assertRaises(RuntimeError):
            self.run_fixture(mutate_schema=True)
        report = json.loads((self.args.output / "results.json").read_text())
        existing = [case for case in report["cases"] if case["case"].endswith("installed-existing")]
        self.assertEqual(len(existing), 4)
        self.assertTrue(all(case["status"] == "failed" and "catalog schema" in case["error"] for case in existing))


class PreparationTests(unittest.TestCase):
    def test_node_manifest_binds_javascript_and_native_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, released, artifacts = [root / name for name in ("source", "baseline", "artifacts")]
            for item in (source, released, artifacts):
                item.mkdir()
            (source / "Cargo.toml").write_text('[workspace.package]\nversion = "0.7.0"\n')
            (released / "baseline.json").write_text(json.dumps({"version": "0.7.0", "ruby_released": False}))
            files = {"sdk/node-ts/native/microsandbox.linux-x64-gnu.node": b"native",
                     "sdk/node-ts/dist/index.js": b"exports.fixture = true;",
                     "sdk/node-ts/package.json": b'{"name":"microsandbox","version":"0.7.0"}',
                     "packages/microsandbox-types/typescript/index.js": b"exports.types = true;",
                     "scripts/compatibility/scenarios/node.cjs": b"console.log('fixture');"}
            for name, data in files.items():
                destination = source / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
            args = argparse.Namespace(workspace=source, baseline=released, artifacts=artifacts,
                                      output=root / "output", language="node")

            def install(_command, cwd, env=None):
                native = cwd / "node_modules/@superradcompany/microsandbox-linux-x64-gnu/microsandbox.linux-x64-gnu.node"
                native.parent.mkdir(parents=True)
                native.write_bytes(b"released-native")
                package = cwd / "node_modules/microsandbox"
                package.mkdir()
                (package / "index.js").write_text("exports.released = true;")
                (package / "package.json").write_text('{"name":"microsandbox","version":"0.7.0"}')

            with mock.patch.object(prepare, "run", side_effect=install), \
                    mock.patch.object(prepare.subprocess, "check_output", return_value=COMMIT):
                prepare.prepare(args)
            manifest = json.loads((args.output / "manifest.json").read_text())
            for generation, record in manifest["sdks"].items():
                self.assertTrue(record["files"], f"{generation} Node payload has no artifact hashes")
                self.assertTrue(any(name.endswith(".node") for name in record["files"]))
                self.assertTrue(any(name.endswith(".js") for name in record["files"]))
                for name, digest in record["files"].items():
                    self.assertEqual(digest, baseline.sha256(args.output / generation / name))


if __name__ == "__main__":
    unittest.main()
