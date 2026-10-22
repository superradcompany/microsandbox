#!/usr/bin/env python3
"""Run snapshot publication/reader fixtures against the pinned released 0.7.8 CLI."""

import argparse
from contextlib import suppress
import hashlib
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import tempfile
import urllib.request


VERSION = "0.7.8"
RELEASE = f"https://github.com/superradcompany/microsandbox/releases/download/v{VERSION}"
PREFIX = "backend::local::snapshot::"
TESTS = (
    PREFIX + "archive::writer_tests::released_reader_accepts_historical_target_and_refuses_canonical_names",
    PREFIX + "group::generation::tests::legacy_cli_observes_complete_generation_after_publisher_crash",
    PREFIX + "group::generation::tests::released_reader_sees_atomic_production_publication_after_crash",
    PREFIX + "group::removal::tests::released_reader_observes_complete_group_after_removal_crash",
    PREFIX + "group::removal::tests::released_reader_observes_whole_group_removal_crash",
)


def release_asset():
    systems = {"Darwin": "darwin", "Linux": "linux"}
    machines = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64"}
    try:
        return f"msb-{systems[platform.system()]}-{machines[platform.machine()]}"
    except KeyError as error:
        raise ValueError("this fixture supports macOS and Linux only") from error


def verify_download(binary, checksums, asset):
    expected = [fields[0] for line in checksums.splitlines()
                if len(fields := line.split()) == 2 and fields[1].lstrip("*") == asset]
    with binary.open("rb") as source:
        actual = hashlib.file_digest(source, "sha256").hexdigest()
    # Never make downloaded code executable on a missing/ambiguous checksum.
    if expected != [actual]:
        raise ValueError("release checksum missing, duplicated, or mismatched")
    binary.chmod(0o700)


def fixture_environment(root, legacy):
    # A historical reader must not inherit candidate runtime/config selection or
    # fault injection. Individual Rust cases create separate recipient catalogs.
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("MSB_") and key not in ("LD_PRELOAD", "DYLD_INSERT_LIBRARIES")}
    env.update(MSB_HOME=str(root / "home"), MSB_BACKEND="local",
               MSB_CONFIG_PATH=str(root / "missing.json"),
               MSB_ARCHIVE_LEGACY_CLI=str(legacy), MSB_TEST_LEGACY_CLI=str(legacy), NO_COLOR="1")
    return env


def run_test(command, env, root, log):
    # Crash tests launch publisher subprocesses. Reap the entire private process
    # group on timeout/interruption before deleting their temporary catalogs.
    with subprocess.Popen(command, env=env, cwd=root, stdout=log,
                          stderr=subprocess.STDOUT, start_new_session=True) as child:
        try:
            return child.wait(timeout=180)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            with suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # A supervisor ignoring SIGTERM needs the SIGKILL fallback below.
                pass
            # The supervisor can exit before a publisher that ignores SIGTERM.
            # Kill survivors in our owned group even when the supervisor exited.
            with suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGKILL)
            child.wait()
            raise


def execute(args):
    args.output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="msb-sc-") as temporary:
        root = Path(temporary)
        legacy = args.legacy_binary
        if legacy is None:
            asset = release_asset()
            for name in (asset, "checksums.sha256"):
                request = urllib.request.Request(f"{RELEASE}/{name}", headers={"User-Agent": "msb-snapshot-ci"})
                with urllib.request.urlopen(request, timeout=60) as source, (root / name).open("wb") as target:
                    shutil.copyfileobj(source, target)
            legacy = root / asset
            verify_download(legacy, (root / "checksums.sha256").read_text(), asset)
        env = fixture_environment(root, legacy)
        version = subprocess.check_output([str(legacy), "--version"], env=env, cwd=root,
                                          text=True, timeout=30).strip()
        if version.split() != ["msb", VERSION]:
            raise ValueError(f"expected msb {VERSION}, got {version!r}")
        (args.output / "setup.log").write_text(f"reader={legacy}\nversion={version}\n")
        if args.test_binary:
            listing = subprocess.check_output([str(args.test_binary), "--list"], env=env,
                                              text=True, timeout=30).splitlines()
            missing = [test for test in TESTS if f"{test}: test" not in listing]
            if missing:
                raise ValueError(f"candidate test binary lacks required cases: {missing}")
        failures = []
        # Run every contract even after one fails, retaining individual diagnostics.
        for test in TESTS:
            if args.test_binary:
                command = [str(args.test_binary), "--ignored", "--exact", test, "--nocapture"]
            else:
                command = ["cargo-nextest", "nextest", "run", "--archive-file", str(args.archive),
                           "--workspace-remap", str(args.workspace), "--run-ignored=only",
                           "--test-threads", "1", "--no-tests", "fail", "-E", f"test(={test})"]
            with (args.output / f"{test.rsplit('::', 1)[1]}.log").open("w") as log:
                try:
                    returncode = run_test(command, env, root, log)
                except subprocess.TimeoutExpired:
                    log.write("fixture timed out; publisher process group reaped\n")
                    returncode = 124
            print(f"{test}: exit {returncode}", flush=True)
            if returncode:
                failures.append(test)
        if failures:
            raise RuntimeError(f"snapshot compatibility cases failed: {failures}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    runner = parser.add_mutually_exclusive_group(required=True)
    runner.add_argument("--archive", type=Path)
    runner.add_argument("--test-binary", type=Path)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--legacy-binary", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.archive and not args.workspace:
        parser.error("--archive requires --workspace")
    for name in ("archive", "workspace", "test_binary", "legacy_binary"):
        if value := getattr(args, name):
            setattr(args, name, value.resolve(strict=True))
    args.output = args.output.resolve()
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt("interrupted; disposing snapshot fixture processes")

    signal.signal(signal.SIGTERM, interrupted)
    execute(args)


if __name__ == "__main__":
    main()
