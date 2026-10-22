#!/usr/bin/env python3
"""Check transferred historical archives, architecture admission and cache conflicts.

The input directory contains disk-060, disk-078 and full-078 subdirectories,
each with the original producer fixture.json and its unchanged standalone archive.
Only the selected archive is transferred; the full producer inventory is retained
as provenance rather than pretending that every original payload was transferred.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import platform
import shlex
import tempfile


spec = importlib.util.spec_from_file_location(
    "historical_installed", Path(__file__).with_name("historical-installed.py"))
installed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installed)
history = installed.history


def transferred_archive(directory, filename):
    fixture = json.loads((directory / "fixture.json").read_text())
    path = directory / filename
    expected = fixture["originals"][filename]
    if fixture["status"] != "produced":
        raise RuntimeError("selected producer fixture did not complete")
    if path.stat().st_size != expected["bytes"] or history.digest(path) != expected["sha256"]:
        raise RuntimeError("transferred archive does not match its producer inventory")
    return path, fixture


def architecture(value):
    return {"arm64": "aarch64", "amd64": "x86_64"}.get(value.lower(), value.lower())


def architecture_refusal(text, source, destination):
    # An arbitrary failure (missing image, parsing, guest exec) is not safe admission.
    return (f"checkpoint architecture {source} cannot restore on {destination}" in text
            or "checkpoint architecture cannot restore on this host" in text)


def reorder_cache_metadata(home):
    paths = sorted((home / "cache" / "manifests").glob("*.json"))
    if not paths:
        raise RuntimeError("fixture did not install image metadata")
    for path in paths:
        original = path.read_bytes()
        value = json.loads(original)
        # Change representation only, including nested maps. Raw OCI strings stay exact
        # because their digests identify their original serialization.
        encoded = json.dumps(value, sort_keys=True, indent=3).encode() + b"\n"
        if encoded == original:
            raise RuntimeError("metadata reorder did not change bytes")
        path.write_bytes(encoded)
    return {str(path.relative_to(home)): history.digest(path) for path in paths}


def local_vmdk_extents(home):
    paths = sorted((home / "cache" / "vmdk").glob("*.vmdk"))
    extents = []
    for path in paths:
        for line in path.read_text().splitlines():
            fields = shlex.split(line)
            if fields and fields[0] == "RW":
                if len(fields) != 5 or fields[2] != "FLAT":
                    raise RuntimeError("unexpected VMDK extent declaration")
                extent = Path(fields[3]).resolve()
                if not extent.is_relative_to(home / "cache") or not extent.is_file():
                    raise RuntimeError("imported VMDK still references an unavailable or foreign extent")
                extents.append(str(extent.relative_to(home)))
    if not extents:
        raise RuntimeError("fixture did not exercise VMDK extent rewriting")
    return extents


def qualify(args):
    args.output.mkdir(parents=True, exist_ok=False)
    destination = architecture(platform.machine())
    report = {
        "destination_architecture": destination,
        "candidate_sha256": history.digest(args.candidate),
        "agent_sha256": history.digest(args.agent),
        "agent": history.agent_identity(args.agent),
        "firmware_sha256": history.digest(args.firmware),
        "harness_sha256": history.digest(Path(__file__)),
        "cases": [], "status": "running",
    }
    inputs = []
    try:
        for label, filename in (("disk-060", "fixture.msb"), ("disk-078", "fixture.msb"),
                                ("full-078", "cp1.msb")):
            path, fixture = transferred_archive(args.transferred / label, filename)
            source = architecture(fixture["architecture"])
            if source == destination:
                raise RuntimeError("cross-architecture fixture came from the destination architecture")
            inputs.append((path, history.digest(path)))
            home = Path(tempfile.mkdtemp(prefix="msb-hx-", dir=args.temp_root)).resolve()
            row = {"kind": label, "home": str(home), "source_architecture": source,
                   "archive_sha256": history.digest(path), "status": "running"}
            runner = history.Runner(args.candidate, history.environment(
                args.candidate, args.firmware, home, args.agent), args.output / label)
            try:
                runner.run("load", "snapshot", "load", "transferred", "--file", path)
                state = installed.group_state(home, "transferred")
                runner.run("inspect", "snapshot", "inspect", "transferred")
                runner.run("verify", "snapshot", "verify", "transferred", "--all")
                row["portable_import_inspect_verify"] = "passed"
                code = runner.run("create", "create", "--name", "cross-host",
                                  "--from-snapshot", "transferred", "--pull", "never", required=False)
                if code:
                    text = (runner.output / "create.stderr").read_text()
                    row["launch_error"] = text
                    if not architecture_refusal(text, source, destination):
                        raise RuntimeError("launch refused without a precise architecture diagnostic")
                    row["launch"] = "architecture-refused"
                else:
                    # Disk snapshots may boot a native agent while their saved binaries cannot
                    # execute. Reaching that agent is not evidence of a usable restored guest.
                    verify = history.VERIFY
                    if label == "full-078":
                        # cp1 is generation one of the real full-memory fixture.
                        # Disk contents alone would also pass after a cold boot.
                        verify += ("\ntest $(cat /dev/shm/history-generation) = 1; "
                                   "sha256sum -c /root/historical/ram-checksum\n")
                    code = runner.run("guest", "exec", "cross-host", "--", "sh", "-ec",
                                      verify, required=False)
                    row["launch"] = "guest-verified" if code == 0 else "guest-execution-failed"
                    if code:
                        raise RuntimeError("foreign disk was admitted but guest contents could not be verified")
                installed.require_unchanged(home, "transferred", state)
                row["status"] = "passed"
            except BaseException as error:
                row["status"], row["error"] = "failed", str(error)
                if not isinstance(error, Exception):
                    raise
            finally:
                try:
                    audit_cleanup(runner, row)
                finally:
                    report["cases"].append(row)
                    save_report(args.output, report)

        # Both archives use the same image reference but pin different platform content.
        # Refusing the incoming cache metadata must not disturb the existing group/guest.
        native = args.native_fixture / "originals" / "fixture.msb"
        native_fixture = json.loads((args.native_fixture / "fixture.json").read_text())
        if native_fixture["status"] != "produced" or architecture(native_fixture["architecture"]) != destination:
            raise RuntimeError("native fixture has the wrong provenance")
        expected = native_fixture["originals"]["fixture.msb"]
        if history.digest(native) != expected["sha256"] or native.stat().st_size != expected["bytes"]:
            raise RuntimeError("native fixture changed")
        inputs.append((native, history.digest(native)))
        foreign, _ = transferred_archive(args.transferred / "disk-078", "fixture.msb")
        home = Path(tempfile.mkdtemp(prefix="msb-hx-", dir=args.temp_root)).resolve()
        runner = history.Runner(args.candidate, history.environment(
            args.candidate, args.firmware, home, args.agent), args.output / "cache-conflict")
        row = {"kind": "cache-conflict", "home": str(home), "status": "running"}
        try:
            runner.run("native-load", "snapshot", "load", "native", "--file", native)
            state = installed.group_state(home, "native")
            reordered = reorder_cache_metadata(home)
            runner.run("reordered-reimport", "snapshot", "load", "native", "--file", native)
            installed.require_unchanged(home, "native", state)
            if any(history.digest(home / path) != digest for path, digest in reordered.items()):
                raise RuntimeError("equivalent metadata was overwritten")
            row["reordered_metadata_preserved"] = True
            row["local_vmdk_extents"] = local_vmdk_extents(home)
            code = runner.run("foreign-load", "snapshot", "load", "foreign", "--file", foreign, required=False)
            text = (runner.output / "foreign-load.stderr").read_text()
            row["import_error"] = text
            if code == 0 or "cache target already exists with different content" not in text:
                raise RuntimeError("expected a precise image metadata conflict")
            if (home / "snapshots" / "foreign").exists():
                raise RuntimeError("rejected import published its group")
            installed.require_unchanged(home, "native", state)
            if any(history.digest(home / path) != digest for path, digest in reordered.items()):
                raise RuntimeError("failed foreign import changed existing image metadata")
            runner.run("native-verify", "snapshot", "verify", "native", "--all")
            runner.run("native-create", "create", "--name", "cross-host",
                       "--from-snapshot", "native", "--pull", "never")
            runner.run("native-guest", "exec", "cross-host", "--", "sh", "-ec", history.VERIFY)
            row["status"] = "passed"
        except BaseException as error:
            row["status"], row["error"] = "failed", str(error)
            if not isinstance(error, Exception):
                raise
        finally:
            try:
                audit_cleanup(runner, row)
            finally:
                report["cases"].append(row)
    except BaseException as error:
        report["error"] = str(error)
        raise
    finally:
        try:
            report["archives_unchanged"] = all(history.digest(path) == digest for path, digest in inputs)
        except Exception as error:
            report["archives_unchanged"], report["archives_error"] = False, str(error)
        report["status"] = ("passed" if len(report["cases"]) == 4
                            and all(row["status"] == "passed" for row in report["cases"])
                            and report["archives_unchanged"] and "error" not in report else "failed")
        save_report(args.output, report)
    if report["status"] != "passed":
        raise RuntimeError("cross-host qualification has failures; inspect report.json")


def audit_cleanup(runner, row):
    errors, interrupted = [], None
    sandboxes = None
    try:
        runner.run("before-cleanup", "list", "--format", "json")
        sandboxes = json.loads((runner.output / "before-cleanup.stdout").read_text())
        if not isinstance(sandboxes, list):
            raise RuntimeError("sandbox audit did not return a list")
        row["before_cleanup"] = sandboxes
    except BaseException as error:
        sandboxes = None
        errors.append(str(error))
        if not isinstance(error, Exception):
            interrupted = error
    # A failed audit is not evidence of absence. Always try the name this harness
    # owns when state is unknown, including a failed create with a residual row.
    if sandboxes is None or sandboxes:
        row["cleanup"] = {}
        try:
            history.cleanup(runner, "cross-host", "cross-host", row["cleanup"])
            if any(code != 0 for code in row["cleanup"].values()):
                raise RuntimeError("sandbox cleanup failed")
        except BaseException as error:
            errors.append(str(error))
            if not isinstance(error, Exception):
                interrupted = error
    try:
        runner.run("after-cleanup", "list", "--format", "json")
        if json.loads((runner.output / "after-cleanup.stdout").read_text()) != []:
            raise RuntimeError("sandbox catalog is not empty")
        row["catalog_empty"] = True
    except BaseException as error:
        errors.append(str(error))
        if not isinstance(error, Exception):
            interrupted = error
    if errors:
        row["status"], row["cleanup_error"] = "failed", "; ".join(errors)
    if interrupted is not None:
        raise interrupted


def save_report(output, report):
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")


def main():
    history.install_termination_handler()
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("transferred", "native-fixture", "candidate", "firmware", "agent", "output"):
        parser.add_argument("--" + option, type=Path, required=True)
    parser.add_argument("--temp-root", type=Path, default=Path("/tmp"))
    args = parser.parse_args()
    for key, value in vars(args).items():
        setattr(args, key, value.resolve())
    qualify(args)


if __name__ == "__main__":
    main()
