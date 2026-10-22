#!/usr/bin/env python3
"""Produce immutable released disk fixtures and check real candidate guest restores.

This is one cell of the historical matrix, not a claim that every migration or
release is qualified. Keep its JSON report and original artifacts with failures.
"""

import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile

import previous_release_upgrade as releases
from lifecycle_evidence import Runner, cleanup, digest, environment, install_termination_handler


VERSIONS = ("0.6.0", "0.6.6", "0.6.7", "0.6.18", "0.7.8")
SEED = """set -eu
mkdir -p /root/historical/many
printf 'microsandbox historical fixture\\n' > /root/historical/marker
head -c 4194304 /dev/urandom > /root/historical/payload
for i in $(seq 1 500); do printf 'file-%s\\n' "$i" > /root/historical/many/"$i"; done
ln /root/historical/payload /root/historical/hardlink
ln -s payload /root/historical/symlink
chmod 640 /root/historical/payload
cd /root/historical
sha256sum payload marker many/* > checksums
sync
"""
VERIFY = """set -eu
cd /root/historical
sha256sum -c checksums >/dev/null
test $(find many -type f | wc -l) = 500
test $(stat -c %i payload) = $(stat -c %i hardlink)
test $(readlink symlink) = payload
test $(stat -c %a payload) = 640
cat marker
"""


def inventory(root):
    """Hash originals without following a substituted symlink outside the fixture."""
    return {str(path.relative_to(root)): {"symlink": os.readlink(path)} if path.is_symlink()
            else {"bytes": path.stat().st_size, "sha256": digest(path)}
            for path in sorted(root.rglob("*")) if path.is_symlink() or path.is_file()}


def agent_identity(agent):
    """Identify the selected guest implementation independently of the CLI."""
    return ({"source": "explicit", "path": str(agent.resolve()), "sha256": digest(agent)}
            if agent else {"source": "embedded"})


def copy_artifact(source, destination):
    # Preserve sparse ext4 files; never hard-link a mutable migration input to an original.
    command = ["cp", "-cR"] if platform.system() == "Darwin" else ["cp", "-R", "--reflink=auto", "--sparse=always"]
    subprocess.run([*command, str(source), str(destination)], check=True)



def verify_descriptor_preservation(original, working):
    """An automatic upgrade must retain the exact historical descriptor bytes."""
    names = [name for name in ("manifest.json", "snapshot.json") if (original / name).is_file()]
    if len(names) != 1:
        raise RuntimeError("fixture must have exactly one historical descriptor")
    name = names[0]
    retained = ".manifest.json.legacy" if name == "manifest.json" else name
    if (working / retained).read_bytes() != (original / name).read_bytes():
        raise RuntimeError("migration changed or lost the original descriptor bytes")
    return retained


def finish_case(runner, prefix, sandbox, row, report, output, attempted=True):
    """Retain cleanup and case evidence even when termination arrives in cleanup."""
    row["cleanup"] = {}
    try:
        if attempted:
            cleanup(runner, prefix, sandbox, row["cleanup"])
        if any(value != 0 for value in row["cleanup"].values()):
            row["status"], row["cleanup_error"] = "failed", "candidate cleanup did not complete"
    except BaseException as error:
        row["status"], row["cleanup_error"] = "failed", str(error)
        raise
    finally:
        report["cases"].append(row)
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")


def finish_originals(report, originals, before, output):
    """Keep the primary failure and a readable report if the final audit also fails."""
    try:
        report["originals_unchanged"] = inventory(originals) == before
    except Exception as error:
        report["originals_unchanged"], report["originals_error"] = False, str(error)
    finally:
        if not report["originals_unchanged"]:
            report["status"] = "failed"
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")


def produce(args):
    args.output.mkdir(parents=True, exist_ok=False)
    bundle = args.release_dir / releases.platform_asset()
    releases.unpack_release(bundle, (args.release_dir / "checksums.sha256").read_text(), args.release_dir)
    binary = args.release_dir / "msb"
    firmware = args.release_dir / releases.firmware_name()
    # Preserve the isolated home for diagnosis; only its own source sandbox is removed.
    home = Path(tempfile.mkdtemp(prefix="msb-hp-", dir="/tmp"))
    runner = Runner(binary, environment(binary, firmware, home), args.output / "producer")
    originals = args.output / "originals"
    originals.mkdir()
    report = {"producer_version": args.version, "harness_sha256": digest(Path(__file__)),
              "platform": platform.platform(),
              "architecture": platform.machine(), "binary_sha256": digest(binary),
              "firmware_sha256": digest(firmware), "bundle_sha256": digest(bundle),
              "home": str(home), "image_requested": args.image, "status": "running"}
    try:
        runner.run("version", "--version")
        version = (runner.output / "version.stdout").read_text().strip()
        if version.split() != ["msb", args.version]:
            raise RuntimeError(f"expected msb {args.version}, got {version!r}")
        disk_flag = "--root-disk" if args.version == "0.7.8" else "--oci-upper-size"
        runner.run("create", "create", args.image, "--name", "historical-source",
                   "--memory", "256M", disk_flag, "256M", "--max-duration", "20m")
        runner.run("seed", "exec", "historical-source", "--", "sh", "-ec", SEED)
        runner.run("source-check", "exec", "historical-source", "--", "sh", "-ec", VERIFY)
        runner.run("stop", "stop", "historical-source")
        source_flag = "--sandbox" if args.version == "0.7.8" else "--from"
        runner.run("capture", "snapshot", "create", "fixture", source_flag,
                   "historical-source", "--integrity")
        descriptors = [path for path in (home / "snapshots").rglob("*.json")
                       if path.name in ("manifest.json", "snapshot.json")]
        if len(descriptors) != 1:
            raise RuntimeError(f"expected one captured descriptor, found {descriptors}")
        descriptor = descriptors[0]
        metadata = json.loads(descriptor.read_text())
        report["descriptor"] = metadata
        report["descriptor_filename"] = descriptor.name
        copy_artifact(descriptor.parent, originals / "artifact")
        export = "export" if args.version in ("0.6.0", "0.6.6") else "save"
        runner.run("archive", "snapshot", export, descriptor.parent,
                   originals / "fixture.msb", "--with-image", "--with-parents")
        runner.run("delete-source", "rm", "historical-source")
        report["originals"] = inventory(originals)
        report["status"] = "produced"
    except BaseException as error:
        report["status"], report["error"] = "failed", str(error)
        raise
    finally:
        # The successful path already removed its source. Failed production must
        # attempt both operations without losing its original error or report.
        report["cleanup"] = {}
        try:
            if report["status"] != "produced":
                cleanup(runner, "producer", "historical-source", report["cleanup"])
        finally:
            (args.output / "fixture.json").write_text(json.dumps(report, indent=2) + "\n")


def qualify(args):
    args.output.mkdir(parents=True, exist_ok=False)
    fixture = json.loads((args.fixture / "fixture.json").read_text())
    originals = args.fixture / "originals"
    before = inventory(originals)
    if fixture.get("status") != "produced" or before != fixture["originals"]:
        raise RuntimeError("producer fixture is incomplete or its original bytes changed")
    home = Path(tempfile.mkdtemp(prefix="msb-hc-", dir="/tmp"))
    env = environment(args.candidate, args.firmware, home, args.agent)
    runner = Runner(args.candidate, env, args.output / "candidate")
    report = {"producer_version": fixture["producer_version"], "home": str(home),
              "harness_sha256": digest(Path(__file__)),
              "candidate_sha256": digest(args.candidate), "firmware_sha256": digest(args.firmware),
              "agent": agent_identity(args.agent),
              "cases": [], "status": "running", "originals_unchanged": False}
    failed = False
    try:
        runner.run("version", "--version")
        # An archive containing its image must cold boot without fetching the image.
        # The subsequent directory case deliberately reuses only that installed image cache.
        for kind in ("archive", "directory"):
            sandbox = "historical-" + kind
            row = {"kind": kind, "status": "running"}
            try:
                source = originals / "fixture.msb"
                if kind == "directory":
                    source = home / "artifact-copy"
                    copy_artifact(originals / "artifact", source)
                runner.run(kind + "-create", "create", "--name", sandbox,
                           "--from-snapshot", source, "--pull", "never")
                runner.run(kind + "-guest", "exec", sandbox, "--", "sh", "-ec",
                           VERIFY + "\nprintf candidate-write > /root/historical/child-write; sync")
                runner.run(kind + "-stop", "stop", sandbox)
                runner.run(kind + "-restart", "start", sandbox)
                runner.run(kind + "-persistent-write", "exec", sandbox, "--", "sh", "-ec",
                           "test $(cat /root/historical/child-write) = candidate-write; " + VERIFY)
                if kind == "directory":
                    row["retained_descriptor"] = verify_descriptor_preservation(originals / "artifact", source)
                row["status"] = "passed"
            except BaseException as error:
                row["status"], row["error"] = "failed", str(error)
                failed = True
                if not isinstance(error, Exception):
                    raise
            finally:
                finish_case(runner, kind, sandbox, row, report, args.output)
        failed |= any(row["status"] != "passed" for row in report["cases"])
        report["status"] = "failed" if failed else "passed"
    except BaseException as error:
        report["status"], report["error"] = "failed", str(error)
        raise
    finally:
        finish_originals(report, originals, before, args.output)
    if failed or not report["originals_unchanged"]:
        raise RuntimeError(f"historical restore qualification failed: {args.output / 'report.json'}")


def main():
    install_termination_handler()
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    producer = commands.add_parser("produce")
    producer.add_argument("--version", choices=VERSIONS, required=True)
    producer.add_argument("--release-dir", type=Path, required=True)
    producer.add_argument("--image", default="alpine:3.22")
    candidate = commands.add_parser("qualify")
    candidate.add_argument("--fixture", type=Path, required=True)
    candidate.add_argument("--candidate", type=Path, required=True)
    candidate.add_argument("--firmware", type=Path, required=True)
    candidate.add_argument("--agent", type=Path)
    for command in (producer, candidate):
        command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    for key, value in vars(args).items():
        if isinstance(value, Path):
            setattr(args, key, value.resolve())
    (produce if args.mode == "produce" else qualify)(args)


if __name__ == "__main__":
    main()
