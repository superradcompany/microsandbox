#!/usr/bin/env python3
"""Produce real 0.7.8 dependent histories and qualify their disk/full restore closure."""

import argparse
import importlib.util
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

import previous_release_upgrade as releases

spec = importlib.util.spec_from_file_location("historical_snapshots", Path(__file__).with_name("historical-snapshots.py"))
history = importlib.util.module_from_spec(spec)
spec.loader.exec_module(history)


def archive_inventory(path):
    # System tar decodes by magic, independently of the SDK's archive reader.
    return json.loads(subprocess.check_output(["tar", "-xOf", str(path), "archive.json"], stdin=subprocess.DEVNULL, timeout=120))


def require_dependent(inventory, full, require_memory=True):
    if inventory.get("completeness") != "dependent":
        raise RuntimeError("released export did not create a dependent archive")
    omitted = [entry for entry in inventory["entries"] if not entry["included"]]
    expected = "checkpoint-disk-layer" if full else "file-payload"
    if not any(entry["kind"] == expected for entry in omitted):
        raise RuntimeError("dependent fixture does not omit a reusable disk layer")
    if full and require_memory and not any(entry["kind"] == "checkpoint-object" for entry in omitted):
        raise RuntimeError("full dependent fixture does not omit reusable RAM objects")


def ram_object_ids(artifact):
    checkpoint = artifact / "checkpoint"
    root = json.loads((checkpoint / "checkpoint.json").read_text())
    algorithm, digest = root["memory"].split(":", 1)
    if algorithm != "sha256" or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise RuntimeError("invalid released memory-index object identity")
    memory = json.loads((checkpoint / "objects/sha256" / digest[:2] / digest).read_text())
    return {extent["content"]["object"] for extent in memory["extents"] if extent["content"]["kind"] == "object"}


def memory_dependency_member(members, members_root):
    # checkpoint-object also includes device state. Require an omitted object referenced
    # by the actual memory map, rather than counting a device-state dependency as RAM.
    for index, member in enumerate(members[1:], start=1):
        omitted = {"sha256:" + Path(e["path"]).name for e in member["inventory"]["entries"]
                   if not e["included"] and e["kind"] == "checkpoint-object"}
        if omitted & ram_object_ids(members_root / member["id"]):
            return index
    raise RuntimeError("full history contains no omitted RAM objects to qualify")


def produce(args):
    args.output.mkdir(parents=True, exist_ok=False)
    release = args.output / "release"
    release.mkdir()
    bundle = args.release_dir / releases.platform_asset()
    releases.unpack_release(bundle, (args.release_dir / "checksums.sha256").read_text(), release)
    binary, firmware = release / "msb", release / releases.firmware_name()
    home = Path(tempfile.mkdtemp(prefix="msb-hcp-", dir=args.temp_root)).resolve()
    runner = history.Runner(binary, history.environment(binary, firmware, home), args.output / "producer")
    originals = args.output / "originals"
    originals.mkdir()
    (originals / "members").mkdir()
    report = {"producer_version": "0.7.8", "kind": args.kind, "platform": platform.platform(),
              "architecture": platform.machine(), "home": str(home), "status": "running",
              "binary_sha256": history.digest(binary), "firmware_sha256": history.digest(firmware),
              "bundle_sha256": history.digest(bundle), "harness_sha256": history.digest(Path(__file__)), "members": []}
    full = args.kind == "full"
    try:
        runner.run("version", "--version")
        if (runner.output / "version.stdout").read_text().strip() != "msb 0.7.8":
            raise RuntimeError("historical chain producer is not released 0.7.8")
        runner.run("create", "create", "alpine:3.22", "--name", "chain-source", "--memory", "256M", "--root-disk", "512M", "--max-duration", "30m")
        runner.run("seed", "exec", "chain-source", "--", "sh", "-ec", history.SEED)
        if full:
            runner.run("seed-ram", "exec", "chain-source", "--", "sh", "-ec", "head -c 33554432 /dev/urandom > /dev/shm/history-payload; sha256sum /dev/shm/history-payload > /root/historical/ram-checksum; sync")
        previous = None
        for generation in range(1, 4):
            name = "cp" + str(generation)
            runner.run("mutate-" + name, "exec", "chain-source", "--", "sh", "-ec",
                       f"printf '{generation}' > /root/historical/generation; printf '{generation}' > /dev/shm/history-generation; sync")
            options = ["--full"] if full else []
            runner.run("capture-" + name, "snapshot", "create", name, "--sandbox", "chain-source", "--group", "historical-chain", "--integrity", *options)
            matches = [p.parent for p in (home / "snapshots/historical-chain").glob("*/group-member.json")
                       if json.loads(p.read_text())["name"] == name]
            if len(matches) != 1:
                raise RuntimeError("capture did not publish one named historical member")
            artifact = matches[0]
            descriptor = json.loads((artifact / "snapshot.json").read_text())
            if previous is not None and descriptor["parent"] is None:
                raise RuntimeError("released producer lost the history ancestry")
            history.copy_artifact(artifact, originals / "members" / artifact.name)
            archive = originals / (name + ".msb")
            options = ["--with-image"] if previous is None else ["--since", str(previous)]
            runner.run("export-" + name, "snapshot", "save", artifact, archive, *options)
            inventory = archive_inventory(archive)
            if previous is not None:
                require_dependent(inventory, full, require_memory=False)
            report["members"].append({"name": name, "id": descriptor["snapshot_id"], "descriptor": descriptor, "archive": archive.name, "inventory": inventory})
            previous = artifact
        if full:
            report["memory_dependency_index"] = memory_dependency_member(report["members"], originals / "members")
        runner.run("source-contents", "exec", "chain-source", "--", "sh", "-ec", history.VERIFY)
        runner.run("stop", "stop", "chain-source")
        runner.run("delete-source", "rm", "chain-source")
        report["originals"] = history.inventory(originals)
        report["status"] = "produced"
    except BaseException as error:
        report["status"], report["error"] = "failed", str(error)
        raise
    finally:
        report["cleanup"] = {}
        try:
            if report["status"] != "produced":
                history.cleanup(runner, "producer", "chain-source", report["cleanup"])
        finally:
            (args.output / "fixture.json").write_text(json.dumps(report, indent=2) + "\n")


def qualify(args):
    args.output.mkdir(parents=True, exist_ok=False)
    fixture = json.loads((args.fixture / "fixture.json").read_text())
    originals = args.fixture / "originals"
    before = history.inventory(originals)
    if fixture.get("status") != "produced" or before != fixture["originals"]:
        raise RuntimeError("historical chain fixture is incomplete or changed")
    members = fixture["members"]
    if len(members) != 3 or len({m["id"] for m in members}) != 3:
        raise RuntimeError("fixture must contain three distinct historical generations")
    full = fixture["kind"] == "full"
    for member in members[1:]:
        require_dependent(member["inventory"], full, require_memory=False)
    memory_index = memory_dependency_member(members, originals / "members") if full else None
    home = Path(tempfile.mkdtemp(prefix="msb-hcc-", dir=args.temp_root)).resolve()
    runner = history.Runner(args.candidate, history.environment(args.candidate, args.firmware, home, args.agent), args.output / "candidate")
    inputs = args.output / "inputs"
    inputs.mkdir()
    archives = [inputs / member["archive"] for member in members]
    report = {"producer_version": fixture["producer_version"], "kind": fixture["kind"], "home": str(home),
              "candidate_sha256": history.digest(args.candidate), "firmware_sha256": history.digest(args.firmware),
              "agent": history.agent_identity(args.agent),
              "harness_sha256": history.digest(Path(__file__)), "cases": [], "status": "running", "originals_unchanged": False}

    def restore(kind, sources, cow=False, generation=3):
        sandbox = "chain-" + kind
        row = {"kind": kind, "status": "running"}
        try:
            options = ["--cow-mem"] if cow else []
            runner.run(kind + "-create", "create", "--name", sandbox, "--from-snapshot", *sources, "--pull", "never", *options)
            verify = history.VERIFY + f"\ntest $(cat /root/historical/generation) = {generation}\n"
            if full:
                verify += f"test $(cat /dev/shm/history-generation) = {generation}; sha256sum -c /root/historical/ram-checksum\n"
            runner.run(kind + "-guest", "exec", sandbox, "--", "sh", "-ec", verify + "printf child > /root/historical/child-write; sync")
            runner.run(kind + "-stop", "stop", sandbox)
            runner.run(kind + "-restart", "start", sandbox)
            # Restart is a cold boot: only durable disk state is required to survive it.
            runner.run(kind + "-persistent", "exec", sandbox, "--", "sh", "-ec", history.VERIFY + f"\ntest $(cat /root/historical/child-write) = child; test $(cat /root/historical/generation) = {generation}")
            row["status"] = "passed"
        except BaseException as error:
            row["status"], row["error"] = "failed", str(error)
            raise
        finally:
            history.finish_case(runner, kind, sandbox, row, report, args.output)
        if row["status"] != "passed":
            raise RuntimeError("restored historical child cleanup failed")

    try:
        runner.run("version", "--version")
        for member, archive in zip(members, archives):
            shutil.copyfile(originals / member["archive"], archive)
        for label, extra in [("missing", []), ("wrong", ["--base", str(archives[0])])]:
            if runner.run(label + "-base", "snapshot", "load", label, "--file", archives[2], *extra, required=False) == 0:
                raise RuntimeError(label + " dependency was incorrectly accepted")
            if (home / "snapshots" / label).exists():
                raise RuntimeError("failed dependency import published a group")
        runner.run("reverse-load", "snapshot", "load", "received", "--file", *reversed(archives))
        group = home / "snapshots/received"
        installed = {p.parent.name for p in group.glob("*/snapshot.json")}
        if installed != {m["id"] for m in members} or json.loads((group / "group.json").read_text())["head"] != members[-1]["id"]:
            raise RuntimeError("reversed historical batch chose the wrong members/head")
        runner.run("verify-all", "snapshot", "verify", "received", "--all")
        if memory_index is not None:
            report["memory_dependency_index"] = memory_index
            restore("ram-dependency", list(reversed(archives[:memory_index + 1])), generation=memory_index + 1)
        restore("archive", list(reversed(archives)))
        # Test a private copy of the actual released directory closure as well.
        copied = inputs / "members"
        history.copy_artifact(originals / "members", copied)
        restore("directory", [copied / members[-1]["id"]])
        history.verify_descriptor_preservation(originals / "members" / members[-1]["id"], copied / members[-1]["id"])
        for member in members[:-1]:
            runner.run("remove-" + member["name"], "snapshot", "remove", "received", "--checkpoint", member["id"], "--force")
        shutil.rmtree(inputs)
        runner.run("verify-survivor", "snapshot", "verify", "received", "--all")
        restore("installed", ["received"])
        if full:
            restore("cow", ["received"], cow=True)
        if {p.parent.name for p in group.glob("*/snapshot.json")} != {members[-1]["id"]}:
            raise RuntimeError("ancestor removal did not leave exactly the selected child")
        report["status"] = "passed"
    except BaseException as error:
        report["status"], report["error"] = "failed", str(error)
        raise
    finally:
        history.finish_originals(report, originals, before, args.output)
    if report["status"] != "passed":
        raise RuntimeError("historical chain originals changed")


def main():
    history.install_termination_handler()
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    producer = commands.add_parser("produce")
    producer.add_argument("--release-dir", type=Path, required=True)
    producer.add_argument("--kind", choices=["disk", "full"], required=True)
    candidate = commands.add_parser("qualify")
    for option in ["fixture", "candidate", "firmware"]:
        candidate.add_argument("--" + option, type=Path, required=True)
    candidate.add_argument("--agent", type=Path)
    for command in [producer, candidate]:
        command.add_argument("--output", type=Path, required=True)
        command.add_argument("--temp-root", type=Path, default=Path("/tmp"))
    args = parser.parse_args()
    for key, value in vars(args).items():
        if isinstance(value, Path):
            setattr(args, key, value.resolve())
    (produce if args.mode == "produce" else qualify)(args)


if __name__ == "__main__":
    main()
