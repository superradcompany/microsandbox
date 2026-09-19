#!/usr/bin/env python3
"""Qualify unordered batch imports using already captured real VM checkpoints.

The fixture root comes from snapshot-groups.py and must contain home/snapshots/work
members full1, full2, full3, local-child, and experiment. No fixture is modified.
Pass --live to restore eager/forked children after imports; all owned VMs are stopped.
Pass --file-only to qualify disk-only cp1/cp2 archives and their cold-boot restore.
"""

import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--fixtures", required=True, type=Path)
    parser.add_argument("--image-home", type=Path,
                        help="Optional home containing the fixture's fully materialized image cache")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--file-only", action="store_true")
    parser.add_argument("--fresh-file", action="store_true",
                        help="Capture two new disk-only checkpoints before the file-only matrix")
    parser.add_argument("--file-standalone", action="store_true",
                        help="Qualify complete disk archives instead of dependent --since exports")
    args = parser.parse_args()
    if args.fresh_file and not (args.file_only and args.live):
        parser.error("--fresh-file requires --file-only --live")
    if args.file_standalone and not args.file_only:
        parser.error("--file-standalone requires --file-only")
    args.output.mkdir(parents=True, exist_ok=False)
    home = args.output / "home"
    inputs = args.output / "inputs"
    inputs.mkdir()
    env = dict(os.environ, MSB_HOME=str(home), MSB_BACKEND="local")
    # Flat-only fixtures may not have the layered image cache required by --with-image.
    # An explicitly supplied cache home must hold the same pinned image digest; export
    # validates that match while reading snapshot artifacts from their original paths.
    source_env = dict(env, MSB_HOME=str(args.image_home or args.fixtures / "home"))
    rows, names = [], []
    report = dict(status="running", binary=args.binary, fixture=str(args.fixtures),
                  image_home=source_env["MSB_HOME"], home=str(home), live=args.live,
                  file_only=args.file_only, fresh_file=args.fresh_file,
                  file_standalone=args.file_standalone, rows=rows)

    def persist():
        (args.output / "report.json").write_text(json.dumps(report, indent=2))

    def run(label, *command, fail=False, source=False, shell=False):
        started = time.perf_counter()
        argv = ["/bin/sh", "-c", command[0]] if shell else [args.binary, *map(str, command)]
        result = subprocess.run(argv,
                                env=source_env if source else env,
                                capture_output=True, text=True, timeout=180)
        row = dict(case=label, ms=round((time.perf_counter() - started) * 1000, 2),
                   exit=result.returncode, expected_failure=fail,
                   stdout=result.stdout, stderr=result.stderr)
        rows.append(row)
        persist()
        print(json.dumps({key: row[key] for key in ("case", "ms", "exit")}), flush=True)
        assert (result.returncode != 0) == fail, row
        return result.stdout.strip()

    def group_head(group):
        return json.loads((home / "snapshots" / group / "group.json").read_text())["head"]

    def members(group):
        return sorted(path.parent.name for path in (home / "snapshots" / group).glob("*/snapshot.json"))

    def restored(mode, group, marker):
        name = "batch-" + mode
        names.append(name)
        options = ["--forked"] if mode == "forked" else []
        run("restore-" + mode, "create", "--name", name, "--from-snapshot", group, *options)
        actual = run("state-" + mode, "exec", name, "--", "sh", "-ec",
                     "cat /disk-marker; cat /dev/shm/marker")
        assert actual == marker, actual
        run("stop-" + mode, "stop", name)

    fixtures = {}
    for metadata in (args.fixtures / "home/snapshots/work").glob("*/group-member.json"):
        name = json.loads(metadata.read_text())["name"]
        descriptor = json.loads((metadata.parent / "snapshot.json").read_text())
        fixtures[name] = (metadata.parent, descriptor)
    required = (("cp1", "cp2") if args.file_only
                else ("full1", "full2", "full3", "local-child", "experiment"))
    assert all(name in fixtures for name in required), sorted(fixtures)
    ids = [fixtures[name][1]["snapshot_id"] for name in required[:3]]
    archives = [inputs / (name + ".msb") for name in ("full1", "full2", "full3")]
    branch = inputs / "branch.msb"
    unrelated = inputs / "unrelated.msb"
    try:
        if args.file_only:
            if args.fresh_file:
                # Start only a disposable child, never the retained fixture sandbox.
                seed = inputs / "seed.msb"
                run("export-file-seed", "snapshot", "save", fixtures["cp2"][0], seed,
                    "--with-image", source=True)
                run("load-file-seed", "snapshot", "load", seed, "--group", "seed")
                names.append("batch-capture")
                run("create-file-source", "create", "--name", "batch-capture", "--from-snapshot", "seed")
                for member, marker in (("cp1", "one"), ("cp2", "two")):
                    run("write-file-" + member, "exec", "batch-capture", "--", "sh", "-ec",
                        "echo " + marker + " > /disk-marker; sync")
                    output = run("capture-file-" + member, "snapshot", "create", member,
                                 "--from-sandbox", "batch-capture", "--group", "fresh")
                    artifact = Path(output.splitlines()[-1])
                    fixtures[member] = (artifact, json.loads((artifact / "snapshot.json").read_text()))
                run("stop-file-source", "stop", "batch-capture")
                ids = [fixtures[name][1]["snapshot_id"] for name in required]
            # These are actual disk-only artifacts, not full checkpoints restored with
            # --disk-only: their inherited payloads use the file-archive layer pool.
            assert all(fixtures[name][1]["state"]["kind"] == "file" for name in required)
            first, second = inputs / "cp1.msb", inputs / "cp2.msb"
            run("export-file-base", "snapshot", "save", fixtures["cp1"][0], first,
                "--with-image", source=True)
            delta_options = [] if args.file_standalone else ["--since", fixtures["cp1"][0]]
            run("export-file-complete" if args.file_standalone else "export-file-delta",
                "snapshot", "save", fixtures["cp2"][0], second, *delta_options, source=True)
            inventory = json.loads(subprocess.check_output(["tar", "-xOf", str(second), "archive.json"]))
            assert inventory["completeness"] == ("boot-complete" if args.file_standalone else "dependent")
            report["file_inventory"] = inventory
            if not args.file_standalone:
                run("missing-file-base-refused", "snapshot", "load", second, "--group", "missing", fail=True)
                assert members("missing") == []
            run("load-file-reverse", "snapshot", "load", second, first, "--group", "file")
            assert members("file") == sorted(ids)
            assert group_head("file") == ids[1]
            for name in required:
                run("verify-file-" + name, "snapshot", "verify", "file:" + name)
            run("install-file-base", "snapshot", "load", first, "--group", "automatic")
            run("file-auto-base", "snapshot", "load", second, "--group", "automatic")
            assert group_head("automatic") == ids[1]
            # The surviving member must own the full disk closure after inputs and its
            # installed historical parent disappear, including borrowed archive layers.
            first.unlink()
            second.unlink()
            run("remove-file-ancestor", "snapshot", "remove", "file:" + ids[0], "--force")
            run("verify-owned-file", "snapshot", "verify", "file")
            if args.live:
                name = "batch-file"
                names.append(name)
                run("restore-file", "create", "--name", name, "--from-snapshot", "file")
                actual = run("state-file", "exec", name, "--", "sh", "-ec",
                             "cat /disk-marker; test ! -e /dev/shm/marker")
                assert actual == "two", actual
                run("stop-file", "stop", name)
            report["status"] = "passed"
            return
        # Include the pinned image once; importing the batch remains offline-capable.
        run("export-baseline", "snapshot", "save", fixtures["full1"][0], archives[0],
            "--with-image", source=True)
        for index in (1, 2):
            run("export-delta-" + str(index), "snapshot", "save",
                fixtures["full" + str(index + 1)][0], archives[index],
                "--since", fixtures["full" + str(index)][0], source=True)
        run("export-branch", "snapshot", "save", fixtures["local-child"][0], branch, source=True)
        run("export-unrelated", "snapshot", "save", fixtures["experiment"][0], unrelated, source=True)
        for index in (1, 2):
            inventory = json.loads(subprocess.check_output(["tar", "-xOf", str(archives[index]), "archive.json"]))
            assert inventory["completeness"] == "dependent", "fixture must omit real dependencies"
            report["delta_" + str(index) + "_inventory"] = inventory

        for label, order in (("reverse", (2, 1, 0)), ("shuffled", (1, 0, 2))):
            output = run("load-" + label, "snapshot", "load", *(archives[index] for index in order), "--group", label)
            # Results correspond to input archive heads; input order does not select the
            # group's head. In reverse order, the final printed path is the oldest member.
            printed_paths = [Path(line) for line in output.splitlines() if line.startswith(str(home))]
            assert [path.name for path in printed_paths] == [ids[index] for index in order]
            assert members(label) == sorted(ids)
            assert group_head(label) == ids[2]
            for name in ("full1", "full2", "full3"):
                run("verify-" + label + "-" + name, "snapshot", "verify", label + ":" + name)

        wildcard_inputs = inputs / "wildcard"
        wildcard_inputs.mkdir()
        for archive in archives:
            os.link(archive, wildcard_inputs / archive.name)
        # This is a real shell expansion, unlike the explicit argument arrays above.
        wildcard_command = (shlex.join([args.binary, "snapshot", "load"]) + " "
                            + shlex.quote(str(wildcard_inputs)) + "/*.msb --group wildcard")
        run("shell-wildcard", wildcard_command, shell=True)
        assert members("wildcard") == sorted(ids)
        assert group_head("wildcard") == ids[2]

        run("group-base-install", "snapshot", "load", archives[0], "--group", "automatic")
        run("group-base-auto", "snapshot", "load", archives[2], archives[1], "--group", "automatic")
        assert group_head("automatic") == ids[2]
        assert members("automatic") == sorted(ids)

        # A destination is a group-store root, not another archive argument. Automatic
        # dependency lookup must also respect an explicitly selected nondefault root.
        alternate = args.output / "alternate-store"
        run("alternate-base", "snapshot", "load", archives[0], "--dest", alternate, "--group", "work")
        run("alternate-auto-base", "snapshot", "load", archives[2], archives[1],
            "--dest", alternate, "--group", "work")
        assert json.loads((alternate / "work/group.json").read_text())["head"] == ids[2]
        run("verify-alternate", "snapshot", "verify", alternate / "work" / ids[2])

        run("missing-base-refused", "snapshot", "load", archives[2], "--group", "missing", fail=True)
        assert members("missing") == []
        run("unrelated-base-refused", "snapshot", "load", archives[2], "--base", unrelated,
            "--group", "unrelated", fail=True)
        assert members("unrelated") == []
        # A complete external base supplies payloads, not mandatory imported history.
        run("external-base", "snapshot", "load", archives[2], "--base", fixtures["full2"][0],
            "--group", "hole")
        assert members("hole") == [ids[2]]
        assert group_head("hole") == ids[2]
        run("verify-history-hole", "snapshot", "verify", "hole")

        run("duplicates", "snapshot", "load", archives[0], archives[0], "--group", "duplicates")
        assert members("duplicates") == [ids[0]]
        run("ambiguous-new", "snapshot", "load", archives[1], branch, archives[0], "--group", "branches")
        assert group_head("branches") is None
        assert len(members("branches")) == 3
        run("headless-restore-refused", "snapshot", "inspect", "branches", fail=True)
        run("explicit-branch-selection", "snapshot", "head", "branches:local-child")
        assert group_head("branches") == fixtures["local-child"][1]["snapshot_id"]

        run("ambiguity-base", "snapshot", "load", archives[0], "--group", "retained")
        run("ambiguity-retains", "snapshot", "load", archives[1], branch, "--group", "retained")
        assert group_head("retained") == ids[0]
        run("ambiguous-forced-head-refused", "snapshot", "load", archives[1], branch, archives[0],
            "--group", "rejected", "--set-head", fail=True)
        assert members("rejected") == []

        # Delete only this harness's exports, never the retained source fixtures. Loaded
        # snapshots must keep working with their own dependency-complete disk/RAM files.
        for archive in inputs.rglob("*.msb"):
            assert archive.is_file()
            archive.unlink()
        for index in (0, 1):
            run("remove-installed-ancestor-" + str(index), "snapshot", "remove",
                "reverse:" + ids[index], "--force")
        run("verify-owned-final", "snapshot", "verify", "reverse")
        assert members("reverse") == [ids[2]]
        if args.live:
            restored("eager", "reverse", "three\nram-three")
            restored("forked", "reverse", "three\nram-three")
        report["status"] = "passed"
    except Exception as error:
        report.update(status="failed", error=repr(error))
        raise
    finally:
        cleanup = []
        for name in names:
            result = subprocess.run([args.binary, "stop", name], env=env,
                                    capture_output=True, text=True, timeout=30)
            cleanup.append(dict(name=name, exit=result.returncode, stderr=result.stderr))
        report["cleanup"] = cleanup
        persist()


if __name__ == "__main__":
    main()
