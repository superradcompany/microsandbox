#!/usr/bin/env python3
"""Qualify released archives through installed group/name/ID selectors and failed retries."""

import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile


spec = importlib.util.spec_from_file_location("historical_snapshots", Path(__file__).with_name("historical-snapshots.py"))
history = importlib.util.module_from_spec(spec)
spec.loader.exec_module(history)


def group_state(home, group):
    """Compare immutable members and head, excluding unrelated caches/lock files."""
    root = home / "snapshots" / group
    manifest = json.loads((root / "group.json").read_text())
    members = {}
    for path in root.glob("*/snapshot.json"):
        local = path.parent / "group-member.json"
        # Older archives did not preserve local aliases. Their stable imported ID is still
        # usable; inventing a name here would make the qualification claim misleading.
        members[path.parent.name] = json.loads(local.read_text()) if local.is_file() else {"name": None}
    descriptors = {path.parent.name: history.digest(path)
                   for path in root.glob("*/snapshot.json")}
    return {"head": manifest["head"], "members": members, "descriptors": descriptors}


def require_unchanged(home, group, expected):
    if group_state(home, group) != expected:
        raise RuntimeError("failed or repeated import changed installed members/head")


def qualify(args):
    args.output.mkdir(parents=True, exist_ok=False)
    fixture = json.loads((args.fixture / "fixture.json").read_text())
    originals = args.fixture / "originals"
    before = history.inventory(originals)
    if fixture.get("status") != "produced" or before != fixture["originals"]:
        raise RuntimeError("producer fixture is incomplete or its original bytes changed")
    # Disk-backed Linux callers can select a short home outside a quota-limited /tmp.
    home = Path(tempfile.mkdtemp(prefix="msb-hi-", dir=args.temp_root)).resolve()
    runner = history.Runner(args.candidate, history.environment(args.candidate, args.firmware, home, args.agent), args.output / "candidate")
    report = {"producer_version": fixture["producer_version"], "home": str(home),
              "candidate_sha256": history.digest(args.candidate),
              "firmware_sha256": history.digest(args.firmware),
              "agent": history.agent_identity(args.agent),
              "harness_sha256": history.digest(Path(__file__)),
              "cases": [], "status": "running", "originals_unchanged": False}
    archive = args.output / "input.msb"
    broken = args.output / "truncated.msb"
    group = "historical-installed"
    owned = []
    try:
        shutil.copyfile(originals / "fixture.msb", archive)
        with archive.open("rb") as source:
            broken.write_bytes(source.read(32))
        runner.run("version", "--version")
        runner.run("load", "snapshot", "load", group, "--file", archive)
        state = group_state(home, group)
        if len(state["members"]) != 1 or state["head"] not in state["members"]:
            raise RuntimeError("single-checkpoint fixture did not produce one selected member")
        checkpoint_id = state["head"]
        checkpoint_name = state["members"][checkpoint_id]["name"]
        report["name_selection"] = "recorded" if checkpoint_name else "unavailable: producer archive did not record a local member name"
        report["installed"] = state
        runner.run("retry-load", "snapshot", "load", group, "--file", archive)
        require_unchanged(home, group, state)
        # A valid historical member followed by malformed input must not partially publish,
        # whether the destination already exists or would have to be created by the batch.
        for target in (group, "failed-new-group"):
            if runner.run("bad-batch-" + target, "snapshot", "load", target, "--file", archive, broken, required=False) == 0:
                raise RuntimeError("malformed historical batch unexpectedly succeeded")
            require_unchanged(home, group, state)
            if (home / "snapshots" / "failed-new-group").exists():
                raise RuntimeError("failed batch published its new destination group")
        runner.run("retry-after-failure", "snapshot", "load", group, "--file", archive)
        require_unchanged(home, group, state)
        runner.run("verify-installed", "snapshot", "verify", group, "--all")
        report["import_retry_and_atomic_refusal"] = "passed"
        # No selected archive path remains when any guest is started. The original fixture
        # stays untouched elsewhere; it is never passed to the candidate's launch command.
        archive.unlink()
        broken.unlink()
        selectors = [("head", None), ("id", checkpoint_id)]
        if checkpoint_name:
            selectors.append(("name", checkpoint_name))
        for kind, selector in selectors:
            sandbox = "historical-" + kind
            owned.append(sandbox)
            row = {"kind": kind, "selector": selector, "status": "running"}
            try:
                options = [] if selector is None else ["--checkpoint", selector]
                runner.run(kind + "-create", "create", "--name", sandbox, "--from-snapshot", group, "--pull", "never", *options)
                runner.run(kind + "-guest", "exec", sandbox, "--", "sh", "-ec",
                           history.VERIFY + "\nprintf installed-write > /root/historical/installed-write; sync")
                runner.run(kind + "-stop", "stop", sandbox)
                runner.run(kind + "-restart", "start", sandbox)
                runner.run(kind + "-persistent", "exec", sandbox, "--", "sh", "-ec",
                           "test $(cat /root/historical/installed-write) = installed-write; " + history.VERIFY)
                row["status"] = "passed"
            except BaseException as error:
                row["status"], row["error"] = "failed", str(error)
                if not isinstance(error, Exception):
                    raise
            finally:
                history.finish_case(runner, kind, sandbox, row, report, args.output)
        require_unchanged(home, group, state)
        if any(row["status"] != "passed" for row in report["cases"]):
            raise RuntimeError("one or more installed historical selectors failed")
        report["status"] = "passed"
    except BaseException as error:
        report["status"], report["error"] = "failed", str(error)
        raise
    finally:
        # Per-case cleanup also covers failed creation. Re-attempt only interrupted cases.
        completed = {"historical-" + row["kind"] for row in report["cases"]}
        for sandbox in owned:
            if sandbox not in completed:
                report.setdefault("interrupted_cleanup", {})[sandbox] = history.cleanup(runner, "interrupted-" + sandbox, sandbox)
        history.finish_originals(report, originals, before, args.output)
    if report["status"] != "passed":
        raise RuntimeError("historical originals changed during qualification")


def main():
    history.install_termination_handler()
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("fixture", "candidate", "firmware", "output"):
        parser.add_argument("--" + option, type=Path, required=True)
    parser.add_argument("--agent", type=Path)
    parser.add_argument("--temp-root", type=Path, default=Path("/tmp"))
    args = parser.parse_args()
    for key, value in vars(args).items():
        if isinstance(value, Path):
            setattr(args, key, value.resolve())
    qualify(args)


if __name__ == "__main__":
    main()
