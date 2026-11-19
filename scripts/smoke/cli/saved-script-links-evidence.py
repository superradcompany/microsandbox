#!/usr/bin/env python3
"""Qualify script link evidence without changing legacy capture success.

Uses one disposable VM, disk/full captures, and actual guest-created hard links.
This does not qualify portable saved-config activation or full resume.
"""

import argparse
import json
import os
from pathlib import Path
import platform
import sqlite3
import sys
import tarfile
import tempfile
import traceback

import lifecycle_evidence as history


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "agent", "firmware", "image", "output", "temp-root"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expect-linked-state", choices=("unknown", "observed"), default="unknown",
                        help="Use observed only to reproduce the pre-fix false evidence")
    args = parser.parse_args()
    for name, value in vars(args).items():
        if isinstance(value, Path):
            setattr(args, name, value.resolve())
    history.install_termination_handler()
    args.output.mkdir(exist_ok=False)
    home = Path(tempfile.mkdtemp(prefix="script-links-", dir=args.temp_root))
    runner = history.Runner(args.binary, history.environment(args.binary, args.firmware, home, args.agent),
                            args.output / "commands")
    name = "script-links"
    pids = set()
    report = {"host": platform.platform(), "home": str(home), "status": "running", "cases": [],
              "artifacts": {str(p): history.digest(p) for p in (args.binary, args.agent, args.firmware, args.image)},
              "harness_sha256": history.digest(Path(__file__)), "expected_linked_state": args.expect_linked_state}

    def rows(sql):
        database = home / "db/msb.db"
        if not database.exists():
            return []
        with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
            return db.execute(sql).fetchall()

    def collect_pids():
        pids.update(pid for (pid,) in rows("SELECT pid FROM run") if pid)

    try:
        runner.run("load", "image", "load", "--input", args.image)
        with tarfile.open(args.image) as archive:
            image = json.load(archive.extractfile("manifest.json"))[0]["RepoTags"][0]
        runner.run("create", "create", image, "--name", name, "--memory", "256M",
                   "--max-memory", "256M", "--cpus", "1", "--max-cpus", "1",
                   "--root-disk", "512M", "--max-duration", "10m", "--net", "none",
                   "--script-raw", "probe=#!/bin/sh\nprintf LINK_EVIDENCE\n")
        collect_pids()
        receipts = home / "sandboxes" / name / "last-active/captures"
        for label, linked in [("original", False), ("linked", True), ("unlinked", False)]:
            if linked:
                runner.run("link", "exec", name, "--", "sh", "-ec",
                           "ln /.msb/scripts/probe /.msb/alias; test \"$(stat -c %h /.msb/scripts/probe)\" = 2")
            elif label == "unlinked":
                runner.run("unlink", "exec", name, "--", "rm", "/.msb/alias")
            assert (home / "sandboxes" / name / "runtime/scripts/probe").stat().st_nlink == (2 if linked else 1)
            for full in [False, True]:
                case = label + ("-full" if full else "-disk")
                before = set(receipts.glob("*.json"))
                code = runner.run(case + "-capture", "snapshot", "create", case, "--sandbox", name,
                                  *(["--full"] if full else []), required=False)
                created = set(receipts.glob("*.json")) - before
                if code:
                    # Some backends retain the removed alias as an open-unlinked inode.
                    # Preserve that existing full-state refusal; an observed script is
                    # never permission to override the filesystem's admission checks.
                    diagnostic = (runner.output / (case + "-capture.stderr")).read_text()
                    assert label == "unlinked" and full, (case, diagnostic)
                    assert "open-unlinked passthrough objects are not checkpointable" in diagnostic
                    assert not created, "refused checkpoint published a configuration receipt"
                    runner.run(case + "-exec", "exec", name, "--", "sh", "-ec",
                               "test \"$(sh /.msb/scripts/probe)\" = LINK_EVIDENCE")
                    report["cases"].append({"case": case, "capture": "refused-open-unlinked",
                                            "status": "passed"})
                    continue
                assert len(created) == 1, (case, len(created))
                record = json.loads(created.pop().read_text())
                scripts = record["scripts"]
                expected = args.expect_linked_state if linked else "observed"
                assert scripts["state"] == expected, (case, scripts["state"])
                if expected == "unknown":
                    assert scripts == {"state": "unknown", "reason": "unreadable"}
                else:
                    assert scripts["files"]["probe"]["content"] == "#!/bin/sh\nprintf LINK_EVIDENCE\n"
                runner.run(case + "-exec", "exec", name, "--", "sh", "-ec",
                           "test \"$(sh /.msb/scripts/probe)\" = LINK_EVIDENCE")
                report["cases"].append({"case": case, "backing_state": expected, "status": "passed"})
        report["status"] = "passed"
    except BaseException as error:
        report.update(status="failed", error=str(error), traceback=traceback.format_exc())
        if not isinstance(error, Exception):
            raise
    finally:
        report["cleanup"] = {name: {}}

        def audit():
            report["remaining_sandboxes"] = len(rows("SELECT id FROM sandbox"))
            report["remaining_live_runs"] = len(rows("SELECT id FROM run WHERE terminated_at IS NULL"))
            report["surviving_pids"] = []
            for pid in pids:
                try:
                    os.kill(pid, 0)
                    report["surviving_pids"].append(pid)
                except ProcessLookupError:
                    pass
            if report["remaining_sandboxes"] or report["remaining_live_runs"] or report["surviving_pids"]:
                raise RuntimeError("candidate cleanup left sandbox state or live processes")

        history.finish_saved_evidence(runner, report["cleanup"], report, report,
                                      args.output, audit, force=True, prepare=collect_pids)
    print(report["status"], flush=True)
    return report["status"] != "passed"


if __name__ == "__main__":
    sys.exit(main())
