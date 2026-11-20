#!/usr/bin/env python3
"""Exercise runtime-owned labels, old peers and durable-transition failures in isolated homes."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import sqlite3
import sys
import tarfile
import tempfile
import traceback


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "releases", "agent", "firmware", "image", "support", "output", "temp-root"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--hooks-binary", type=Path)
    parser.add_argument("--legacy-label-binary", type=Path)
    parser.add_argument("--case", action="append", choices=("current", "v0.6.0", "v0.6.6", "v0.6.7", "v0.6.18", "v0.7.8", "before-modify", "after-modify-effect"))
    parser.add_argument("--large-script", action="store_true",
                        help="Retain a 5 MiB unchanged script while updating labels")
    args = parser.parse_args()
    sys.path.insert(0, str(args.support.resolve()))
    spec = importlib.util.spec_from_file_location("history", args.support / "lifecycle_evidence.py")
    history = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(history)
    history.install_termination_handler()
    args.output.mkdir(exist_ok=False)
    report = {"host": platform.platform(), "cases": [], "status": "running", "artifacts": {
        str(p): history.digest(p) for p in (args.binary, args.agent, args.firmware, args.image)
    }, "harness_sha256": history.digest(Path(__file__))}
    cases = [(v, None) for v in ("current", "v0.6.0", "v0.6.6", "v0.6.7", "v0.6.18", "v0.7.8")]
    if args.hooks_binary:
        cases += [("hooks", phase) for phase in ("before-modify", "after-modify-effect")]
    if args.case:
        if any(case in ("before-modify", "after-modify-effect") for case in args.case) and not args.hooks_binary:
            parser.error("failure cases require --hooks-binary")
        cases = [(version, failure) for version, failure in cases if (failure or version) in args.case]
    for version, failure in cases:
        runtime = args.hooks_binary if failure else args.binary if version == "current" else args.releases / version / "msb"
        report["artifacts"][str(runtime)] = history.digest(runtime)
        home = Path(tempfile.mkdtemp(prefix="labels-", dir=args.temp_root))
        env = history.environment(runtime, args.firmware, home, args.agent)
        if failure:
            env["MSB_TEST_RETENTION_FAILURE"] = failure
        runner = history.Runner(args.binary, env, args.output / (failure or version))
        row = {"runtime": version, "failure": failure, "home": str(home), "status": "running"}
        report["cases"].append(row)
        pids = set()

        def rows(sql):
            with sqlite3.connect((home / "db/msb.db").as_uri() + "?mode=ro", uri=True) as db:
                return db.execute(sql).fetchall()

        def config(column="config"):
            return json.loads(rows(f"SELECT {column} FROM sandbox WHERE name='labels'")[0][0])

        def journal():
            return json.loads((home / "sandboxes/labels/last-active/state.json").read_text())

        try:
            runner.run("load", "image", "load", "--input", args.image)
            with tarfile.open(args.image) as archive:
                image = json.load(archive.extractfile("manifest.json"))[0]["RepoTags"][0]
            extra = []
            if args.large_script:
                configuration = home / "large-script.json"
                configuration.write_text(json.dumps({"scripts": {"large": "#" + "x" * (5 * 1024 * 1024) + "\n"}}))
                extra = ["--conf", configuration]
            runner.run("create", "create", image, "--name", "labels", "--memory", "256M", "--max-memory", "256M",
                       "--cpus", "1", "--max-cpus", "1", "--root-disk", "512M", "--max-duration", "5m", *extra)
            pids.update(pid for (pid,) in rows("SELECT pid FROM run") if pid)
            runner.run("seed", "exec", "labels", "--", "sh", "-ec", "echo retained >/root/labels-marker; sync")
            script_before = config()["runtime"]["scripts"].get("large") if args.large_script else None
            before = journal() if version in ("current", "hooks") else None
            code = runner.run("label-set", "modify", "labels", "--label", "team=one", "--format", "json", required=not failure)
            if failure:
                assert code != 0
                active = config("active_config")
                if failure == "before-modify":
                    assert active["labels"].get("team") is None
                    assert config()["labels"].get("team") is None
                    assert journal() == before
                else:
                    assert active["labels"]["team"] == config()["labels"]["team"] == "one"
                    assert rows("SELECT key,value FROM sandbox_labels") == [("team", "one")]
                    assert journal()["pending"] == "modify"
                runner.run("still-running", "exec", "labels", "--", "cat", "/root/labels-marker")
                if args.large_script:
                    assert config()["runtime"]["scripts"]["large"] == script_before
                row["failure_outcome"] = "not_applied" if failure == "before-modify" else "unknown_after_application"
            else:
                assert config()["labels"]["team"] == config("active_config")["labels"]["team"] == "one"
                if version == "current":
                    changed = journal()
                    assert changed["generation"] > before["generation"]
                    assert changed["confirmed"]["source"] == config("active_config")
                    runner.run("label-remove", "modify", "labels", "--label-rm", "team", "--format", "json")
                    assert journal()["confirmed"]["source"]["labels"].get("team") is None
                    # Released 0.7.8 did not support live labels. Preserve that refusal,
                    # then exercise the pre-extension SDK which writes active labels directly.
                    released = history.Runner(args.releases / "v0.7.8/msb", env, args.output / "released-writer")
                    prior_active, prior_desired, prior_journal = config("active_config"), config(), journal()
                    assert released.run("unsupported-label", "modify", "labels", "--label", "legacy=two", "--format", "json", required=False) != 0
                    assert config("active_config") == prior_active and config() == prior_desired and journal() == prior_journal
                    assert args.legacy_label_binary, "current case requires the previous legacy-label SDK binary"
                    report["artifacts"][str(args.legacy_label_binary)] = history.digest(args.legacy_label_binary)
                    old = history.Runner(args.legacy_label_binary, env, args.output / "old-writer")
                    generation = journal()["generation"]
                    old.run("old-label", "modify", "labels", "--label", "legacy=two", "--format", "json")
                    assert journal()["generation"] == generation
                    assert journal()["confirmed"]["source"] != config("active_config")
                    runner.run("after-old-label", "modify", "labels", "--label", "current=three", "--format", "json")
                    assert journal()["confirmed"]["source"] is None
                    assert config("active_config")["labels"] == {"legacy": "two", "current": "three"}
                    row["old_writer_evidence_remains_unknown"] = True
                else:
                    assert not (home / "sandboxes/labels/last-active/state.json").exists()
                    row["legacy_catalog_route_preserved"] = True
                if args.large_script:
                    assert config()["runtime"]["scripts"]["large"] == script_before
                    runner.run("large-script-retained", "exec", "labels", "--", "sh", "-ec",
                               "test $(wc -c < /.msb/scripts/large) -gt 4194304")
                    row["large_script_preserved"] = True
                runner.run("stop", "stop", "labels")
                runner.run("restart", "start", "labels")
                pids.update(pid for (pid,) in rows("SELECT pid FROM run") if pid)
                runner.run("check", "exec", "labels", "--", "sh", "-ec", 'test "$(cat /root/labels-marker)" = retained')
                assert config()["labels"] == config("active_config")["labels"]
                if version == "current":
                    assert journal()["confirmed"]["source"] == config("active_config")
                    row["fresh_restart_reestablishes_evidence"] = True
            row["status"] = "passed"
        except BaseException as error:
            row.update(status="failed", error=str(error), traceback=traceback.format_exc())
            report["status"] = "failed"
            if not isinstance(error, Exception):
                raise
        finally:
            row["cleanup"] = {}

            def collect_pids():
                pids.update(pid for (pid,) in rows("SELECT pid FROM run") if pid)

            def audit():
                row["remaining_sandboxes"] = rows("SELECT count(*) FROM sandbox")[0][0]
                row["remaining_live_runs"] = rows("SELECT count(*) FROM run WHERE terminated_at IS NULL")[0][0]
                row["surviving_pids"] = []
                for pid in pids:
                    try:
                        os.kill(pid, 0)
                        row["surviving_pids"].append(pid)
                    except ProcessLookupError:
                        pass
                assert row["remaining_sandboxes"] == row["remaining_live_runs"] == 0
                assert not row["surviving_pids"]
            history.finish_saved_evidence(runner, {"labels": row["cleanup"]}, row, report, args.output, audit, prepare=collect_pids)
    report["status"] = "passed" if all(row["status"] == "passed" for row in report["cases"]) else "failed"
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(report["status"], flush=True)
    return report["status"] != "passed"


if __name__ == "__main__":
    sys.exit(main())
