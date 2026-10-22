#!/usr/bin/env python3
"""Collect real stopped-source init evidence for the saved-config projector.

Requires a candidate CLI, current guest agent, released CLI, firmware and an
Alpine image archive. Uses isolated homes and records cleanup even on failure.
This qualifies private source evidence, not portable saved-config emission.
"""

import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import sqlite3
import sys
import tarfile
import tempfile
import traceback


def init_image(source, destination):
    """Give an existing Alpine disk a recognized init entrypoint without pulling."""
    with tarfile.open(source) as original, tarfile.open(destination, "w") as output:
        manifest = json.load(original.extractfile("manifest.json"))
        assert len(manifest) == 1
        old_config = manifest[0]["Config"]
        config = json.load(original.extractfile(old_config))
        config["config"]["Entrypoint"] = ["/sbin/init"]
        config["config"]["Cmd"] = []
        encoded = json.dumps(config, separators=(",", ":")).encode()
        new_config = hashlib.sha256(encoded).hexdigest() + ".json"
        manifest[0]["Config"] = new_config
        manifest[0]["RepoTags"] = ["local/init-provenance:latest"]
        for member in original.getmembers():
            if member.name in ("manifest.json", old_config, "repositories"):
                continue
            output.addfile(member, original.extractfile(member) if member.isfile() else None)
        for name, body in [(new_config, encoded), ("manifest.json", json.dumps(manifest).encode())]:
            member = tarfile.TarInfo(name)
            member.size = len(body)
            output.addfile(member, io.BytesIO(body))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "old", "agent", "firmware", "image", "output", "temp-root"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    for name, value in vars(args).items():
        setattr(args, name, value.resolve())
    support = Path(__file__).resolve().parent
    sys.path.insert(0, str(support))
    spec = importlib.util.spec_from_file_location("history", support / "lifecycle_evidence.py")
    history = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(history)
    history.install_termination_handler()

    args.output.mkdir(exist_ok=False)
    home = Path(tempfile.mkdtemp(prefix="saved-init-", dir=args.temp_root))
    env = history.environment(args.binary, args.firmware, home, args.agent)
    runner = history.Runner(args.binary, env, args.output / "current")
    old = history.Runner(args.old, env, args.output / "old-reader")
    report = {
        "host": platform.platform(), "home": str(home),
        "binary": history.digest(args.binary), "old": history.digest(args.old),
        "agent": history.digest(args.agent), "image": history.digest(args.image),
        "cases": [], "status": "running",
    }
    names, pids = [], set()

    def rows(query, values=()):
        with sqlite3.connect((home / "db/msb.db").as_uri() + "?mode=ro", uri=True) as connection:
            return connection.execute(query, values).fetchall()

    def state(name):
        path = home / "sandboxes" / name / "last-active/state.json"
        return path, json.loads(path.read_text())

    def verify(name, kind, path):
        journal, retained = state(name)
        source = retained["confirmed"]["source"]
        expected = {"kind": kind}
        if path:
            expected["configured"] = path
        assert retained["pending"] is None and retained["uncertain_since"] is None
        assert source["init_provenance"] == expected
        assert (source["init"]["cmd"] if source["init"] else None) == path
        init = json.loads(journal.with_name("init.json").read_text())
        observation = {"kind": "handoff", "path": path} if path else {"kind": "builtin"}
        assert init["observation"] == observation
        assert init["owner"] == retained["confirmed"]["owner"]
        config = rows("SELECT config FROM sandbox WHERE name=?", (name,))
        assert len(config) == 1
        assert json.loads(config[0][0])["init_provenance"] == expected
        pids.update(pid for (pid,) in rows("SELECT pid FROM run") if pid)
        return {"provenance": expected, "observation": observation, "owner": init["owner"]}

    try:
        fixture = args.output / "init-image.tar"
        init_image(args.image, fixture)
        runner.run("load", "image", "load", "--input", fixture)
        network = args.output / "network.json"
        network.write_text('{"http":{"deny_response":false}}\n')
        for label, selected in [("auto", "auto"), ("explicit", "/sbin/init"), ("builtin", None)]:
            name = "origin-" + label
            names.append(name)
            command = [
                "create", "local/init-provenance:latest", "--name", name,
                "--memory", "256M", "--max-memory", "256M", "--cpus", "1",
                "--max-cpus", "2", "--root-disk", "512M", "--max-duration", "5m",
                "--net-conf", network,
            ]
            if selected:
                command += ["--init", selected]
            runner.run(label + "-create", *command)
            kind = "path" if label == "explicit" else label
            path = "/sbin/init" if selected else None
            row = {"case": label, "initial": verify(name, kind, path)}
            runner.run(label + "-exec", "exec", name, "--", "sh", "-ec",
                       'echo retained >/root/provenance-marker; sync; tr "\\000" " " </proc/1/cmdline')
            if selected:
                assert "/sbin/init" in (runner.output / (label + "-exec.stdout")).read_text()
            old.run(label + "-inspect", "inspect", name, "--format", "json")
            runner.run(label + "-modify", "modify", name, "--cpus", "2", "--format", "json")
            row["modified"] = verify(name, kind, path)
            # The init fixture is not a shutdown-aware service; force-stop it deliberately.
            stop = ["--force"] if selected else []
            runner.run(label + "-stop", "stop", *stop, name)
            runner.run(label + "-start", "start", name)
            row["restarted"] = verify(name, kind, path)
            assert row["initial"]["owner"] != row["restarted"]["owner"]
            check = 'test "$(cat /root/provenance-marker)" = retained'
            runner.run(label + "-check", "exec", name, "--", "sh", "-ec", check)
            runner.run(label + "-stop2", "stop", *stop, name)
            journal, stopped = state(name)
            init = json.loads(journal.with_name("init.json").read_text())
            assert init["owner"] == stopped["confirmed"]["owner"]
            assert init["observation"] == row["restarted"]["observation"]
            runner.run(label + "-capture", "snapshot", "create", "--sandbox", name,
                       "--output", args.output / (label + ".msb"))
            assert state(name)[1] == stopped
            assert json.loads(journal.with_name("init.json").read_text()) == init
            # This is the real stopped journal, not a fabricated runtime capture receipt.
            evidence = {
                "case": label, "source": stopped["confirmed"]["source"],
                "init": init["observation"], "owner": stopped["confirmed"]["owner"],
                "generation": stopped["confirmed"]["generation"],
            }
            fd = os.open(args.output / (label + "-source.json"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as output:
                json.dump(evidence, output)
            # Released SDK requests still work; absence of private origin evidence must
            # stay unavailable when the old writer replaces the local configuration.
            old.run(label + "-start", "start", name)
            old.run(label + "-exec", "exec", name, "--", "sh", "-ec", check)
            assert state(name)[1]["confirmed"]["source"] is None
            old.run(label + "-stop", "stop", *stop, name)
            runner.run(label + "-rm", "rm", name)
            names.remove(name)
            row["status"] = "passed"
            report["cases"].append(row)
        report["status"] = "passed"
    except BaseException as error:
        report.update(status="failed", error=str(error), traceback=traceback.format_exc())
        if not isinstance(error, Exception):
            raise
    finally:
        report["cleanup"] = {name: {} for name in names}

        def collect_pids():
            pids.update(pid for (pid,) in rows("SELECT pid FROM run") if pid)

        def audit():
            report["remaining_sandboxes"] = rows("SELECT count(*) FROM sandbox")[0][0]
            report["remaining_live_runs"] = rows("SELECT count(*) FROM run WHERE terminated_at IS NULL")[0][0]
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
