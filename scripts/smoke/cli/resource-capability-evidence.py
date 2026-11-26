#!/usr/bin/env python3
"""Exercise all four old/new host-relay and guest combinations in disposable VMs.

The probe is the current agent-client resource_observations integration test binary.
It checks UnsupportedOperation/NotSent or an observation, then pings on the same
connection. Ordinary exec and resource growth must remain usable in every case.
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

import lifecycle_evidence as evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("old-runtime", "new-runtime", "old-agent", "new-agent", "firmware",
                "probe", "image", "output", "temp-root"):
        parser.add_argument("--" + key, type=Path, required=True)
    args = parser.parse_args()
    for key, value in vars(args).items():
        setattr(args, key, value.resolve())
    evidence.install_termination_handler()
    args.output.mkdir(exist_ok=False)
    with tarfile.open(args.image) as archive:
        image = json.load(archive.extractfile("manifest.json"))[0]["RepoTags"][0]
    artifacts = (args.old_runtime, args.new_runtime, args.old_agent, args.new_agent,
                 args.firmware, args.probe, args.image, Path(__file__))
    report = {"status": "running", "host": platform.platform(), "cases": [],
              "artifacts": {str(path): evidence.digest(path) for path in artifacts}}

    for new_relay, new_guest in ((False, False), (False, True), (True, False), (True, True)):
        label = f"relay-{int(new_relay)}-guest-{int(new_guest)}"
        home = Path(tempfile.mkdtemp(prefix="relay-", dir=args.temp_root))
        runtime = args.new_runtime if new_relay else args.old_runtime
        agent = args.new_agent if new_guest else args.old_agent
        env = evidence.environment(runtime, args.firmware, home, agent)
        runner = evidence.Runner(runtime, env, args.output / label)
        row = {"case": label, "home": str(home), "status": "running", "cleanup": {}}
        report["cases"].append(row)
        pids = set()

        def rows(query):
            with sqlite3.connect((home / "db/msb.db").as_uri() + "?mode=ro", uri=True) as db:
                return db.execute(query).fetchall()

        def identity():
            live = rows("SELECT id,pid FROM run WHERE terminated_at IS NULL")
            assert len(live) == 1 and live[0][1], live
            os.kill(live[0][1], 0)
            return live

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
                    # The audited runtime has exited; absence is the desired result.
                    pass
            assert row["remaining_sandboxes"] == row["remaining_live_runs"] == 0
            assert not row["surviving_pids"]

        try:
            # Load a local image so registry availability cannot change matrix coverage.
            runner.run("load", "image", "load", "--input", args.image)
            runner.run("create", "create", image, "--name", "rq", "--memory", "256M",
                       "--max-memory", "768M", "--cpus", "1", "--max-cpus", "2",
                       "--root-disk", "512M", "--max-duration", "5m", "--net", "none")
            collect_pids()
            row["before"] = identity()
            # A volatile marker and boot identity detect silent reboot, not just disk survival.
            runner.run("marker", "exec", "rq", "--", "sh", "-ec",
                       "echo retained >/dev/shm/relay-marker; cat /proc/sys/kernel/random/boot_id >/root/relay-boot")
            sockets = list(home.rglob("agent.sock"))
            assert len(sockets) == 1, sockets
            probe_env = dict(env, MSB_RESOURCE_SOCKET=str(sockets[0]),
                             MSB_EXPECT_OBSERVATION="1" if new_relay and new_guest else "0")
            probe = evidence.Runner(args.probe, probe_env, args.output / (label + "-probe"))

            def check(label):
                probe.run(label, "--ignored", "--exact", "live_resource_capability_safety", "--nocapture")
                # An incorrect test executable/filter can exit successfully after running
                # zero tests. Require the actual assertion-bearing probe to have run.
                output = (probe.output / (label + ".stdout")).read_text()
                assert "test result: ok. 1 passed; 0 failed; 0 ignored;" in output, output
                assert identity() == row["before"]
                runner.run(label + "-exec", "exec", "rq", "--", "sh", "-ec",
                           'test "$(cat /dev/shm/relay-marker)" = retained; '
                           'test "$(cat /root/relay-boot)" = "$(cat /proc/sys/kernel/random/boot_id)"')

            check("before-modify")
            runner.run("modify", "modify", "rq", "--cpus", "2", "--memory", "512M", "--format", "json")
            check("after-modify")
            row["after"] = identity()
            row["status"] = "passed"
        except BaseException as error:
            # Record interruption before finally saves the report, then propagate it.
            # Catching only Exception would leave a cancelled case marked running.
            row.update(status="failed", error=str(error), traceback=traceback.format_exc())
            report["status"] = "failed"
            if not isinstance(error, Exception):
                raise
        finally:
            evidence.finish_saved_evidence(runner, {"rq": row["cleanup"]}, row, report,
                                           args.output, audit, prepare=collect_pids)

    report["status"] = "passed" if all(row["status"] == "passed" for row in report["cases"]) else "failed"
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(report["status"])
    return int(report["status"] != "passed")


if __name__ == "__main__":
    sys.exit(main())
