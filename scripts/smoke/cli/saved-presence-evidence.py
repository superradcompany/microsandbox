#!/usr/bin/env python3
"""Check private presence evidence across released writers and runtimes.

Uses isolated homes and real guest execution. Does not enable portable capture.
The raw records are private test evidence, never snapshot metadata.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import sqlite3
import sys
import tempfile
import traceback


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "releases", "agent", "firmware", "image", "support", "output", "temp-root"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--with-mount", action="store_true", help="Also verify omitted mount ownership defaults")
    parser.add_argument("--with-network-defaults", action="store_true", help="Verify private evidence for omitted HTTP defaults")
    parser.add_argument("--with-unrecorded-secret-policy", action="store_true",
                        help="Reconstruct a historical policy lacking its enclosing action")
    parser.add_argument("--with-unrecorded-network-policy", action="store_true",
                        help="Keep omitted TLS/DNS settings unknown through real restart and label writes")
    args = parser.parse_args()
    sys.path.insert(0, str(args.support.resolve()))
    spec = importlib.util.spec_from_file_location("history", args.support / "lifecycle_evidence.py")
    history = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(history)
    history.install_termination_handler()
    args.output.mkdir(exist_ok=False)
    report = {"host": platform.platform(), "cases": [], "status": "running",
              "artifacts": {str(p): history.digest(p) for p in (args.binary, args.agent, args.firmware, args.image)}}
    report["harness_sha256"] = history.digest(Path(__file__))
    versions = ["current", "v0.6.0", "v0.6.6", "v0.6.7", "v0.6.18", "v0.7.8"]
    for version in versions:
        runtime = args.binary if version == "current" else args.releases / version / "msb"
        report["artifacts"][str(runtime)] = history.digest(runtime)
        home = Path(tempfile.mkdtemp(prefix="presence-", dir=args.temp_root))
        env = history.environment(runtime, args.firmware, home, args.agent)
        runner = history.Runner(args.binary, env, args.output / version)
        row = {"runtime": version, "home": str(home), "status": "running"}
        report["cases"].append(row)
        pids = set()

        def rows(sql):
            with sqlite3.connect((home / "db/msb.db").as_uri() + "?mode=ro", uri=True) as db:
                return db.execute(sql).fetchall()

        def config():
            return json.loads(rows("SELECT config FROM sandbox WHERE name='presence'")[0][0])

        def journal():
            return json.loads((home / "sandboxes/presence/last-active/state.json").read_text())

        def check_presence(source):
            evidence = source["field_presence"]
            assert evidence["thp"] == "madvise", evidence
            if not args.with_unrecorded_network_policy or source["network"].get("dns") is None:
                assert "dns" in evidence["absent_network"], evidence
                assert "tls" in evidence["absent_network"], evidence
            assert source["resources"].get("thp") is None
            if not args.with_unrecorded_network_policy:
                assert source["network"].get("dns") is None
            if args.with_network_defaults:
                assert {entry["kind"] for entry in evidence["nested_network"]} == {
                    "http_deny_message", "http_network_deny_message", "http_secret_deny_message"
                }, evidence
                for field in ("deny_message", "network_deny_message", "secret_deny_message"):
                    assert field not in source["network"]["http"]
            if args.with_mount:
                assert evidence["default_mount_ownership"] == [{"kind": "tmpfs", "guest": "/presence"}]
                options = source["mounts"][0]["options"]
                assert "override_uid" not in options and "override_gid" not in options

        def check_mount(label, cli):
            if args.with_mount:
                cli.run(label, "exec", "presence", "--", "sh", "-ec",
                        "grep -q ' /presence tmpfs ' /proc/mounts; echo writable >/presence/check; test -s /presence/check")

        def save_source(label, source):
            fd = os.open(args.output / version / (label + ".json"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as out:
                json.dump(source, out)

        try:
            runner.run("load", "image", "load", "--input", args.image)
            # The archive's tag is recorded in its Docker manifest, not assumed here.
            import tarfile
            with tarfile.open(args.image) as archive:
                image = json.load(archive.extractfile("manifest.json"))[0]["RepoTags"][0]
            runner.run("create", "create", image, "--name", "presence", "--memory", "256M",
                       "--max-memory", "256M", "--cpus", "1", "--max-cpus",
                       "1" if version == "v0.6.0" else "2", "--root-disk", "512M", "--max-duration", "5m",
                       *(["--tmpfs", "/presence:16M"] if args.with_mount else []))
            pids.update(pid for (pid,) in rows("SELECT pid FROM run") if pid)
            check_presence(config())
            check_mount("mount-created", runner)
            runner.run("seed", "exec", "presence", "--", "sh", "-ec", "echo retained >/root/presence-marker; sync")
            if args.with_unrecorded_secret_policy:
                runner.run("historical-stop", "stop", "presence")
                # Simulate an older saved record, only while this disposable VM is
                # stopped. There is no secret material; the absent scalar is the case.
                source = config()
                source["network"]["secrets"] = {"secrets": [], "passthrough_hosts": []}
                with sqlite3.connect(home / "db/msb.db") as db:
                    db.execute("UPDATE sandbox SET config=? WHERE name='presence'",
                               (json.dumps(source),))
                runner.run("historical-start", "start", "presence")
                # Start may intentionally retain the original desired JSON. A label
                # edit exercises the actual SDK rewrite that used to erase absence.
                runner.run("historical-rewrite", "modify", "presence", "--label", "rewrite=checked")
                rewritten = config()
                assert rewritten["network"]["secrets"]["violation_action"] == "block-and-log"
                assert rewritten["field_presence"]["secret_policy_unrecorded"] is True
                row["unrecorded_policy_survives_restart"] = True
                save_source("historical-rewritten-config", rewritten)
                if version == "current":
                    assert journal()["confirmed"]["source"]["field_presence"]["secret_policy_unrecorded"] is True
            if args.with_unrecorded_network_policy:
                runner.run("historical-network-stop", "stop", "presence")
                # Only this stopped disposable fixture is altered. Interception stays
                # disabled; missing settings use their unchanged decoder defaults.
                source = config()
                source["network"]["tls"] = {
                    "enabled": False, "intercepted_ports": [443], "bypass": [],
                    "block_quic_on_intercept": True, "upstream_ca_cert": [],
                    "scoped_upstream_ca_cert": [], "scoped_verify_upstream": [],
                    "intercept_ca": {"cert_path": None, "key_path": None}}
                source["network"]["dns"] = {"nameservers": []}
                with sqlite3.connect(home / "db/msb.db") as db:
                    db.execute("UPDATE sandbox SET config=? WHERE name='presence'",
                               (json.dumps(source),))
                runner.run("historical-network-start", "start", "presence")
                runner.run("historical-network-rewrite", "modify", "presence", "--label", "network-rewrite=checked")
                rewritten = config()
                assert rewritten["network"]["tls"]["verify_upstream"] is True
                assert rewritten["network"]["dns"]["rebind_protection"] is True
                assert rewritten["network"]["dns"]["query_timeout_ms"] == 5000
                missing = {"tls_verify_upstream", "dns_rebind_protection", "dns_query_timeout_ms"}
                assert set(rewritten.get("field_presence", {}).get("unrecorded_network_policy", [])) == missing
                row["unrecorded_network_policy_survives_restart"] = True
                save_source("historical-network-rewritten-config", rewritten)
                if version == "current":
                    retained = journal()["confirmed"]["source"]
                    assert set(retained["field_presence"]["unrecorded_network_policy"]) == missing
            if version == "current":
                first = journal()
                check_presence(first["confirmed"]["source"])
                save_source("current-source", first["confirmed"]["source"])
                old = history.Runner(args.releases / "v0.7.8/msb", env, args.output / "old-writer")
                old.run("inspect", "inspect", "presence", "--format", "json")
                old.run("modify", "modify", "presence", "--cpus", "2", "--format", "json")
                # A new runtime owns this mutation even when the requester is old. It
                # advances its journal and retains evidence only for unchanged fields.
                changed = journal()
                assert changed["confirmed"]["owner"] == first["confirmed"]["owner"]
                assert changed["confirmed"]["generation"] > first["confirmed"]["generation"]
                assert changed["confirmed"]["source"]["resources"]["cpus"] == 2
                check_presence(changed["confirmed"]["source"])
                active = json.loads(rows("SELECT active_config FROM sandbox WHERE name='presence'")[0][0])
                # Legacy catalog writers can drop unknown evidence. Capture's existing
                # exact-source guard then rejects this journal/catalog mismatch.
                row["legacy_active_config_matches_journal"] = active == changed["confirmed"]["source"]
                save_source("runtime-modified-source", changed["confirmed"]["source"])
                save_source("old-modified-config", config())
                assert "field_presence" not in config()
                old.run("exec", "exec", "presence", "--", "cat", "/root/presence-marker")
                old.run("stop", "stop", "presence")
                old.run("start", "start", "presence")
                assert journal()["confirmed"]["source"] is None
                pids.update(pid for (pid,) in rows("SELECT pid FROM run") if pid)
                old.run("exec-restarted", "exec", "presence", "--", "cat", "/root/presence-marker")
                check_mount("mount-old-restarted", old)
                old.run("stop2", "stop", "presence")
                runner.run("start-after-old", "start", "presence")
                # A current restart must not promote missing private evidence.
                source = journal()["confirmed"]["source"]
                assert source is not None
                assert source.get("field_presence", {}).get("thp") is None
                assert "dns" not in source.get("field_presence", {}).get("absent_network", [])
                assert not source.get("field_presence", {}).get("default_mount_ownership")
                if args.with_network_defaults:
                    assert not source.get("field_presence", {}).get("nested_network")
                save_source("new-after-old-source", source)
                row["runtime_tracks_old_request_and_old_restart_loses_evidence"] = True
            else:
                runner.run("stop", "stop", "presence")
                runner.run("start", "start", "presence")
                check_presence(config())
                # The old runtime has no durable source evidence; configuration alone
                # must never be treated as proof of its active generation.
                assert not (home / "sandboxes/presence/last-active/state.json").exists()
                row["old_runtime_operations_preserved"] = True
            pids.update(pid for (pid,) in rows("SELECT pid FROM run") if pid)
            runner.run("check", "exec", "presence", "--", "sh", "-ec", 'test "$(cat /root/presence-marker)" = retained')
            check_mount("mount-restarted", runner)
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
            history.finish_saved_evidence(runner, {"presence": row["cleanup"]}, row,
                                          report, args.output, audit, prepare=collect_pids)
    report["status"] = "passed" if all(row["status"] == "passed" for row in report["cases"]) else "failed"
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(report["status"], flush=True)
    return report["status"] != "passed"


if __name__ == "__main__":
    sys.exit(main())
