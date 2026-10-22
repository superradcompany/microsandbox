#!/usr/bin/env python3
"""Verify destination proxy/policy on a workload already running at full capture.

The resumed workload starts no new exec session. Local fixtures observe its traffic
before and after create returns; the source sandbox is removed before every restore.
This does not promise migration of an existing remote TCP session.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import shlex
import tempfile
import time


spec = importlib.util.spec_from_file_location(
    "snapshot_proxy", Path(__file__).with_name("snapshot-launch-proxy.py"))
proxy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxy)


TrackedSocksFixture = proxy.SocksFixture
ALLOW_CASES = ("allow", "http-connect", "socks4", "socks4-user")


def events(server):
    with server.events_lock:
        return list(server.events)


def sealed_full(group):
    # Full state includes extensionless RAM/device objects and raw/qcow2 disks.
    # A suffix allowlist would silently leave most of the captured payload unchecked.
    result = {}
    for path in sorted(group.rglob("*")):
        relative = path.relative_to(group)
        if relative.parts[0] == ".msb-leases" or relative == Path(".group.lock"):
            continue
        if path.is_symlink():
            raise RuntimeError("unexpected symlink in captured group")
        if path.is_file():
            result[str(relative)] = proxy.digest(path)
    return result


def wait_until(check, message, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.05)
    raise RuntimeError(message)


def guest_progress(runner, label, name, require_success=False):
    # Observe a process restored from RAM, rather than making exec perform a network
    # request itself. Waiting for two more iterations excludes an old buffered result.
    condition = (' && [ "$success" -ge "$((success_before + 2))" ]'
                 if require_success else "")
    _, stdout = runner.run(label, "exec", name, "--", "sh", "-ec",
                           'set -- $(cat /root/policy-attempts); before=$1; success_before=$2; '
                           'for i in $(seq 1 150); do '
                           'set -- $(cat /root/policy-attempts); now=$1; success=$2; '
                           'if [ "$now" -ge "$((before + 2))" ]' + condition + '; then '
                           'printf "%s %s %s %s\\n" "$before" "$now" "$success_before" "$success"; '
                           'exit 0; fi; '
                           'sleep 0.1; done; exit 1')
    values = [int(item) for item in stdout.split()]
    if (len(values) != 4 or values[1] < values[0] + 2
            or (require_success and values[3] < values[2] + 2)):
        raise RuntimeError("resumed workload lacks independently observed progress")
    return values


def assert_policy(label, observed):
    """Require positive control traffic as well as meaningful negative observations."""
    if label in ALLOW_CASES:
        expected_auth = "not-required" if label == "http-connect" else "accepted"
        if not any(row["http"] and row["authenticated"]
                   and row.get("authentication") == expected_auth for row in observed):
            raise RuntimeError("allowed resumed workload never reached destination proxy")
    else:
        if any(row["http"] for row in observed):
            raise RuntimeError("refused resumed request reached destination HTTP handler")
        if label in ("deny", "missing-credential") and observed:
            raise RuntimeError("pre-connection refusal contacted the destination proxy")
        if label == "wrong-credential" and not any(
                row.get("authentication") == "rejected" for row in observed):
            raise RuntimeError("wrong-credential case did not exercise authentication")


def qualify(args):
    args.output.mkdir(parents=True, exist_ok=False)
    home = Path(tempfile.mkdtemp(prefix="msb-rp-", dir=args.temp_root)).resolve()
    runner = proxy.Runner(args, home)
    names, servers = set(), []
    archive_hash = proxy.digest(args.archive)
    report = {
        "status": "running", "home": str(home), "cases": [], "cleanup": {},
        "candidate_sha256": proxy.digest(args.candidate),
        "agent_sha256": proxy.digest(args.agent),
        "firmware_sha256": proxy.digest(args.firmware),
        "archive_sha256": archive_hash,
        "harness_sha256": proxy.digest(Path(__file__)),
        "fixture_sha256": proxy.digest(Path(__file__).with_name("snapshot-launch-proxy.py")),
    }
    try:
        runner.run("seed", "snapshot", "load", "seed", "--file", args.archive)
        source_proxy = TrackedSocksFixture()
        servers.append(source_proxy)
        names.add("source")
        # An isolated host has no external route. A loopback-only ephemeral listener
        # requests the allocator's private IPv4 path without opening external egress.
        runner.run("source-create", "create", "--from-snapshot", "seed", "--name", "source",
                   "--pull", "never", "--memory", "256M", "--max-duration", "10m",
                   "--proxy", source_proxy.url, "--net-rule", "allow@198.51.100.0/24",
                   "--no-dns-rebind-protection", "--port", "127.0.0.1:0:18080")
        runner.run("source-inspect", "inspect", "source", "--format", "json")
        runner.run("source-proxy-control", "exec", "source", "--", "sh", "-ec",
                   f'test "$(wget -T 3 -qO- http://{proxy.TARGET}:{proxy.TARGET_PORT}/probe)" '
                   '= snapshot-destination-proxy')
        wait_until(lambda: any(row["http"] for row in events(source_proxy)),
                   "source control lacks proxy evidence")
        initial_requests = len(events(source_proxy))
        # Atomic rename makes the counter readable while the background shell updates it.
        workload = (
            'n=0; s=0; echo "0 0" > /root/policy-attempts; '
            'while :; do '
            f'if wget -T 2 -qO /root/policy-body http://{proxy.TARGET}:{proxy.TARGET_PORT}/probe '
            '&& [ "$(cat /root/policy-body)" = snapshot-destination-proxy ]; then s=$((s + 1)); fi; '
            'n=$((n + 1)); printf "%s %s\\n" "$n" "$s" > /root/policy-next; '
            'mv /root/policy-next /root/policy-attempts; sleep 0.2; done')
        runner.run("source-workload", "exec", "source", "--", "sh", "-ec",
                   "nohup sh -c " + shlex.quote(workload)
                   + " </dev/null >/root/policy-workload.log 2>&1 &")
        wait_until(lambda: len(events(source_proxy)) > initial_requests,
                   "source workload never reached its proxy")
        guest_progress(runner, "source-progress", "source", require_success=True)
        runner.run("capture", "snapshot", "create", "full", "--sandbox", "source",
                   "--full", "--integrity")
        runner.run("source-stop", "stop", "source")
        runner.run("source-remove", "rm", "source")
        names.remove("source")
        # Keep the old endpoint alive to detect an accidental fallback, but the source
        # runtime itself is gone. Finish its handler callbacks before freezing the count.
        wait_until(source_proxy.idle, "source proxy handlers did not finish")
        source_events = events(source_proxy)
        sealed = sealed_full(home / "snapshots/full")
        if not sealed:
            raise RuntimeError("full capture has no immutable files to check")
        report["sealed_before"] = sealed
        report["source_requests"] = len(source_events)
        for label in (*ALLOW_CASES, "deny", "wrong-credential", "missing-credential"):
            if label == "http-connect":
                server = proxy.HttpFixture()
            elif label.startswith("socks4"):
                server = proxy.Socks4Fixture(b"fixture-user" if label == "socks4-user" else None)
            else:
                server = proxy.SocksFixture(b"destination-only-value")
            servers.append(server)
            names.add(label)
            flags = ["--from-snapshot", "full", "--name", label, "--pull", "never",
                     "--proxy", server.url, "--no-dns-rebind-protection",
                     "--port", "127.0.0.1:0:18080"]
            flags += (["--net-default", "deny"] if label == "deny"
                      else ["--net-rule", "allow@198.51.100.0/24"])
            runner.env.pop(proxy.PASSWORD_ENV, None)
            if server.protocol == "socks5":
                if label != "missing-credential":
                    runner.env[proxy.PASSWORD_ENV] = (
                        "incorrect-fixture-value" if label == "wrong-credential"
                        else "destination-only-value")
                flags += ["--socks5-username", "fixture",
                          "--socks5-password-env", proxy.PASSWORD_ENV]
            if label == "socks4-user":
                flags += ["--socks4-user-id", "fixture-user"]
            row = {"case": label, "status": "running"}
            report["cases"].append(row)
            code, _ = runner.run(label + "-create", "create", *flags, expected=None)
            row["launch_exit"] = code
            row["events_at_create_return"] = events(server)
            if label == "missing-credential":
                diagnostic = (args.output / (label + "-create.stderr")).read_text()
                if code == 0 or proxy.PASSWORD_ENV not in diagnostic:
                    raise RuntimeError("missing credential did not cause its expected refusal")
            else:
                if code != 0:
                    raise RuntimeError(f"{label} failed to resume; inspect create stderr")
                row["guest_iterations"] = guest_progress(
                    runner, label + "-progress", label, require_success=label in ALLOW_CASES)
                if label in ALLOW_CASES:
                    wait_until(lambda: any(event["http"] for event in events(server)),
                               "resumed workload never used the replacement proxy")
            inspect, _ = runner.run(label + "-inspect", "inspect", label,
                                    "--format", "json", expected=None)
            if label != "missing-credential" and inspect != 0:
                raise RuntimeError("cannot inspect the resumed sandbox before stopping it")
            if inspect == 0:
                runner.run(label + "-stop", "stop", label)
                runner.run(label + "-remove", "rm", label)
            names.remove(label)
            # A negative assertion is valid only after the guest can no longer
            # initiate traffic and every accepted handler has recorded its result.
            server.close()
            row["events"] = events(server)
            assert_policy(label, row["events"])
            wait_until(source_proxy.idle, "source proxy handlers did not finish after resume")
            if events(source_proxy) != source_events:
                raise RuntimeError("resumed workload fell back to the source proxy")
            row["status"] = "passed"
        source_proxy.close()
        if events(source_proxy) != source_events:
            raise RuntimeError("late resumed traffic reached the source proxy")
        report["sealed_after"] = sealed_full(home / "snapshots/full")
        if report["sealed_after"] != sealed:
            raise RuntimeError("destination workflow modified the full checkpoint")
        report["sealed_unchanged"] = True
        report["status"] = "passed"
    except BaseException as error:
        report["status"] = "failed"
        report["error"] = str(error)
        if "source" in names and isinstance(error, Exception):
            try:
                runner.run("source-failure-diagnostics", "exec", "source", "--", "sh", "-c",
                           "id; ip address; ip route; cat /root/policy-attempts; "
                           "head -c 4096 /root/policy-workload.log", expected=None)
            except Exception as diagnostic:
                report["diagnostic_error"] = type(diagnostic).__name__
        raise
    finally:
        for name in sorted(names):
            for operation in ("stop", "rm"):
                try:
                    code, _ = runner.run(f"cleanup-{name}-{operation}", operation,
                                         name, expected=None)
                    report["cleanup"][f"{name}/{operation}"] = code
                except Exception as error:
                    report["cleanup"][f"{name}/{operation}"] = type(error).__name__
        for index, server in enumerate(servers):
            try:
                server.close()
            except Exception as error:
                report["cleanup"][f"fixture/{index}"] = type(error).__name__
        report["proxy_events"] = [events(server) for server in servers]
        proxy.audit_inputs_and_catalog(report, args.archive, archive_hash, home)
        (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    if report["status"] != "passed":
        raise RuntimeError("qualification cleanup failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("candidate", "agent", "firmware", "archive", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--temp-root", type=Path, default=Path("/tmp"))
    args = parser.parse_args()
    for name, value in vars(args).items():
        if isinstance(value, Path):
            setattr(args, name, value.resolve())
    proxy.install_termination_handler()
    qualify(args)


if __name__ == "__main__":
    main()
