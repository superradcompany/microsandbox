#!/usr/bin/env python3
"""Live shared virtio-fs and network reconnect contract checks in a disposable home.

Usage: checkpoint-shared-resources.py MSB_BIN AGENTD LIBKRUNFW fs|net
Retains JSON evidence. Only task-owned sandboxes and temporary host paths are used.
"""

import concurrent.futures
import json
import os
from pathlib import Path
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

binary, agent, firmware, mode = sys.argv[1:5]
binary, agent, firmware = (str(Path(path).resolve()) for path in (binary, agent, firmware))
assert mode in ("fs", "net")
root = Path(tempfile.mkdtemp(prefix="cbh-shared-", dir=os.environ.get("CBH_TEST_ROOT"))).resolve()
# Windows named pipes are machine-wide. Distinct homes alone do not isolate
# concurrent fixture sandbox names, so give every run its own logical aliases.
aliases = {name: f"{mode}-{root.name.removeprefix('cbh-shared-')}-{name}"
           for name in ("source", "child", "strict-refused", "forked", "branched", "grandchild", "archived")}
env = dict(os.environ, MSB_HOME=str(root / "home"), MSB_AGENTD_PATH=agent,
           MSB_LIBKRUNFW_PATH=firmware, MSB_PATH=binary)
owned, records = [], []
record_lock = threading.Lock()
client = None
server = None
print(f"Evidence: {root}", flush=True)


def record(item):
    with record_lock:
        records.append(item)
        (root / "results.json").write_text(json.dumps(records, indent=2))
    print(json.dumps({key: item[key] for key in ("label", "code", "seconds") if key in item}), flush=True)


def run(label, *args, check=True, timeout=180):
    args = tuple(aliases.get(arg, arg) for arg in args)
    start = time.monotonic()
    result = subprocess.run([binary, *args], env=env, capture_output=True,
                            text=True, timeout=timeout)
    record(dict(label=label, args=args, code=result.returncode,
                seconds=time.monotonic() - start, stdout=result.stdout, stderr=result.stderr))
    if check and result.returncode:
        raise RuntimeError(f"{label}: {result.stderr}")
    return result


def guest(label, name, script, check=True):
    return run(label, "exec", name, "--", "sh", "-ec", script, check=check)


def create(name, *args):
    owned.append(name)
    return run("create-" + name, "create", "--name", name, *args)


def wait_until(predicate, timeout=10):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError("observable condition did not become true")
        time.sleep(0.05)


try:
    if mode == "fs":
        workspace = root / "workspace"
        workspace.mkdir()
        (workspace / "tracked").write_text("captured\n")
        (workspace / "overwrite").write_text("initial\n")
        create("source", "alpine", "--memory", "256M", "--max-memory", "256M",
               "--root-disk", "256M", "--mount-dir", f"{workspace}:/workspace")
        guest("populate-captured-cache", "source", "cat /workspace/tracked; cat /workspace/overwrite")
        run("capture", "snapshot", "create", "baseline", "--group", "shared",
            "--from-sandbox", "source", "--full")
        create("child", "--from-snapshot", "shared:baseline")
        # Independent concurrent writes prove both VMs still address the original export.
        # They do not claim atomic appends or lost-update protection on a shared file.
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            jobs = []
            for name in ("source", "child"):
                # Complete client initialization one at a time, then release
                # both guest writers together. This isolates filesystem
                # concurrency from the CLI's separate startup/migration lease.
                jobs.append(pool.submit(guest, "concurrent-" + name, name,
                                        f"touch /workspace/{name}.ready; "
                                        "while [ ! -e /workspace/start ]; do sleep 0.02; done; "
                                        f"i=0; while [ $i -lt 50 ]; do echo {name}-$i >> /workspace/{name}.log; i=$((i+1)); done; sync"))
                wait_until(lambda: (workspace / f"{name}.ready").exists())
            (workspace / "start").touch()
            for job in jobs:
                job.result()
        for name in ("source", "child"):
            assert (workspace / f"{name}.log").read_text().splitlines() == [f"{name}-{i}" for i in range(50)]
        guest("source-overwrite", "source", "printf source > /workspace/overwrite; sync")
        assert (workspace / "overwrite").read_text() == "source"
        guest("child-overwrite", "child", "printf child > /workspace/overwrite; sync")
        assert (workspace / "overwrite").read_text() == "child"
        # Strict admission is not a lifetime lock or a snapshot of the host namespace.
        (workspace / "host-created-after-restore").write_text("host-new\n")
        for name in ("source", "child"):
            assert guest("host-new-visible-" + name, name, "cat /workspace/host-created-after-restore").stdout.strip() == "host-new"
        (workspace / "tracked").write_text("host-changed-after-restore\n")
        for name in ("source", "child"):
            # Saved clean cache may still return old bytes. Record, do not promise eager invalidation.
            # Cached attributes and pages can expire independently: even a new
            # file prefix with an old length is possible. This is an observation,
            # not a coherence guarantee for unsynchronized external writes.
            guest("changed-cache-observation-" + name, name, "cat /workspace/tracked", check=False)
        owned.append("strict-refused")
        refused = run("strict-changed-before-restore", "create", "--name", "strict-refused",
                      "--from-snapshot", "shared:baseline", check=False)
        assert refused.returncode != 0, "strict restore accepted incompatible tracked host state"
        # Preserve the actual diagnostic: refusal must concern external state, not an unrelated failure.
        assert any(word in refused.stderr.lower() for word in ("stale", "changed", "identity", "mount"))
        record(dict(label="shared-fs-contract", concurrent_host_files=True,
                    shared_overwrite=True, post_restore_host_namespace_visible=True,
                    strict_restore_refused=True))
    else:
        messages = []
        connections = []
        message_lock = threading.Lock()

        class Echo(socketserver.StreamRequestHandler):
            def handle(self):
                identity = id(self)
                with message_lock:
                    connections.append(identity)
                while line := self.rfile.readline():
                    message = line.decode().strip()
                    with message_lock:
                        messages.append((identity, message))
                    self.wfile.write(f"{identity}:{message}\n".encode())
                    self.wfile.flush()
                    if message == "child-new" or message.startswith("probe-"):
                        return

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True

        server = Server(("127.0.0.1", 0), Echo)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.server_address[1]
        create("source", "alpine", "--memory", "256M", "--max-memory", "256M", "--root-disk", "256M",
               "--net-rule", "allow@host")
        guest("fifo", "source", "mkfifo /dev/shm/input")
        client = subprocess.Popen([binary, "exec", aliases["source"], "--", "sh", "-ec",
                                   f"exec 3<>/dev/shm/input; nc host.microsandbox.internal {port} <&3 > /dev/shm/replies"],
                                  env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        # Wait for the long-lived client's startup and actual TCP connect,
        # rather than racing a second CLI initialization or writing to a FIFO
        # before its reader has opened it.
        wait_until(lambda: bool(connections))
        guest("send-before", "source", "exec 3<>/dev/shm/input; printf 'before\n' >&3")
        wait_until(lambda: any(message == "before" for _, message in messages))
        wait_until(lambda: "before" in guest("confirm-before", "source", "cat /dev/shm/replies").stdout)
        hosts = guest("source-host-aliases", "source", "cat /etc/hosts").stdout
        gateways = {"ipv6" if ":" in line.split()[0] else "ipv4": line.split()[0]
                    for line in hosts.splitlines() if len(line.split()) > 1 and line.split()[1] == "host.microsandbox.internal"}
        assert set(gateways) == {"ipv4", "ipv6"}, "this dual-stack fixture requires both guest address families"

        def probe(name):
            for family, address in gateways.items():
                message = f"probe-{name}-{family}"
                reply = guest(f"{name}-{family}-reconnect", name,
                              f"printf '{message}\n' | nc -w 3 {address} {port}")
                assert message in reply.stdout
            guest(name + "-neighbours", name, "ip neigh; ip -6 neigh")

        # Warm both ARP and IPv6 ND before capture. A fresh cache would hide
        # the gateway identity mismatch this regression is meant to catch.
        probe("source")
        run("capture", "snapshot", "create", "baseline", "--group", "network",
            "--from-sandbox", "source", "--full")
        guest("send-source-after", "source", "exec 3<>/dev/shm/input; printf 'source-after\n' >&3")
        wait_until(lambda: any(message == "source-after" for _, message in messages))
        source_ids = {identity for identity, message in messages if message in ("before", "source-after")}
        assert len(source_ids) == 1, "capture replaced the source's external connection"
        create("child", "--from-snapshot", "network:baseline", "--net-rule", "allow@host")
        guest("send-inherited-child", "child", "exec 3<>/dev/shm/input; printf 'child-old\n' >&3")
        time.sleep(2)
        assert not any(message == "child-old" for _, message in messages), "child unexpectedly reused source connection"
        guest("child-network-state", "child", "ip addr; ip route; ip neigh; cat /etc/hosts")
        new = guest("fresh-child-connection", "child", f"printf 'child-new\n' | nc -w 10 host.microsandbox.internal {port}", check=False)
        record(dict(label="network-observed-messages", messages=messages))
        if new.returncode:
            guest("child-network-after-failure", "child", "ip addr; ip route; ip neigh", check=False)
            run("child-system-logs", "logs", "--source", "system", "child", check=False, timeout=10)
            # Diagnostic only: a retry after neighbour invalidation must never
            # turn the original reconnect failure into a qualification pass.
            guest("diagnostic-clear-neighbours", "child", "ip neigh flush dev eth0", check=False)
            guest("diagnostic-reconnect", "child", f"printf 'child-new\n' | nc -w 10 host.microsandbox.internal {port}", check=False)
            record(dict(label="network-diagnostic-messages", messages=messages))
        guest("source-still-live", "source", "exec 3<>/dev/shm/input; printf 'source-final\n' >&3")
        wait_until(lambda: any(message == "source-final" for _, message in messages))
        record(dict(label="network-contract", messages=messages,
                    inherited_child_observation_seconds=2,
                    note="No inherited child roundtrip during observation; this does not bound TCP timeout latency."))
        assert new.returncode == 0, "new child TCP connection failed"
        assert "child-new" in new.stdout
        assert any(message == "child-new" and identity not in source_ids for identity, message in messages)
        probe("child")
        create("forked", "--from-snapshot", "network:baseline", "--forked", "--net-rule", "allow@host")
        probe("forked")
        owned.append("branched")
        run("branch-source", "branch", "source", "--name", "branched")
        probe("branched")
        owned.append("grandchild")
        run("branch-child", "branch", "branched", "--name", "grandchild")
        probe("grandchild")
        archive = root / "network.msb"
        run("capture-archive", "snapshot", "create", "portable", "--from-sandbox", "child", "--full", "-o", str(archive))
        create("archived", "--from-snapshot", str(archive), "--forked", "--net-rule", "allow@host")
        probe("archived")
        # Keep siblings alive together and prove fresh host TCP state remains
        # independent even though all retain one virtual gateway identity.
        for name in ("child", "forked", "branched", "grandchild", "archived"):
            probe(name)
        guest("source-after-all-children", "source", "exec 3<>/dev/shm/input; printf 'source-final-again\n' >&3")
        wait_until(lambda: any(message == "source-final-again" for _, message in messages))
        assert all(identity in source_ids for identity, message in messages if message.startswith("source-"))
        record(dict(label="dual-stack-restores-and-branches", messages=messages))
finally:
    for name in reversed(owned):
        try:
            stopped = run("cleanup-stop-" + name, "stop", name, "--timeout", "10", check=False, timeout=20)
            if stopped.returncode:
                run("cleanup-kill-" + name, "stop", "--force", name, check=False, timeout=20)
            run("cleanup-remove-" + name, "remove", name, check=False, timeout=20)
        except Exception as error:
            record(dict(label="cleanup-needs-attention", name=name, error=str(error)))
    if client is not None:
        try:
            client.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            client.kill()
            client.communicate()
    if server is not None:
        server.shutdown()
        server.server_close()
    catalog = run("postflight-catalog", "list", "--format", "json", check=False)
    print(f"Evidence retained: {root}", flush=True)

# Only reached if the actual assertions succeeded; cleanup cannot manufacture
# a pass after a capture, restore, or reconnect failure.
assert catalog.returncode == 0 and json.loads(catalog.stdout) == [], "owned sandboxes remain after cleanup"
assert not any(item["label"] == "cleanup-needs-attention" for item in records)
record(dict(label="PASS", mode=mode))
