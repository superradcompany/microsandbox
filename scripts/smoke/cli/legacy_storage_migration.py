#!/usr/bin/env python3
"""Produce real legacy storage, then qualify a candidate without rewriting fixture paths.

Run ``produce --output NEW --producer /path/to/0.7.11/msb --producer-firmware FW``
first, then ``verify --output SAME --candidate /path/to/msb --candidate-firmware FW``.
Only the explicitly reserved disposable home is used. Production failures, cold child
starts and full execution restore are recorded separately. This is a live VM test, not
a replacement for deterministic transaction fault/cancellation tests.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import stat
import subprocess
import sys
import time


SCHEMA = "microsandbox.legacy-storage-smoke/1"
MARKER_TIME = 1577934245
IMAGE = "mirror.gcr.io/library/alpine:3.20"


def digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def growth_target(sandbox: Path, configured_mib: int = 0) -> str:
    """Choose a larger fixture disk size, including restores with the default 4 GiB root."""
    journal = json.loads((sandbox / "root-disk.json").read_text())
    head = journal["layers"][-1]
    path = Path(head["path"])
    if not path.is_absolute():
        path = sandbox / path
    if head["format"] == "qcow2":
        with path.open("rb") as disk:
            header = disk.read(32)
        if len(header) != 32 or header[:4] != b"QFI\xfb":
            raise ValueError("candidate published an invalid QCOW head")
        capacity = int.from_bytes(header[24:32], "big")
    elif head["format"] == "raw":
        capacity = path.stat().st_size
    else:
        raise ValueError("unsupported fixture disk format")
    capacity_mib = (capacity + 1024 * 1024 - 1) // (1024 * 1024)
    return f"{max(384, max(capacity_mib, configured_mib) + 64)}M"


def environment(binary: Path, firmware: Path, home: Path) -> dict[str, str]:
    result = {key: value for key, value in os.environ.items() if not key.startswith("MSB_")}
    result.update(MSB_HOME=str(home), MSB_PATH=str(binary), MSB_LIBKRUNFW_PATH=str(firmware),
                  MSB_BACKEND="local", MSB_CONFIG_PATH=str(home / "unused-config.json"), NO_COLOR="1")
    return result


def inventory(directory: Path, external: list[str] = ()) -> dict[str, str]:
    """Hash disk bytes without following guest links, including explicit external fixtures."""
    files = {}
    for parent, _, names in os.walk(directory, followlinks=False):
        for name in names:
            path = Path(parent) / name
            if path.suffix not in (".raw", ".ext4", ".qcow2"):
                continue
            if stat.S_ISREG(path.lstat().st_mode):
                files[str(path.relative_to(directory))] = digest(path)
    for value in external:
        path = Path(value)
        if stat.S_ISREG(path.lstat().st_mode):
            files["external:" + str(path)] = digest(path)
    return files


def guest_seed(value: str, owned: tuple[str, ...] = ()) -> str:
    script = f"printf '%s' {shlex.quote(value)} >/migration-marker; "
    script += "chown 1001:1002 /migration-marker; chmod 640 /migration-marker; "
    script += "TZ=UTC touch -t 202001020304.05 /migration-marker; "
    for path in owned:
        script += f"printf '%s' {shlex.quote(value + ':' + path)} >{shlex.quote(path + '/migration-marker')}; "
    return script + "sync"


def guest_check(value: str, owned: tuple[str, ...] = (), protected: bool = False) -> str:
    script = f"test \"$(cat /migration-marker)\" = {shlex.quote(value)}; "
    script += f"test \"$(stat -c '%u:%g:%a:%Y' /migration-marker)\" = 1001:1002:640:{MARKER_TIME}; "
    for path in owned:
        script += f"test \"$(cat {shlex.quote(path + '/migration-marker')})\" = {shlex.quote(value + ':' + path)}; "
    if protected:
        script += "test ! -e /.msb/root-disk.json; test ! -e /.msb/owned-disks; "
        script += "test ! -e /.msb/checkpoints; test ! -e /.msb/checkpoint-store; "
    return script + "true"


class Harness:
    def __init__(self, output: Path, binary: Path, firmware: Path, phase: str, runtime: Path | None = None):
        self.output = output.resolve()
        self.home = self.output / "home"
        self.binary = binary.resolve(strict=True)
        self.firmware = firmware.resolve(strict=True)
        self.runtime = runtime.resolve(strict=True) if runtime else None
        self.phase = phase
        self.log = self.output / phase
        self.log.mkdir(exist_ok=False)
        (self.log / "artifacts.json").write_text(json.dumps({
            "binary": str(self.binary), "binary_sha256": digest(self.binary),
            "firmware": str(self.firmware), "firmware_sha256": digest(self.firmware),
            "runtime": str(self.runtime) if self.runtime else str(self.binary),
            "runtime_sha256": digest(self.runtime) if self.runtime else digest(self.binary),
            "platform": platform.platform(), "started_unix": time.time(),
        }, indent=2))
        self.commands = []
        self.names = []

    def run(self, label: str, *args: str, required: bool = True, timeout: int = 180,
            binary: Path | None = None, firmware: Path | None = None) -> subprocess.CompletedProcess:
        executable = binary or self.binary
        selected_environment = environment(executable, firmware or self.firmware, self.home)
        if self.runtime and binary is None:
            selected_environment["MSB_PATH"] = str(self.runtime)
        start = time.monotonic()
        try:
            result = subprocess.run([str(executable), *args], cwd=self.output,
                                    env=selected_environment,
                                    capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            def text(value):
                return value.decode(errors="replace") if isinstance(value, bytes) else value or ""
            result = subprocess.CompletedProcess(args, 124, text(error.stdout), text(error.stderr) + "\nHARNESS TIMEOUT")
        # Sequence numbers preserve evidence even when cleanup retries use the same label.
        prefix = f"{len(self.commands):03d}-{label}"
        (self.log / (prefix + ".stdout")).write_text(result.stdout, encoding="utf-8")
        (self.log / (prefix + ".stderr")).write_text(result.stderr, encoding="utf-8")
        self.commands.append(dict(label=label, args=args, binary=str(executable), exit=result.returncode,
                                  seconds=round(time.monotonic() - start, 3)))
        (self.log / "commands.json").write_text(json.dumps(self.commands, indent=2))
        print(f"{self.phase}: {label}: exit {result.returncode}", flush=True)
        if required and result.returncode:
            raise RuntimeError(f"{label}: {result.stderr}")
        return result

    def guest(self, label: str, name: str, script: str):
        return self.run(label, "exec", name, "--", "sh", "-ec", script)

    def stop(self, name: str, required: bool = True):
        return self.run(name + "-stop", "stop", name, required=required)

    def create(self, name: str, owned: tuple[str, ...] = (), root: str = "256M", directory: bool = False,
               readonly: bool = False):
        self.names.append(name)
        mounts = []
        for guest in owned:
            mounts.extend(["--mount-owned", guest if directory else guest + ":kind=disk,size=128M" + (",ro" if readonly else "")])
        self.run(name + "-create", "create", "--name", name, "--memory", "256M", "--root-disk", root,
                 *mounts, IMAGE)
        self.guest(name + "-seed", name, guest_seed("latest:" + name, () if readonly else owned))

    def capture(self, name: str, label: str, full: bool = False):
        self.run(name + "-capture-" + label, "snapshot", "create", label, "--sandbox", name,
                 *(["--full"] if full else []))
        return name + ":" + label

    def shutdown(self):
        for name in dict.fromkeys(self.names):
            self.run(name + "-cleanup", "stop", name, "--force", required=False, timeout=30)
        self.run("final-list", "list", required=False, timeout=30)


def reserve_output(output: Path):
    # The disposable test root is also a catalog ancestor; an ambient group-writable
    # umask must not turn every intended storage scenario into unsafe-home refusal.
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    (output / "fixture-owner.json").write_text(json.dumps({"schema": SCHEMA, "path": str(output.resolve())}))


def read_manifest(output: Path) -> dict:
    owner = json.loads((output / "fixture-owner.json").read_text())
    if owner != {"schema": SCHEMA, "path": str(output.resolve())}:
        raise ValueError("fixture ownership or absolute location changed; do not reuse or relocate homes")
    manifest = json.loads((output / "fixtures.json").read_text())
    if manifest["schema"] != SCHEMA or manifest["output"] != str(output.resolve()):
        raise ValueError("invalid fixture manifest or relocated home")
    return manifest


def produce(args):
    reserve_output(args.output)
    harness = Harness(args.output, args.producer, args.producer_firmware, "produce")
    cases = []
    manifest = dict(schema=SCHEMA, output=str(harness.output), platform=platform.platform(),
                    producer=str(harness.binary), producer_sha256=digest(harness.binary),
                    firmware=str(harness.firmware), firmware_sha256=digest(harness.firmware), cases=cases)

    def save():
        (harness.output / "fixtures.json").write_text(json.dumps(manifest, indent=2))

    def remember(name, owned=(), expected="start", kind="release-produced", external=(), **extra):
        sandbox = harness.home / "sandboxes" / name
        journal = sandbox / "runtime/root-disk.json"
        if journal.exists() and not journal.is_symlink() and journal.is_file():
            (harness.log / (name + "-root-journal.json")).write_bytes(journal.read_bytes())
        case = dict(name=name, owned=owned, expected=expected, kind=kind, value="latest:" + name,
                    external=external, before=inventory(sandbox, external), **extra)
        cases.append(case)
        save()

    def scenario(name, action):
        try:
            action()
        except Exception as error:
            cases.append(dict(name=name, setup_error=str(error)))
            save()
            harness.stop(name, required=False)

    try:
        harness.run("producer-version", "--version")
        for name, owned, root, directory in [
            ("simple", (), "256M", False), ("flat", (), "flat:256M", False),
            ("owned-dir", ("/data",), "256M", True), ("owned-raw", ("/data",), "256M", False),
            ("owned-multi", ("/data", "/logs"), "256M", False),
        ]:
            def simple(name=name, owned=owned, root=root, directory=directory):
                harness.create(name, owned, root, directory)
                harness.stop(name)
                remember(name, owned)
            scenario(name, simple)

        def readonly_owned():
            harness.create("owned-readonly", ("/data",), readonly=True)
            harness.guest("owned-readonly-policy", "owned-readonly", "if touch /data/forbidden; then exit 1; fi")
            harness.stop("owned-readonly")
            remember("owned-readonly", readonly="/data")
        scenario("owned-readonly", readonly_owned)

        for name, full, owned, delete_source in [
            ("disk-child", False, (), False), ("full-child", True, (), False),
            ("owned-child", False, ("/data",), False), ("orphan-child", False, (), True),
        ]:
            def child(name=name, full=full, owned=owned, delete_source=delete_source):
                source = name + "-source"
                harness.create(source, owned)
                if full:
                    harness.guest(source + "-ram", source, "echo retained-ram >/dev/shm/migration-memory")
                snapshot = harness.capture(source, "saved", full)
                harness.names.append(name)
                harness.run(name + "-restore", "restore", snapshot, "--name", name)
                if full:
                    harness.guest(name + "-old-execution-restore", name,
                                  "test \"$(cat /dev/shm/migration-memory)\" = retained-ram")
                    manifest["execution_snapshot"] = snapshot
                harness.guest(name + "-post-restore-write", name, guest_seed("latest:" + name, owned))
                harness.stop(name)
                harness.guest(source + "-post-snapshot-write", source, guest_seed("latest:" + source, owned))
                harness.stop(source)
                # Old restart is required evidence that the produced selection really works.
                harness.run(name + "-old-restart", "start", name)
                harness.guest(name + "-old-restart-data", name, guest_check("latest:" + name, owned))
                harness.stop(name)
                if delete_source:
                    harness.run(name + "-delete-source-snapshot", "snapshot", "remove", snapshot)
                    harness.run(name + "-delete-parent", "remove", source)
                else:
                    remember(source, owned)
                remember(name, owned, full_child_cold_restart=full)
            scenario(name, child)

        def fork():
            harness.create("fork-source")
            harness.names.append("fork-child")
            harness.run("fork-produce", "fork", "fork-source", "--name", "fork-child")
            harness.guest("fork-child-latest", "fork-child", guest_seed("latest:fork-child"))
            harness.guest("fork-source-latest", "fork-source", guest_seed("latest:fork-source"))
            for name in ("fork-child", "fork-source"):
                harness.stop(name)
                remember(name)
        scenario("fork-child", fork)

        for name, operation in [("stopped-grown", "stopped"), ("live-grown", "live"),
                                ("compacted", "compact"), ("owned-compacted", "compact")]:
            def transformed(name=name, operation=operation):
                owned = ("/data",) if name == "owned-compacted" else ()
                harness.create(name, owned)
                if operation == "compact":
                    harness.capture(name, "one")
                    harness.guest(name + "-middle-write", name, guest_seed("middle:" + name, owned))
                    harness.capture(name, "two")
                    harness.guest(name + "-latest-write", name, guest_seed("latest:" + name, owned))
                if operation != "live":
                    harness.stop(name)
                harness.run(name + "-modify", "modify", name,
                            *(["--compact"] if operation == "compact" else ["--root-disk", "320M"]))
                if operation != "live":
                    harness.run(name + "-old-restart", "start", name)
                harness.guest(name + "-old-data", name, guest_check("latest:" + name, owned))
                harness.stop(name)
                remember(name, owned)
            scenario(name, transformed)

        # Keep attack aliases away from positive fixtures: an intentionally planted sibling
        # hardlink must not make the otherwise simple success fixture itself ineligible.
        harness.create("attack-victim")
        harness.stop("attack-victim")
        for name in ["extra-file", "missing-simple-journal", "pending-growth", "sibling-path", "metadata-path",
                     "journal-symlink", "journal-fifo", "orphan-layer", "missing-predecessor", "cross-owned",
                     "sibling-hardlink", "metadata-hardlink", "oversized-journal"]:
            if name == "journal-fifo" and os.name == "nt":
                continue
            def injected(name=name):
                owned = ("/data", "/logs") if name == "cross-owned" else ()
                harness.create(name, owned)
                if name == "extra-file":
                    harness.guest(name + "-note", name, "echo keep-this-note >/.msb/user-note")
                if name == "missing-predecessor":
                    harness.capture(name, "saved")
                    harness.guest(name + "-later-write", name, guest_seed("latest:" + name))
                harness.stop(name)
                sandbox = harness.home / "sandboxes" / name
                journal = sandbox / "runtime/root-disk.json"
                value = json.loads(journal.read_text())
                external = []
                if name == "missing-simple-journal":
                    journal.unlink()
                elif name == "pending-growth":
                    value["growth_target"] = 384 * 1024 * 1024
                    journal.write_text(json.dumps(value))
                elif name in ("sibling-path", "metadata-path", "sibling-hardlink", "metadata-hardlink"):
                    target = harness.home / "sandboxes/attack-victim/upper.ext4"
                    if name.startswith("metadata-"):
                        target = sandbox / "external-mounts.json"
                        target.write_text('{"sentinel":"host-authority"}')
                    selected = target
                    if name.endswith("hardlink"):
                        selected = sandbox / "upper-forged.raw"
                        os.link(target, selected)
                    value["layers"][0]["path"] = str(selected)
                    journal.write_text(json.dumps(value))
                    external = [str(target)]
                elif name == "oversized-journal":
                    journal.write_bytes(b" " * (1024 * 1024 + 1))
                elif name in ("journal-symlink", "journal-fifo"):
                    journal.unlink()
                    if name == "journal-fifo":
                        os.mkfifo(journal, 0o600)
                    else:
                        target = harness.output / "symlink-canary"
                        target.write_text("host-canary")
                        journal.symlink_to(target)
                        external = [str(target)]
                elif name == "orphan-layer":
                    journal.unlink()
                    (sandbox / "upper-orphan.qcow2").write_bytes(b"uncommitted candidate")
                elif name == "missing-predecessor":
                    # Keep the missing bytes outside the sandbox for manual fixture recovery.
                    source = Path(value["layers"][0]["path"])
                    retained = harness.output / (name + "-retained-base.raw")
                    source.rename(retained)
                    external = [str(retained)]
                elif name == "cross-owned":
                    owned_journals = sorted((sandbox / "runtime/owned-disks").glob("*/disk.json"))
                    first, second = [json.loads(path.read_text()) for path in owned_journals]
                    first["layers"][0]["path"] = second["layers"][0]["path"]
                    owned_journals[0].write_text(json.dumps(first))
                expected = "start" if name in ("extra-file", "missing-simple-journal") else "refuse"
                remember(name, owned, expected, "guest-note" if name == "extra-file" else "injected-stopped-state",
                         external, note=name == "extra-file")
            scenario(name, injected)

        def external_parent():
            directory = harness.output / "external"
            directory.mkdir()
            disk = directory / "explicit.raw"
            shutil.copyfile(harness.home / "sandboxes/simple/upper.ext4", disk)
            harness.create("external-parent", root=str(disk) + ":format=raw,fstype=ext4")
            harness.stop("external-parent")
            neighbor = directory / "upper-unrelated.qcow2"
            neighbor.write_bytes(b"unrelated neighboring file")
            remember("external-parent", external=[str(disk), str(neighbor)], external_write_through=str(disk))
        scenario("external-parent", external_parent)
        save()
    finally:
        harness.shutdown()
        save()
    if any("setup_error" in case for case in cases):
        raise SystemExit("Some fixture producers failed; see fixtures.json. Successful fixtures remain usable.")


def maintenance_confirmed(args):
    """Test-only opt-in to answering the Mac prompt; never an argument sent to msb."""
    if sys.platform != "darwin":
        return False
    if not getattr(args, "legacy_writers_stopped", False):
        raise ValueError("macOS test maintenance requires --legacy-writers-stopped after stopping old writers")
    return True


def verify(args):
    from legacy_storage_preview import repair_in_terminal

    maintenance = maintenance_confirmed(args)
    manifest = read_manifest(args.output.resolve())
    harness = Harness(args.output, args.candidate, args.candidate_firmware, args.label)
    results = []

    def record(case, **details):
        results.append(dict(case=case, **details))
        (harness.log / "results.json").write_text(json.dumps(results, indent=2))

    try:
        harness.run("candidate-version", "--version")
        unrelated = None
        if args.unrelated_live:
            unrelated = "unrelated-live-" + hashlib.sha256(harness.phase.encode()).hexdigest()[:8]
            harness.create(unrelated)
            # A RAM-only marker and a progressing process distinguish coexistence from a
            # successful restart. This VM remains alive while legacy disks are captured.
            harness.guest("unrelated-live-seed", unrelated,
                          "echo retained-live-memory >/dev/shm/live-marker; "
                          "sh -c 'counter=0; while :; do counter=$((counter + 1)); "
                          "echo $counter >/dev/shm/live-counter.tmp; "
                          "mv /dev/shm/live-counter.tmp /dev/shm/live-counter; sleep 1; done' "
                          "</dev/null >/dev/null 2>&1 & echo $! >/dev/shm/live-pid")
        for case in manifest["cases"]:
            name = case["name"]
            if "setup_error" in case:
                record(name, passed=False, setup_error=case["setup_error"])
                continue
            sandbox = harness.home / "sandboxes" / name
            before = inventory(sandbox, case["external"])
            started = False
            if maintenance:
                if case["expected"] != "refuse":
                    automatic = harness.run(name + "-maintenance-required", "start", name, required=False)
                    if automatic.returncode == 0:
                        harness.names.append(name)
                        harness.stop(name)
                        record(name, passed=False, error="legacy start bypassed explicit maintenance")
                        continue
                    if "explicit maintenance recovery" not in automatic.stderr or before != inventory(sandbox, case["external"]):
                        record(name, passed=False, error="automatic start did not safely require maintenance", stderr=automatic.stderr)
                        continue
                result = repair_in_terminal(harness, name + "-maintenance-repair", name, maintenance)
                # An invalid view must fail recovery itself, rather than merely failing a
                # later boot or satisfying the missing-maintenance gate accidentally.
                if result.returncode == 0 and case["expected"] != "refuse":
                    result = harness.run(name + "-candidate-start", "start", name, required=False)
                    started = result.returncode == 0
            else:
                result = harness.run(name + "-candidate-start", "start", name, required=False)
                started = result.returncode == 0
            # Copied terminal PIDs can identify unrelated processes on this host. A refusal
            # never authorizes cleanup; only this invocation's successful starts do.
            if started:
                harness.names.append(name)
            if case["expected"] == "refuse":
                unchanged = before == inventory(sandbox, case["external"])
                # A crash/timeout is never counted as a safe admission refusal.
                refused = ("explicit maintenance recovery" not in result.stderr and 0 < result.returncode < 124) and any(
                    word in result.stderr.lower() for word in ("migration", "recovery", "storage", "journal", "symlink",
                                                               "legacy selection", "legacy metadata"))
                record(name, passed=refused and unchanged, refused=refused, disk_bytes_unchanged=unchanged,
                       exit=result.returncode, stderr=result.stderr)
                if started:
                    harness.stop(name)
                continue
            if result.returncode:
                record(name, passed=False, exit=result.returncode, stderr=result.stderr,
                       disk_bytes_unchanged=before == inventory(sandbox, case["external"]))
                continue
            try:
                harness.guest(name + "-selected-data", name, guest_check(case["value"], tuple(case["owned"]), True))
                if case.get("readonly"):
                    harness.guest(name + "-readonly-policy", name,
                                  f"if touch {shlex.quote(case['readonly'] + '/forbidden')}; then exit 1; fi")
                if case.get("note"):
                    assert (sandbox / "runtime/user-note").read_text() == "keep-this-note\n"
                assert (sandbox / "state-layout.json").is_file()
                assert (sandbox / "runtime/heartbeat.json").is_dir()
                # Two starts cover the ready fast path, not just one successful migration.
                harness.stop(name)
                harness.run(name + "-ready-restart", "start", name)
                harness.guest(name + "-ready-data", name, guest_check(case["value"], tuple(case["owned"]), True))
                if case.get("external_write_through"):
                    old_hash = digest(Path(case["external_write_through"]))
                    harness.guest(name + "-external-write", name, "echo visible-through-binding >/external-write; sync")
                    assert digest(Path(case["external_write_through"])) != old_hash, "external binding was silently privatized"
                harness.stop(name)
                record(name, passed=True, cold_restart=True, full_execution_restore=False)
            except Exception as error:
                record(name, passed=False, verification_error=str(error))
                harness.stop(name, required=False)
        if args.storage_operations:
            storage_operations(harness, manifest, results, record)
        old = Path(manifest["producer"])
        old_firmware = Path(manifest["firmware"])
        refusal = harness.run("old-cli-refusal", "start", "simple", binary=old, firmware=old_firmware, required=False)
        record("old-cli-refusal", passed=0 < refusal.returncode < 124 and any(
            text in refusal.stderr.lower() for text in ("schema is newer", "migration file", "upgrade required")))
        if args.execution_restore and "execution_snapshot" in manifest:
            name = "candidate-exec-" + hashlib.sha256(harness.phase.encode()).hexdigest()[:8]
            result = harness.run("old-full-snapshot-execution-restore", "restore", manifest["execution_snapshot"],
                                 "--name", name, required=False)
            if result.returncode:
                record("old-full-snapshot-execution-restore", passed=False, full_execution_restore=True,
                       exit=result.returncode, stderr=result.stderr)
            else:
                harness.names.append(name)
                ram = harness.run("restored-memory", "exec", name, "--", "sh", "-ec",
                                  'test "$(cat /dev/shm/migration-memory)" = retained-ram', required=False)
                record("old-full-snapshot-execution-restore", passed=ram.returncode == 0, full_execution_restore=True)
                harness.stop(name)
        if unrelated:
            live = harness.run("unrelated-live-progress", "exec", unrelated, "--", "sh", "-ec",
                               guest_check("latest:" + unrelated, protected=True) +
                               '; test "$(cat /dev/shm/live-marker)" = retained-live-memory; '
                               'kill -0 "$(cat /dev/shm/live-pid)"; '
                               'test "$(cat /dev/shm/live-counter)" -gt 1', required=False)
            record("unrelated-protected-vm-remains-live", passed=live.returncode == 0,
                   memory_and_process_retained=True)
    finally:
        harness.shutdown()
    if any(not result["passed"] for result in results):
        raise SystemExit("Migration qualification has failures; see results.json")


def storage_operations(harness, manifest, results, record):
    """Exercise storage writes after migration, while preserving the original marker contract."""
    token = hashlib.sha256(harness.phase.encode()).hexdigest()[:6]
    for source in ("simple", "owned-child"):
        if not any(result["case"] == source and result["passed"] for result in results):
            record(source + "-post-migration-operations", passed=False, skipped="source did not migrate")
            continue
        case = next(case for case in manifest["cases"] if case["name"] == source)
        owned = tuple(case["owned"])
        restored = f"post-{token}-{source}-disk"
        forked = f"post-{token}-{source}-fork"
        resumed = f"post-{token}-{source}-full"
        started = []
        latest = f"after-capture:{token}:{source}"
        try:
            harness.run(source + "-post-start", "start", source)
            started.append(source)
            harness.names.append(source)
            harness.guest(source + "-post-memory-seed", source, "echo retained-new-ram >/dev/shm/migration-memory; sync")
            snapshot = harness.capture(source, "post-" + token)
            full = harness.capture(source, "post-full-" + token, full=True)
            harness.guest(source + "-post-snapshot-write", source,
                          f"printf '%s' {shlex.quote(latest)} >/migration-after-capture; sync")
            harness.run(source + "-post-fork", "fork", source, "--name", forked)
            started.append(forked)
            harness.names.append(forked)
            harness.guest(source + "-post-fork-view", forked,
                          guest_check(case["value"], owned, True) +
                          f"; test \"$(cat /migration-after-capture)\" = {shlex.quote(latest)}")
            harness.stop(forked)
            harness.stop(source)
            harness.run(source + "-post-disk-restore", "restore", snapshot, "--name", restored)
            started.append(restored)
            harness.names.append(restored)
            harness.guest(source + "-post-restored-view", restored, guest_check(case["value"], owned, True))
            harness.stop(restored)
            # This check requires RAM from an actual same-candidate full restore. Cold child
            # start and a filesystem marker cannot satisfy it.
            harness.run(source + "-post-full-restore", "restore", full, "--name", resumed)
            started.append(resumed)
            harness.names.append(resumed)
            harness.guest(source + "-post-full-memory", resumed,
                          'test "$(cat /dev/shm/migration-memory)" = retained-new-ram')
            harness.stop(resumed)
            inspected = json.loads(harness.run(source + "-post-inspect", "inspect", source,
                                               "--format", "json").stdout)
            configured = inspected["config"]["image"]["Oci"].get("root_disk") or {}
            # Restored children may have a small captured disk but the normal default 4 GiB
            # reservation in their saved config. The modify API also enforces that reservation.
            configured_mib = configured.get("size_mib") or 4096
            harness.run(source + "-post-stopped-grow", "modify", source, "--root-disk",
                        growth_target(harness.home / "sandboxes" / source, configured_mib))
            harness.run(source + "-post-compact", "modify", source, "--compact")
            harness.run(source + "-post-restart", "start", source)
            harness.guest(source + "-post-latest-view", source,
                          guest_check(case["value"], owned, True) +
                          f"; test \"$(cat /migration-after-capture)\" = {shlex.quote(latest)}")
            harness.stop(source)
            record(source + "-post-migration-operations", passed=True, snapshot=True, fork=True,
                   grow=True, compact=True, same_candidate_full_execution_restore=True)
        except Exception as error:
            record(source + "-post-migration-operations", passed=False, verification_error=str(error))
            for name in started:
                harness.stop(name, required=False)


def writer_race(args):
    """Keep a real old VM alive across catalog admission and related-child migration refusal."""
    reserve_output(args.output)
    old = Harness(args.output, args.producer, args.producer_firmware, "old-writer")
    new = Harness(args.output, args.candidate, args.candidate_firmware, "writer-candidate")
    new.names = ["writer-parent", "writer-child"]
    result = dict(schema=SCHEMA, producer_sha256=digest(old.binary), candidate_sha256=digest(new.binary))
    try:
        old.create("writer-parent")
        old.run("fork-related-child", "fork", "writer-parent", "--name", "writer-child")
        old.guest("child-latest", "writer-child", guest_seed("latest:writer-child"))
        old.stop("writer-child")
        old.guest("old-continuing-work", "writer-parent",
                  "nohup sh -c 'n=0; while :; do n=$((n+1)); echo $n >/old-progress; sleep 1; done' "
                  ">/old-progress.log 2>&1 </dev/null &")
        sandbox = old.home / "sandboxes/writer-child"
        before = inventory(sandbox)
        refusal = new.run("related-live-start-refused", "start", "writer-child", required=False)
        result["related_start_refused"] = (0 < refusal.returncode < 124
                                           and "related writer" in refusal.stderr.lower())
        result["refused_disk_bytes_unchanged"] = before == inventory(sandbox)
        new.guest("old-vm-still-executes", "writer-parent", guest_check("latest:writer-parent"))
        new.guest("old-vm-still-progresses", "writer-parent",
                  'before=$(cat /old-progress); sleep 2; after=$(cat /old-progress); test "$after" -gt "$before"')
        result["old_vm_continues_across_catalog_upgrade"] = True
        new.stop("writer-parent")
        new.run("child-start-after-writer-stop", "start", "writer-child")
        new.guest("child-preserves-latest", "writer-child", guest_check("latest:writer-child", protected=True))
        new.stop("writer-child")
        result["migration_after_explicit_writer_stop"] = True
        result["passed"] = result["related_start_refused"] and result["refused_disk_bytes_unchanged"]
    except Exception as error:
        result.update(passed=False, error=str(error))
    finally:
        new.shutdown()
        (args.output / "writer-race-result.json").write_text(json.dumps(result, indent=2))
    if not result["passed"]:
        raise SystemExit("Related writer qualification failed; see writer-race-result.json")


def verify_operations(args):
    """Repeat storage-operation checks on an already migrated disposable fixture home."""
    manifest = read_manifest(args.output.resolve())
    harness = Harness(args.output, args.candidate, args.candidate_firmware, args.label)
    results = []

    def record(name, **details):
        results.append(dict(case=name, **details))
        (harness.log / "results.json").write_text(json.dumps(results, indent=2))

    ready = [dict(case=name, passed=(harness.home / "sandboxes" / name / "state-layout.json").is_file())
             for name in ("simple", "owned-child")]
    try:
        storage_operations(harness, manifest, ready, record)
    finally:
        harness.shutdown()
    if any(not result["passed"] for result in results):
        raise SystemExit("Post-migration storage qualification failed; see results.json")


def mixed_runtime(args):
    """Use the candidate SDK/CLI to start already protected data with an explicit older runtime."""
    manifest = read_manifest(args.output.resolve())
    harness = Harness(args.output, args.candidate, args.runtime_firmware, args.label, args.runtime)
    results = []
    try:
        for name in ("simple", "owned-child"):
            case = next(case for case in manifest["cases"] if case["name"] == name)
            owns_instance = False
            try:
                started = harness.run(name + "-mixed-start", "start", name, required=False)
                if started.returncode:
                    results.append(dict(case=name, passed=False, exit=started.returncode,
                                        refused=True, stderr=started.stderr))
                    continue
                owns_instance = True
                harness.names.append(name)
                harness.guest(name + "-mixed-data", name,
                              guest_check(case["value"], tuple(case["owned"]), True))
                process = None
                if platform.system() == "Linux":
                    import sqlite3
                    with sqlite3.connect(f"file:{harness.home / 'db/msb.db'}?mode=ro", uri=True) as catalog:
                        pid = catalog.execute("SELECT run.pid FROM run JOIN sandbox ON sandbox.id=run.sandbox_id "
                                              "WHERE sandbox.name=? ORDER BY run.id DESC LIMIT 1", (name,)).fetchone()[0]
                    process = os.readlink(f"/proc/{pid}/exe")
                    assert Path(process).resolve() == harness.runtime, "selected old runtime was not launched"
                harness.stop(name)
                results.append(dict(case=name, passed=True, runtime_process=process))
            except Exception as error:
                results.append(dict(case=name, passed=False, error=str(error)))
                if owns_instance:
                    harness.stop(name, required=False)
    finally:
        harness.shutdown()
        (harness.log / "results.json").write_text(json.dumps(results, indent=2))
    if any(not result["passed"] for result in results):
        raise SystemExit("Mixed runtime qualification has refusals or failures; see results.json")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="phase", required=True)
    producer = subcommands.add_parser("produce")
    producer.add_argument("--output", required=True, type=Path)
    producer.add_argument("--producer", required=True, type=Path)
    producer.add_argument("--producer-firmware", required=True, type=Path)
    producer.set_defaults(action=produce)
    candidate = subcommands.add_parser("verify")
    candidate.add_argument("--output", required=True, type=Path)
    candidate.add_argument("--candidate", required=True, type=Path)
    candidate.add_argument("--candidate-firmware", required=True, type=Path)
    candidate.add_argument("--label", default="verify")
    candidate.add_argument("--legacy-writers-stopped", action="store_true",
                           help="Test-only consent to answer the Mac maintenance prompt after excluding legacy writers across homes")
    candidate.add_argument("--execution-restore", action="store_true")
    candidate.add_argument("--storage-operations", action="store_true")
    candidate.add_argument("--unrelated-live", action="store_true",
                           help="keep a new protected VM running across every migration")
    candidate.set_defaults(action=verify)
    writer = subcommands.add_parser("writer-race")
    writer.add_argument("--output", required=True, type=Path)
    writer.add_argument("--producer", required=True, type=Path)
    writer.add_argument("--producer-firmware", required=True, type=Path)
    writer.add_argument("--candidate", required=True, type=Path)
    writer.add_argument("--candidate-firmware", required=True, type=Path)
    writer.set_defaults(action=writer_race)
    operations = subcommands.add_parser("operations")
    operations.add_argument("--output", required=True, type=Path)
    operations.add_argument("--candidate", required=True, type=Path)
    operations.add_argument("--candidate-firmware", required=True, type=Path)
    operations.add_argument("--label", default="post-migration-operations")
    operations.set_defaults(action=verify_operations)
    mixed = subcommands.add_parser("mixed-runtime")
    mixed.add_argument("--output", required=True, type=Path)
    mixed.add_argument("--candidate", required=True, type=Path)
    mixed.add_argument("--runtime", required=True, type=Path)
    mixed.add_argument("--runtime-firmware", required=True, type=Path)
    mixed.add_argument("--label", default="mixed-runtime")
    mixed.set_defaults(action=mixed_runtime)
    args = parser.parse_args()
    if hasattr(args, "label") and (Path(args.label).name != args.label or args.label in (".", "..", "produce")):
        parser.error("--label must be a new single-directory name")
    args.action(args)


if __name__ == "__main__":
    main()
