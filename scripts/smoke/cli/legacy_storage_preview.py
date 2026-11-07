#!/usr/bin/env python3
"""Qualify unresolved disk-state refusal and share legacy fixtures/terminal helpers.

Normal repair does not choose a disk view. Both scripted and interactive repair
must preserve unresolved inputs and offer investigation instead.
Use a fresh disposable fixture directory and the same absolute paths for both phases.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import queue
import re
import shutil
import sqlite3
import subprocess
import threading
import time
import uuid

import legacy_storage_migration as migration


BRANCH_FILE = "/work/imports/current"
BRANCHES = ("east", "west")


def produce_branches(harness: migration.Harness, name: str) -> dict:
    harness.create(name)
    harness.guest(name + "-base", name, "mkdir -p /work/imports; echo common >/work/imports/base; sync")
    harness.capture(name, "common")
    harness.stop(name)

    # Start both branches from exactly the same stopped overlay. Let the released
    # guest write their files, so the fixture includes real ext4 and overlayfs state.
    sandbox = harness.home / "sandboxes" / name
    journal = sandbox / "runtime/root-disk.json"
    layers = json.loads(journal.read_text())["layers"]
    head = Path(layers[-1]["path"])
    if head.parent != sandbox or not re.fullmatch(r"upper-[0-9a-f]{32}\.qcow2", head.name):
        raise ValueError(f"unexpected released head for {name}")
    common = harness.output / (name + "-common-head")
    shutil.copyfile(head, common)

    for branch in BRANCHES:
        harness.run(f"{name}-{branch}-start", "start", name)
        harness.guest(f"{name}-{branch}-write", name,
                      f"echo {branch} >{BRANCH_FILE}; echo received >/work/imports/{branch}.json; sync")
        harness.stop(name)
        if branch == BRANCHES[0]:
            head.rename(sandbox / f"upper-{uuid.uuid4().hex}.qcow2")
            shutil.copyfile(common, head)

    # Model loss of the active journal. Keep it outside the sandbox so test
    # teardown can establish which inputs were present before candidate access.
    journal.rename(harness.output / (name + "-original-root-disk.json"))
    return {"name": name, "before": migration.inventory(sandbox)}


def produce(args):
    migration.IMAGE = args.image
    migration.reserve_output(args.output)
    harness = migration.Harness(args.output, args.producer, args.producer_firmware, "produce")
    try:
        harness.run("producer-version", "--version")
        cases = []
        for branch in BRANCHES:
            name = "select-" + branch
            harness.create(name)
            harness.guest(name + "-base", name,
                          "mkdir -p /work/imports; echo common >/work/imports/base; sync")
            harness.capture(name, "common")
            harness.guest(name + "-latest", name,
                          f"echo {branch} >{BRANCH_FILE}; echo received >/work/imports/{branch}.json; sync")
            harness.stop(name)
            sandbox = harness.home / "sandboxes" / name
            (sandbox / "runtime/root-disk.json").rename(
                harness.output / (name + "-original-root-disk.json"))
            cases.append(dict(name=name, branch=branch, kind="unresolved-state", before=migration.inventory(sandbox)))
        manifest = {"schema": migration.SCHEMA, "output": str(harness.output), "image": args.image, "cases": cases}
        (harness.output / "fixtures.json").write_text(json.dumps(manifest, indent=2))
    finally:
        harness.shutdown()


def inspect(harness, name):
    result = harness.run(name + "-diagnose", "doctor", name, "--format", "json", required=False)
    assert result.returncode == 2, result.stderr
    diagnosis = json.loads(result.stdout)["sandboxes"][0]
    assert diagnosis["status"] == "recovery_required" and not diagnosis["running"], diagnosis
    candidates = diagnosis["inspection"]["candidates"]
    heads = [view for view in candidates if view["layers"] == 2]
    assert len(heads) == 1 and len(candidates) == 2, candidates
    assert {view["disk_id"] for view in candidates} == {"root"}
    return diagnosis


class Terminal:
    """Exercise the public wizard with real console handles and retain the transcript."""

    def __init__(self, harness, label, args):
        if os.name == "nt":
            from winpty import PtyProcess
        else:
            from ptyprocess import PtyProcessUnicode as PtyProcess

        self.log = harness.log / (label + ".terminal")
        self.tty = PtyProcess.spawn([str(harness.binary), *args], cwd=str(harness.output),
                                    dimensions=(60, 200),
                                    env=migration.environment(harness.binary, harness.firmware, harness.home))
        self.chunks = queue.Queue()
        self.transcript = ""
        self.pending = ""
        self.finished = False
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        # Close the child first. Closing its buffered fd while the reader thread is
        # waiting for another prompt can deadlock cleanup after a failed assertion.
        if self.tty.isalive():
            self.send("q")
            self.reader.join(timeout=3)
            if self.tty.isalive():
                self.tty.terminate(force=True)
        self.reader.join(timeout=5)
        self.tty.close(force=True)

    def _read(self):
        try:
            with self.log.open("w", encoding="utf-8") as stream:
                while chunk := self.tty.read(4096):
                    stream.write(chunk)
                    stream.flush()
                    self.chunks.put(chunk)
        except (EOFError, OSError):
            # PTYs signal normal child shutdown with EOF or an OS error, depending on the platform.
            pass
        finally:
            self.chunks.put(None)

    def expect(self, marker=None, allow_exit=False):
        if self.finished:
            if marker and not allow_exit:
                raise AssertionError(f"repair already exited before {marker!r}")
            return None if marker else self.pending
        deadline = time.monotonic() + 180
        while marker is None or marker not in self.pending:
            try:
                chunk = self.chunks.get(timeout=max(0, deadline - time.monotonic()))
            except queue.Empty as exc:
                raise TimeoutError(f"waiting for {marker!r}: {self.pending[-1500:]}") from exc
            if chunk is None:
                self.finished = True
                if marker and not allow_exit:
                    raise AssertionError(f"repair exited before {marker!r}: {self.pending[-1500:]}")
                return None if marker else self.pending
            self.transcript += chunk
            if len(self.transcript) > 8 * 1024 * 1024:
                raise RuntimeError("repair exceeded the test transcript limit")
            # ConPTY can repaint the screen when emitting an otherwise plain prompt.
            self.pending = re.sub(r"\x1b\[[?0-9;]*[A-Za-z]", "", self.pending + chunk).replace("\r", "")
        output, self.pending = self.pending.split(marker, 1)
        return output

    def send(self, line):
        self.tty.write(line + ("\r" if os.name == "nt" else "\n"))

    def send_key(self, key):
        """Send raw menu input without an extra Enter that could accept the next screen."""
        self.tty.write(key)

    def wait(self):
        self.expect()
        return self.tty.wait()


def repair_in_terminal(harness, label, name, maintenance=False):
    """Drive only this fixture's repair and a separately authorized Mac confirmation.

    Unknown prompts, including requests to stop a VM, fail the harness. This helper
    never derives cross-home maintenance safety from the fixture's own catalog.
    """
    command = ["self", "repair", "--sandbox", name]
    marker = "enter select · esc back"
    with Terminal(harness, label, command) as wizard:
        while (current := wizard.expect(marker, allow_exit=True)) is not None:
            if "Confirm storage repairs" in current:
                wizard.send_key("y")
            elif "macOS maintenance confirmation" in current:
                if not maintenance:
                    wizard.send_key("\x1b")
                    raise ValueError("the test operator has not authorized the Mac maintenance confirmation")
                wizard.send_key("y")
            elif "Couldn't safely repair" in current:
                wizard.send_key("\x1b")
            elif "Repair results" in current:
                # Escape closes this read-only result menu without selecting a candidate.
                wizard.send_key("\x1b")
            else:
                raise AssertionError(f"unexpected repair prompt: {current}")
        result = subprocess.CompletedProcess(command, wizard.wait(), wizard.transcript, wizard.transcript)
        assert not any(text in wizard.transcript for text in (
            "View number", "Browse with", "Preparing read-only copies", "Apply these disk views"))
        return result


def catalog_state(home):
    # Disk hashes alone would miss a shared catalog upgrade that prevents a
    # released CLI from reopening the sandbox after its operator cancels.
    uri = (home / "db/msb.db").as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True) as db:
        return (db.execute("SELECT version FROM seaql_migrations ORDER BY version").fetchall(),
                db.execute("SELECT * FROM sandbox ORDER BY id").fetchall(),
                db.execute("SELECT * FROM run ORDER BY id").fetchall())


def verify(args):
    manifest = migration.read_manifest(args.output.resolve())
    harness = migration.Harness(args.output, args.candidate, args.candidate_firmware, args.label)
    results = []
    try:
        for index, case in enumerate(manifest["cases"]):
            name = case["name"]
            branch = case.get("branch")
            # Older disposable fixtures used the prior harness label, not a storage format.
            assert case.get("kind") in ("unresolved-state", "scripted-selection") and branch in BRANCHES, case
            sandbox = harness.home / "sandboxes" / name
            before = migration.inventory(sandbox)
            assert before == case["before"]
            old = None
            if index == 0 and args.producer:
                artifacts = json.loads((harness.output / "produce/artifacts.json").read_text())
                assert migration.digest(args.producer) == artifacts["binary_sha256"]
                assert migration.digest(args.producer_firmware) == artifacts["firmware_sha256"]
                old = migration.Harness(args.output, args.producer, args.producer_firmware, args.label + "-old-cli")
                old.run("before-diagnosis", "inspect", name)
            catalog = catalog_state(harness.home)
            diagnosis = inspect(harness, name)
            refused = harness.run(name + "-script-needs-investigation", "self", "repair", "--sandbox", name,
                                  "--format", "json", required=False)
            assert refused.returncode == 2 and "investigation" in refused.stdout
            interactive = repair_in_terminal(harness, name + "-interactive-investigation", name)
            assert interactive.returncode == 2 and "Couldn't safely repair" in interactive.stdout
            assert inspect(harness, name) == diagnosis and migration.inventory(sandbox) == before
            assert catalog_state(harness.home) == catalog, "investigation changed the source catalog"
            if old:
                old.run("after-investigation", "inspect", name)
            assert not (sandbox / ".storage-migration").exists() and not (sandbox / "state-layout.json").exists()
            results.append({"case": name, "fixture_branch": branch, "scripted_and_interactive_refusal": True,
                            "original_disks_and_catalog_unchanged": True, "no_candidate_selected": True})
            (harness.log / "results.json").write_text(json.dumps(results, indent=2))
    finally:
        harness.shutdown()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    phases = parser.add_subparsers(dest="phase", required=True)
    producer = phases.add_parser("produce")
    producer.add_argument("--output", type=Path, required=True)
    producer.add_argument("--producer", type=Path, required=True)
    producer.add_argument("--producer-firmware", type=Path, required=True)
    producer.add_argument("--image", default=migration.IMAGE, help="Released guest image used by the isolated fixtures")
    producer.set_defaults(action=produce)
    candidate = phases.add_parser("verify")
    candidate.add_argument("--output", type=Path, required=True)
    candidate.add_argument("--candidate", type=Path, required=True)
    candidate.add_argument("--candidate-firmware", type=Path, required=True)
    candidate.add_argument("--label", default="unresolved-state")
    candidate.add_argument("--producer", type=Path, help="Also reopen the old home after read-only investigation")
    candidate.add_argument("--producer-firmware", type=Path)
    candidate.set_defaults(action=verify)
    args = parser.parse_args()
    if args.phase == "verify":
        if Path(args.label).name != args.label or args.label in ("", ".", "..", "produce"):
            parser.error("--label must be a new single-directory name")
        if bool(args.producer) != bool(args.producer_firmware):
            parser.error("pass both --producer and --producer-firmware for the released CLI check")
    args.action(args)


if __name__ == "__main__":
    main()
