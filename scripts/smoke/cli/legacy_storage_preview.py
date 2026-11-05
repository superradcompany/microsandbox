#!/usr/bin/env python3
"""Produce divergent legacy disks, then inspect and apply them through a real terminal.

The verify phase uses pywinpty on Windows and ptyprocess on Unix. Use a fresh
disposable fixture directory and the same absolute paths for both phases.
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
import threading
import time
import uuid

from legacy_storage_migration import (
    Harness, SCHEMA, digest, environment, inventory, maintenance_arguments, read_manifest, reserve_output,
)


BRANCH_FILE = "/work/imports/current"
BRANCHES = ("east", "west")


def produce_branches(harness: Harness, name: str) -> dict:
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
    return {"name": name, "before": inventory(sandbox)}


def produce(args):
    reserve_output(args.output)
    harness = Harness(args.output, args.producer, args.producer_firmware, "produce")
    try:
        harness.run("producer-version", "--version")
        cases = [produce_branches(harness, "pick-" + branch) for branch in BRANCHES]
        manifest = {"schema": SCHEMA, "output": str(harness.output), "cases": cases}
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
    assert len(heads) == 2 and heads[0]["virtual_size"] == heads[1]["virtual_size"], candidates
    assert heads[0]["id"] != heads[1]["id"] and {view["disk_id"] for view in candidates} == {"root"}
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
                                    env=environment(harness.binary, harness.firmware, harness.home))
        self.chunks = queue.Queue()
        self.transcript = ""
        self.pending = ""
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

    def expect(self, marker=None):
        deadline = time.monotonic() + 180
        while marker is None or marker not in self.pending:
            try:
                chunk = self.chunks.get(timeout=max(0, deadline - time.monotonic()))
            except queue.Empty as exc:
                raise TimeoutError(f"waiting for {marker!r}: {self.pending[-1500:]}") from exc
            if chunk is None:
                if marker:
                    raise AssertionError(f"repair exited before {marker!r}: {self.pending[-1500:]}")
                return self.pending
            self.transcript += chunk
            if len(self.transcript) > 8 * 1024 * 1024:
                raise RuntimeError("repair exceeded the test transcript limit")
            # ConPTY can repaint the screen when emitting an otherwise plain prompt.
            self.pending = re.sub(r"\x1b\[[?0-9;]*[A-Za-z]", "", self.pending + chunk).replace("\r", "")
        output, self.pending = self.pending.split(marker, 1)
        return output

    def send(self, line):
        self.tty.write(line + ("\r" if os.name == "nt" else "\n"))

    def wait(self):
        self.expect()
        return self.tty.wait()


def interact(harness, name, maintenance, branch, cancel):
    prompt = "View number, browse command, or q to cancel: "
    label = name + ("-cancel" if cancel else "-apply")
    with Terminal(harness, label, ["self", "repair", name, *maintenance]) as tty:
        tty.expect(prompt)
        tty.send("compare " + BRANCH_FILE)
        compared = tty.expect(prompt)
        # Select by inspected guest contents. Discovery order and candidate IDs
        # deliberately play no part in deciding which head to keep.
        views = {int(number): body for number, body in
                 re.findall(r"View (\d+):\s*(.*?)(?=View \d+:|$)", compared, re.S)}
        choices = {label: [n for n, body in views.items() if f"bytes: {label}" in body] for label in BRANCHES}
        assert all(len(matching) == 1 for matching in choices.values()), compared
        assert sum("path is absent" in body for body in views.values()) == 1, compared
        selected = choices[branch][0]
        tty.send(f"cat {selected} /etc/alpine-release")
        lower = tty.expect(prompt)
        assert "bytes: 3.20." in lower, f"missing OCI lower in preview: {lower}"
        tty.send(f"ls {selected} /work/imports")
        listing = tty.expect(prompt)
        assert branch + ".json" in listing, listing
        if cancel:
            tty.send("q")
        else:
            tty.send(str(selected))
            tty.expect("Apply these disk views? [y/N]")
            tty.send("y")
        assert tty.wait() == (2 if cancel else 0), tty.transcript[-1500:]


def catalog_state(home):
    # Disk hashes alone would miss a shared catalog upgrade that prevents a
    # released CLI from reopening the sandbox after its operator cancels.
    uri = (home / "db/msb.db").as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True) as db:
        return (db.execute("SELECT version FROM seaql_migrations ORDER BY version").fetchall(),
                db.execute("SELECT * FROM sandbox ORDER BY id").fetchall(),
                db.execute("SELECT * FROM run ORDER BY id").fetchall())


def verify(args):
    manifest = read_manifest(args.output.resolve())
    maintenance = maintenance_arguments(args)
    harness = Harness(args.output, args.candidate, args.candidate_firmware, args.label)
    results = []
    try:
        for index, case in enumerate(manifest["cases"]):
            name = case["name"]
            branch = name.removeprefix("pick-")
            assert branch in BRANCHES
            sandbox = harness.home / "sandboxes" / name
            before = inventory(sandbox)
            assert before == case["before"]
            old = None
            if index == 0 and args.producer:
                artifacts = json.loads((harness.output / "produce/artifacts.json").read_text())
                assert digest(args.producer) == artifacts["binary_sha256"]
                assert digest(args.producer_firmware) == artifacts["firmware_sha256"]
                old = Harness(args.output, args.producer, args.producer_firmware, args.label + "-old-cli")
                old.run("before-preview", "inspect", name)
            catalog = catalog_state(harness.home)
            diagnosis = inspect(harness, name)
            refused = harness.run(name + "-script-needs-choice", "self", "repair", name,
                                  "--format", "json", *maintenance, required=False)
            assert refused.returncode == 2 and not (sandbox / ".storage-migration").exists()
            interact(harness, name, maintenance, branch, cancel=True)
            assert inspect(harness, name) == diagnosis and inventory(sandbox) == before
            assert catalog_state(harness.home) == catalog, "private inspection changed the source catalog"
            if old:
                old.run("after-cancel", "inspect", name)
            assert not (sandbox / ".storage-migration").exists() and not (sandbox / "state-layout.json").exists()
            interact(harness, name, maintenance, branch, cancel=False)
            after = inventory(sandbox)
            assert all(after.get(path) == digest for path, digest in before.items())
            harness.run(name + "-boot", "start", name)
            harness.names.append(name)
            other = next(label for label in BRANCHES if label != branch)
            harness.guest(name + "-data", name, f'test "$(cat {BRANCH_FILE})" = {branch}; '
                          f'test -f /work/imports/{branch}.json; test ! -e /work/imports/{other}.json; '
                          'test "$(cat /work/imports/base)" = common')
            harness.stop(name)
            results.append({"case": name, "selected_by_contents": branch, "cancel_preserved_inputs": True})
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
    producer.set_defaults(action=produce)
    candidate = phases.add_parser("verify")
    candidate.add_argument("--output", type=Path, required=True)
    candidate.add_argument("--candidate", type=Path, required=True)
    candidate.add_argument("--candidate-firmware", type=Path, required=True)
    candidate.add_argument("--label", default="guided-repair")
    candidate.add_argument("--legacy-writers-stopped", action="store_true")
    candidate.add_argument("--producer", type=Path, help="Also reopen the old home with its original CLI after cancellation")
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
