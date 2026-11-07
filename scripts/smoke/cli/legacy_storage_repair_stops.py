#!/usr/bin/env python3
"""Exercise consent, generation fencing and post-stop reinspection for macOS repair."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sqlite3
import sys

from legacy_storage_migration import Harness, SCHEMA, inventory, reserve_output
from legacy_storage_preview import Terminal
from legacy_storage_repair import choose, frame


PEER = "wizard-peer"
TARGET = "wizard-target"
STOP = f"Stop '{PEER}' gracefully?"
MAINTENANCE = "Have you stopped legacy VMs and excluded new writers?"


def confirm_repair(wizard):
    current = frame(wizard)
    assert "Confirm storage repairs" in current, current
    wizard.send_key("y")
    current = frame(wizard)
    assert STOP in current, current


def producer(args):
    reserve_output(args.output)
    old = Harness(args.output, args.producer, args.producer_firmware, "old-produce")
    try:
        old.run("version", "--version")
        for name in (TARGET, PEER):
            old.create(name)
            old.stop(name)
        before = inventory(old.home / "sandboxes" / TARGET)
        (old.output / "before.json").write_text(json.dumps(before, indent=2))
    finally:
        for name in old.names:
            old.run(name + "-ensure-stopped", "stop", name, required=False, timeout=30)
        assert not old.run("end-running", "list", "--running", "--quiet").stdout.strip()


def latest_run(home, name):
    # The fixture records immutable generations, not just a possibly reused OS process ID.
    database = (home / "db" / "msb.db").resolve().as_uri() + "?mode=ro"
    with sqlite3.connect(database, uri=True) as db:
        row = db.execute("SELECT s.id, s.status, r.id, r.status, r.termination_reason, r.signals_sent "
                         "FROM sandbox s JOIN run r ON s.id = r.sandbox_id "
                         "WHERE s.name = ? ORDER BY r.id DESC LIMIT 1", (name,)).fetchone()
    assert row, name
    return dict(zip(("sandbox_id", "sandbox_status", "run_id", "run_status", "reason", "signals"), row))


def verify(args):
    owner = json.loads((args.output / "fixture-owner.json").read_text())
    assert owner == {"schema": SCHEMA, "path": str(args.output.resolve())}
    old = Harness(args.output, args.producer, args.producer_firmware, args.label + "-old")
    new = Harness(args.output, args.candidate, args.candidate_firmware, args.label)
    before = json.loads((old.output / "before.json").read_text())
    target = old.home / "sandboxes" / TARGET
    command = ["self", "repair", TARGET]
    result = {}
    try:
        old.run("boot-peer", "start", PEER)
        old.guest("seed-ram", PEER, "echo first >/dev/shm/repair-stop-check")
        first = latest_run(old.home, PEER)
        assert first["sandbox_status"] == first["run_status"] == "Running"

        with Terminal(new, "decline-stop", command) as wizard:
            confirm_repair(wizard)
            wizard.send_key("n")
            assert wizard.wait() == 2
        old.guest("decline-kept-ram", PEER, 'test "$(cat /dev/shm/repair-stop-check)" = first')
        assert latest_run(old.home, PEER) == first
        assert inventory(target) == before
        result["declined_run"] = first

        with Terminal(new, "reject-stale-generation", command) as wizard:
            confirm_repair(wizard)
            old.stop(PEER)
            old.run("replace-peer", "start", PEER)
            old.guest("replacement-ram", PEER, "echo replacement >/dev/shm/repair-stop-check")
            second = latest_run(old.home, PEER)
            assert first["sandbox_id"] == second["sandbox_id"] and first["run_id"] != second["run_id"]
            wizard.send_key("y")
            current = frame(wizard)
            assert "Couldn't safely repair" in current, current
            wizard.send_key("\x1b")
            current = frame(wizard)
            choose(wizard, current, "Finish")
            assert wizard.wait() != 0
        old.guest("stale-consent-kept-ram", PEER, 'test "$(cat /dev/shm/repair-stop-check)" = replacement')
        assert latest_run(old.home, PEER) == second
        result["replacement_survived_stale_stop"] = second

        with Terminal(new, "stop-and-recheck", command) as wizard:
            confirm_repair(wizard)
            wizard.send_key("y")
            current = frame(wizard)
            assert MAINTENANCE in current, current
            stopped = latest_run(old.home, PEER)
            assert stopped["run_id"] == second["run_id"] and stopped["sandbox_status"] == "Stopped"
            assert stopped["run_status"] == "Terminated" and stopped["reason"] == "ShutdownRequested"
            assert stopped["signals"] is None
            # The check must reach the separate cross-home prerequisite after the peer exits.
            # This fixture cannot attest to other homes or know about unrelated host workloads.
            wizard.send_key("\x1b")
            assert wizard.wait() == 2
            assert "Repair cancelled. Results:" in wizard.transcript
            assert f"stopped {PEER}" in wizard.transcript
            assert "Completed actions were not undone" in wizard.transcript
        result["consented_run_stopped"] = stopped
        assert inventory(target) == before
        assert not (target / ".storage-migration").exists() and not (target / "state-layout.json").exists()
        result["target_disks_and_admission_unchanged"] = True
        (new.log / "results.json").write_text(json.dumps(result, indent=2))
    finally:
        # Only this fixture's peer was started; never stop any process by its PID.
        new.run("ensure-test-peer-stopped", "stop", PEER, required=False, timeout=30)
        assert not new.run("end-running", "list", "--running", "--quiet").stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    phases = parser.add_subparsers(dest="phase", required=True)
    for name, action in (("produce", producer), ("verify", verify)):
        phase = phases.add_parser(name)
        phase.add_argument("--output", required=True, type=Path)
        phase.add_argument("--producer", required=True, type=Path)
        phase.add_argument("--producer-firmware", required=True, type=Path)
        if name == "verify":
            phase.add_argument("--candidate", required=True, type=Path)
            phase.add_argument("--candidate-firmware", required=True, type=Path)
            phase.add_argument("--label", default="verify")
        phase.set_defaults(action=action)
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("the cross-home maintenance and unrelated legacy peer case requires macOS")
    args.action(args)


if __name__ == "__main__":
    main()
