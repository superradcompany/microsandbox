#!/usr/bin/env python3
"""Check migration beside live legacy and protected VMs in a disposable home."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from legacy_storage_migration import Harness, guest_check, inventory, maintenance_confirmed, reserve_output
from legacy_storage_preview import repair_in_terminal


def verify(args):
    maintenance = maintenance_confirmed(args)
    reserve_output(args.output)
    old = Harness(args.output, args.producer, args.producer_firmware, "produce")
    new = Harness(args.output, args.candidate, args.candidate_firmware, "candidate")
    new.names = ["legacy-peer", "legacy-target", "protected-peer"]
    try:
        old.create("legacy-peer")
        old.guest("legacy-peer-memory", "legacy-peer", "echo old-still-running >/dev/shm/coexistence")
        old.create("legacy-target")
        old.stop("legacy-target")
        target = new.home / "sandboxes/legacy-target"
        before = inventory(target)

        # Catalog upgrade and new creation must remain possible with an old VM alive.
        new.create("protected-peer")
        new.stop("protected-peer")
        new.run("protected-ready-restart", "start", "protected-peer")
        new.guest("protected-memory", "protected-peer", "echo new-still-running >/dev/shm/coexistence")
        new.guest("legacy-survives-catalog-upgrade", "legacy-peer",
                  'test "$(cat /dev/shm/coexistence)" = old-still-running')
        attempted = new.run("migration-with-unrelated-old-vm", "start", "legacy-target", required=False)
        if sys.platform == "darwin":
            assert 0 < attempted.returncode < 124 and "explicit maintenance recovery" in attempted.stderr, attempted.stderr
            # Noninteractive repair cannot stop a known peer or claim maintenance consent.
            confirmed = new.run("scripted-repair-keeps-live-peer", "self", "repair", "--sandbox", "legacy-target",
                                required=False)
            assert 0 < confirmed.returncode < 124 and "legacy-peer" in confirmed.stderr, confirmed.stderr
            assert before == inventory(target)
            assert not (target / "state-layout.json").exists()
            assert not (target / ".storage-migration").exists()
            report = new.run("refusal-no-admission", "doctor", "legacy-target",
                             "--format", "json", required=False)
            assert report.returncode == 2, report.stderr
            assert not json.loads(report.stdout)["sandboxes"][0]["protection_registered"]
        else:
            assert attempted.returncode == 0, attempted.stderr
            new.guest("per-file-protected-data", "legacy-target", guest_check("latest:legacy-target", protected=True))
            new.stop("legacy-target")
        new.guest("old-vm-not-stopped", "legacy-peer", 'test "$(cat /dev/shm/coexistence)" = old-still-running')

        new.stop("legacy-peer")
        if maintenance:
            repaired = repair_in_terminal(new, "interactive-maintenance-after-teardown", "legacy-target", maintenance)
            assert repaired.returncode == 0, repaired.stderr
        new.run("migration-after-old-teardown", "start", "legacy-target")
        new.guest("migrated-data", "legacy-target", guest_check("latest:legacy-target", protected=True))
        new.guest("protected-vm-not-stopped", "protected-peer",
                  'test "$(cat /dev/shm/coexistence)" = new-still-running')
        new.stop("legacy-target")
        (new.log / "results.json").write_text(json.dumps(dict(
            passed=True, platform=sys.platform, new_creation_and_ready_restart_unaffected=True,
            legacy_vm_survived_catalog_upgrade=True, protected_vm_kept_execution=True,
            macos_refused_unclassified_writer=sys.platform == "darwin",
            explicit_maintenance_required=sys.platform == "darwin",
            per_file_migration_beside_unrelated_old_vm=sys.platform != "darwin",
        ), indent=2))
    finally:
        new.shutdown()


def verify_cross_home_maintenance(args):
    """An old VM absent from the selected catalog must not enable automatic Mac import."""
    maintenance = maintenance_confirmed(args)
    foreign_output = args.output / "foreign-home"
    target_output = args.output / "target-home"
    reserve_output(foreign_output)
    reserve_output(target_output)
    old = Harness(foreign_output, args.producer, args.producer_firmware, "old")
    producer = Harness(target_output, args.producer, args.producer_firmware, "produce")
    candidate = Harness(target_output, args.candidate, args.candidate_firmware, "candidate")
    try:
        old.create("foreign-legacy")
        old.guest("foreign-memory", "foreign-legacy", "echo foreign-live >/dev/shm/cross-home")
        producer.create("cross-target")
        producer.stop("cross-target")
        producer.names.clear()  # Stopped before this home's catalog is upgraded.
        candidate.create("protected-cross-peer")
        candidate.guest("protected-memory", "protected-cross-peer", "echo protected-live >/dev/shm/cross-home")
        sandbox = candidate.home / "sandboxes/cross-target"
        before = inventory(sandbox)
        for command in (("start",), ("self", "repair")):
            refused = candidate.run(command[-1] + "-requires-maintenance", *command, "cross-target", required=False)
            assert 0 < refused.returncode < 124, refused.stderr
            assert "maintenance" in refused.stderr.lower(), refused.stderr
        assert before == inventory(sandbox)
        assert not (sandbox / ".storage-migration").exists()
        assert not (sandbox / "state-layout.json").exists()
        report = candidate.run("cross-home-doctor", "doctor", "cross-target",
                               "--format", "json", required=False)
        assert report.returncode == 2, report.stderr
        entry = json.loads(report.stdout)["sandboxes"][0]
        assert entry["status"] == "maintenance_required" and not entry["protection_registered"], entry
        old.guest("foreign-not-stopped", "foreign-legacy", 'test "$(cat /dev/shm/cross-home)" = foreign-live')
        old.stop("foreign-legacy")
        repaired = repair_in_terminal(candidate, "cross-home-maintenance", "cross-target", maintenance)
        assert repaired.returncode == 0, repaired.stderr
        candidate.run("cross-home-start", "start", "cross-target")
        candidate.names.append("cross-target")
        candidate.guest("cross-home-data", "cross-target", guest_check("latest:cross-target", protected=True))
        candidate.guest("protected-still-live", "protected-cross-peer",
                        'test "$(cat /dev/shm/cross-home)" = protected-live')
        (candidate.log / "results.json").write_text(json.dumps(dict(
            passed=True, old_vm_in_another_home_remained_running=True,
            start_and_unconfirmed_recovery_refused_without_admission=True,
            explicit_recovery_after_foreign_teardown=True, protected_peer_kept_memory=True,
        ), indent=2))
    finally:
        candidate.shutdown()
        producer.shutdown()
        old.shutdown()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--producer", required=True, type=Path)
    parser.add_argument("--producer-firmware", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--candidate-firmware", required=True, type=Path)
    parser.add_argument("--legacy-writers-stopped", action="store_true",
                        help="Test-only consent to answer the Mac maintenance prompt after excluding unrelated legacy writers across homes")
    args = parser.parse_args()
    verify(args)
    if sys.platform == "darwin":
        verify_cross_home_maintenance(args)


if __name__ == "__main__":
    main()
