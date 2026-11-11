#!/usr/bin/env python3
"""Exercise guided repair of intact released storage and safe unresolved-case reporting.

Produce a fresh disposable home with v0.7.11, then verify it at the same absolute
location with the candidate. The test drives a real terminal; no disk-view picker
or guest-file browser is used to repair supported layouts. Pass the established
macOS maintenance attestation only after arranging its required writer exclusion.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

import legacy_storage_migration as migration
from legacy_storage_preview import Terminal, catalog_state, produce_branches


MENU = "enter select · esc back"
PICKER = "space select · enter confirm · esc cancel"
FORBIDDEN = ("View number", "Browse with", "Preparing read-only copies", "Apply these disk views")
CASES = {"app", "worker", "restored", "grown", "compacted", "database"}


def produce(args):
    migration.IMAGE = args.image
    migration.reserve_output(args.output)
    harness = migration.Harness(args.output, args.producer, args.producer_firmware, "produce")
    cases = []

    def remember(name, owned=(), value=None, unresolved=False):
        cases.append(dict(name=name, owned=owned, value=value or "latest:" + name,
                          unresolved=unresolved, before=migration.inventory(harness.home / "sandboxes" / name)))
        (harness.output / "fixtures.json").write_text(json.dumps(
            dict(schema=migration.SCHEMA, output=str(harness.output), image=args.image, cases=cases), indent=2))

    try:
        harness.run("producer-version", "--version")
        harness.create("app", ("/data", "/logs"))
        harness.stop("app")
        remember("app", ("/data", "/logs"))

        harness.create("worker")
        snapshot = harness.capture("worker", "saved")
        harness.guest("worker-post-snapshot", "worker", migration.guest_seed("post-snapshot:worker"))
        harness.stop("worker")
        harness.run("worker-old-restart", "start", "worker")
        harness.guest("worker-old-latest", "worker", migration.guest_check("post-snapshot:worker"))
        harness.stop("worker")
        remember("worker", value="post-snapshot:worker")

        harness.names.append("restored")
        harness.run("restored-old", "restore", snapshot, "--name", "restored")
        harness.guest("restored-post-snapshot", "restored", migration.guest_seed("post-restore:restored"))
        harness.stop("restored")
        remember("restored", value="post-restore:restored")

        for name, operation in (("grown", "--root-disk"), ("compacted", "--compact")):
            harness.create(name)
            if operation == "--compact":
                harness.capture(name, "first")
                harness.guest(name + "-middle", name, migration.guest_seed("middle:" + name))
                harness.capture(name, "second")
                harness.guest(name + "-latest", name, migration.guest_seed("latest:" + name))
            harness.stop(name)
            harness.run(name + "-operation", "modify", name, operation,
                        *(["320M"] if operation == "--root-disk" else []))
            harness.run(name + "-old-restart", "start", name)
            harness.guest(name + "-old-latest", name, migration.guest_check("latest:" + name))
            harness.stop(name)
            remember(name)

        # Only this unresolved case loses its journal, deliberately and after the producer
        # finished. It is distinct from the intact 0.7.12 regression fixtures above.
        produce_branches(harness, "database")
        remember("database", unresolved=True)
    finally:
        harness.shutdown()


def frame(wizard):
    return wizard.expect(MENU)


def choose(wizard, current, label):
    """Navigate visible choices, never guess a selection from timing or a raw index."""
    choices = re.findall(r"^\s+([> ]) (.+)$", current, re.M)
    labels = [text for _, text in choices]
    assert label in labels, (label, current)
    pointer = next(i for i, (mark, _) in enumerate(choices) if mark == ">")
    wanted = labels.index(label)
    for _ in range(abs(wanted - pointer)):
        wizard.send_key("\x1b[B" if wanted > pointer else "\x1b[A")
        frame(wizard)
    wizard.send_key("\r")


def assert_no_browser(wizard):
    assert not any(text in wizard.transcript for text in FORBIDDEN), wizard.transcript[-3000:]


def unchanged_inputs(harness, expected):
    for name, before in expected.items():
        assert migration.inventory(harness.home / "sandboxes" / name) == before, name


def baseline(args):
    """Reproduce the actual strict-admission regression before running the candidate."""
    manifest = migration.read_manifest(args.output.resolve())
    harness = migration.Harness(args.output, args.baseline, args.baseline_firmware, args.label)
    cases = {case["name"]: case for case in manifest["cases"]}
    assert set(cases) == CASES, "fixture production did not complete"
    results = []
    for name, case in cases.items():
        if case["unresolved"]:
            continue
        sandbox = harness.home / "sandboxes" / name
        assert migration.inventory(sandbox) == case["before"], name
        result = harness.run(name + "-strict-refusal", "start", name, required=False)
        if result.returncode == 0:
            # A surprising successful start still authorizes stopping this exact fixture.
            harness.stop(name)
        assert 0 < result.returncode < 124 and "migration/recovery required" in result.stderr, result.stderr
        assert migration.inventory(sandbox) == case["before"], name
        results.append(dict(case=name, strict_admission_refused=True, original_disks_unchanged=True))
        (harness.log / "results.json").write_text(json.dumps(results, indent=2))


def verify(args):
    manifest = migration.read_manifest(args.output.resolve())
    migration.IMAGE = manifest.get("image", migration.IMAGE)
    maintenance = migration.maintenance_confirmed(args)
    harness = migration.Harness(args.output, args.candidate, args.candidate_firmware, args.label)
    cases = {case["name"]: case for case in manifest["cases"]}
    assert set(cases) == CASES, "fixture production did not complete"
    before = {name: case["before"] for name, case in cases.items()}
    results = []

    def record(name, **values):
        results.append(dict(case=name, passed=True, **values))
        (harness.log / "results.json").write_text(json.dumps(results, indent=2))

    try:
        unchanged_inputs(harness, before)
        version_output = harness.run("candidate-version", "--version").stdout
        version = re.search(r"\d+\.\d+\.\d+(?:[-+][\w.-]+)?", version_output).group()
        catalog = catalog_state(harness.home)
        with Terminal(harness, "unresolved-report", ["self", "repair", "--sandbox", "database"]) as wizard:
            current = frame(wizard)
            assert "Couldn't safely repair 'database'." in current, current
            assert "We couldn't establish which saved disk state is active." in current, current
            assert "Original disk files were left unchanged" in current, current
            choose(wizard, current, "Review diagnostic report")
            current = frame(wizard)
            assert "CLI: " + version in current, current
            assert "Configured runtime: " + version in current, current
            assert "Operation: legacy storage repair" in current and "active_state_unresolved" in current
            assert str(harness.home) not in current and "east.json" not in current and "west.json" not in current
            # Returning from a report must not start a repair, install a protection record,
            # or change the shared catalog merely to render diagnostic information.
            choose(wizard, current, "Print report for copying")
            current = frame(wizard)
            assert "microsandbox storage repair report" in current and "Repair results" in current, current
            choose(wizard, current, "Finish")
            assert wizard.wait() == 2, wizard.transcript[-3000:]
            assert_no_browser(wizard)
        unchanged_inputs(harness, before)
        assert catalog_state(harness.home) == catalog
        assert not (harness.home / "sandboxes/database/.storage-migration").exists()
        assert not (harness.home / "sandboxes/database/state-layout.json").exists()
        record("unresolved-report", catalog_and_originals_unchanged=True, no_disk_browser=True,
               reviewed_report_has_versions=True, guest_contents_and_host_paths_absent=True)

        with Terminal(harness, "decline-repair", ["self", "repair", "--sandbox", "app"]) as wizard:
            current = frame(wizard)
            assert "Confirm storage repairs" in current, current
            wizard.send_key("n")
            assert wizard.wait() == 2, wizard.transcript[-2000:]
            assert "cancelled; repair not attempted" in wizard.transcript
            assert_no_browser(wizard)
        unchanged_inputs(harness, before)
        assert catalog_state(harness.home) == catalog
        record("decline-repair", catalog_and_originals_unchanged=True)

        if maintenance:
            # JSON output cannot silently attest to the cross-home maintenance window.
            refused = harness.run("scripted-maintenance-refused", "self", "repair", "--sandbox", "app",
                                  "--format", "json", required=False)
            assert refused.returncode == 2, refused.stderr
            report = json.loads(refused.stdout)
            assert "interactive maintenance confirmation" in report["next_step"], report
            assert "without --format json" in report["next_step"], report
            unchanged_inputs(harness, before)
            assert catalog_state(harness.home) == catalog
            assert not (harness.home / "sandboxes/app/.storage-migration").exists()
            assert not (harness.home / "sandboxes/app/state-layout.json").exists()
            record("scripted-maintenance-refused", interactive_remedy=True, catalog_and_originals_unchanged=True)

            with Terminal(harness, "decline-maintenance", ["self", "repair", "--sandbox", "app"]) as wizard:
                current = frame(wizard)
                assert "Confirm storage repairs" in current, current
                wizard.send_key("y")
                current = frame(wizard)
                assert "macOS maintenance confirmation" in current, current
                wizard.send_key("n")
                assert wizard.wait() == 2, wizard.transcript[-2000:]
                assert "maintenance not confirmed" in wizard.transcript, wizard.transcript
                assert_no_browser(wizard)
            unchanged_inputs(harness, before)
            assert catalog_state(harness.home) == catalog
            assert not (harness.home / "sandboxes/app/.storage-migration").exists()
            assert not (harness.home / "sandboxes/app/state-layout.json").exists()
            record("decline-maintenance", catalog_and_originals_unchanged=True, no_admission=True)

        # New storage is created normally, then checked as a ready entry without legacy
        # capture. It must remain hidden from the initial repair picker by default.
        harness.create("ready")
        harness.stop("ready")
        ready = harness.home / "sandboxes/ready"
        ready_before = migration.inventory(ready)
        with Terminal(harness, "ready-picker", ["self", "repair"]) as wizard:
            current = wizard.expect(PICKER)
            assert "database" in current and "app" in current
            assert not re.search(r"\] ready\s", current), current
            wizard.send_key("r")
            current = wizard.expect(PICKER)
            assert re.search(r"\] ready\s", current), current
            wizard.send_key("r")
            current = wizard.expect(PICKER)
            assert not re.search(r"\] ready\s", current), current
            wizard.send_key("\x1b")
            assert wizard.wait() == 2, wizard.transcript[-2000:]
        assert migration.inventory(ready) == ready_before
        unchanged_inputs(harness, before)
        record("ready-picker", hidden_by_default=True, explicit_toggle=True, cancellation_preserved_inputs=True)

        with Terminal(harness, "mixed-batch", ["self", "repair"]) as wizard:
            wizard.expect(PICKER)
            wizard.send_key(" ")  # The first row is All listed; ready remains hidden.
            current = wizard.expect(PICKER)
            assert "[x] All listed" in current, current
            wizard.send_key("\r")
            current = frame(wizard)
            assert "app" in current and "worker" in current and "database" in current, current
            wizard.send_key("y")
            current = frame(wizard)
            # No VMs are running in this fixture. Confirm the macOS prerequisite only when
            # the operator explicitly supplied the harness's maintenance attestation.
            if maintenance:
                assert "macOS maintenance confirmation" in current, current
                wizard.send_key("y")
                current = frame(wizard)
            assert "Repair results" in current, current
            assert "database" in current and "needs investigation" in current, current
            choose(wizard, current, "Finish")
            assert wizard.wait() == 2, wizard.transcript[-4000:]
            assert_no_browser(wizard)
        assert migration.inventory(ready) == ready_before
        assert migration.inventory(harness.home / "sandboxes/database") == before["database"]
        for name, case in cases.items():
            if case["unresolved"]:
                continue
            sandbox = harness.home / "sandboxes" / name
            after = migration.inventory(sandbox)
            assert all(after.get(path) == checksum for path, checksum in before[name].items()), name
            assert (sandbox / "state-layout.json").is_file(), name
            harness.names.append(name)
            harness.run(name + "-boot", "start", name)
            harness.guest(name + "-latest-and-boundary", name,
                          migration.guest_check(case["value"], tuple(case["owned"]), True))
            harness.stop(name)
            record(name, automatic_selected_state=True, latest_writes=True, protected_boundary=True,
                   original_disks_unchanged_before_boot=True)
        record("mixed-batch", independent_repairs_completed=True, unresolved_originals_retained=True,
               ready_unchanged=True, no_disk_browser=True)

        with Terminal(harness, "already-ready", ["self", "repair", "--sandbox", "app"]) as wizard:
            assert wizard.wait() == 0, wizard.transcript[-2000:]
            assert "already ready" in wizard.transcript, wizard.transcript
            assert_no_browser(wizard)
        record("already-ready", no_legacy_work=True)
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
    strict = phases.add_parser("baseline")
    strict.add_argument("--output", type=Path, required=True)
    strict.add_argument("--baseline", type=Path, required=True)
    strict.add_argument("--baseline-firmware", type=Path, required=True)
    strict.add_argument("--label", default="strict-baseline")
    strict.set_defaults(action=baseline)
    candidate = phases.add_parser("verify")
    candidate.add_argument("--output", type=Path, required=True)
    candidate.add_argument("--candidate", type=Path, required=True)
    candidate.add_argument("--candidate-firmware", type=Path, required=True)
    candidate.add_argument("--label", default="guided-repair")
    candidate.add_argument("--legacy-writers-stopped", action="store_true",
                           help="Test-only consent to answer the Mac maintenance prompt after excluding legacy writers across homes")
    candidate.set_defaults(action=verify)
    args = parser.parse_args()
    if args.phase in ("baseline", "verify") and (Path(args.label).name != args.label or args.label in ("", ".", "..", "produce")):
        parser.error("--label must be a new single-directory name")
    args.action(args)


if __name__ == "__main__":
    main()
