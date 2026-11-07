#!/usr/bin/env python3
"""Exercise explicit recovery against refused fixtures from legacy_storage_migration.py.

The output must be a disposable fixture home already qualified by the migration harness.
Original disks are checked before boot; recovery is never permitted to rewrite those inputs.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from legacy_storage_migration import Harness, guest_check, inventory, maintenance_arguments, read_manifest


def verify(args):
    maintenance = maintenance_arguments(args)
    manifest = read_manifest(args.output.resolve())
    harness = Harness(args.output, args.candidate, args.candidate_firmware, args.label)
    cases = {case["name"]: case for case in manifest["cases"]}
    results = []

    def record(name, **values):
        results.append(dict(case=name, **values))
        (harness.log / "results.json").write_text(json.dumps(results, indent=2))

    try:
        for name in ("orphan-layer", "cross-owned"):
            case = cases[name]
            assert "setup_error" not in case, case
            sandbox = harness.home / "sandboxes" / name
            before = inventory(sandbox, case["external"])
            report = harness.run(name + "-inspect", "doctor", name,
                                 "--format", "json", required=False)
            assert report.returncode == 2, report.stderr
            entry = json.loads(report.stdout)["sandboxes"][0]
            assert entry["status"] == "recovery_required", entry
            choices = entry["inspection"]["candidates"]
            assert choices and len({view["disk_id"] for view in choices}) == len(choices), choices
            # These fixtures have exactly one complete authorized view for each disk role.
            # Do not turn the harness into an arbitrary or ambiguous candidate selector.
            selected = [argument for view in choices for argument in
                        ("--select", view["disk_id"] + "=" + view["id"])]
            rejected = harness.run(name + "-ack-required", "self", "repair", name,
                                   *selected, required=False)
            assert rejected.returncode != 0
            unknown = harness.run(name + "-unknown-view", "self", "repair", name,
                                  "--select", "root=view-not-authorized", "--accept-selected-view", *maintenance,
                                  required=False)
            assert 0 < unknown.returncode < 124
            assert not (sandbox / ".storage-migration").exists()
            assert before == inventory(sandbox, case["external"])
            recovered = harness.run(name + "-recover", "self", "repair", name,
                                    *selected, "--accept-selected-view", *maintenance, "--format", "json")
            result = json.loads(recovered.stdout)
            assert result["ready"] and result["originals_retained"], result
            after = inventory(sandbox, case["external"])
            assert all(after.get(path) == digest for path, digest in before.items()), "original disk changed"
            # Repeating explicit selection on ready storage must never silently replace its view.
            repeated = harness.run(name + "-no-replacement", "self", "repair", name,
                                   *selected, "--accept-selected-view", *maintenance, required=False)
            assert repeated.returncode != 0
            assert after == inventory(sandbox, case["external"])
            harness.run(name + "-recovered-start", "start", name)
            harness.names.append(name)
            harness.guest(name + "-recovered-data", name,
                          guest_check(case["value"], tuple(case["owned"]), True))
            harness.stop(name)
            record(name, passed=True, originals_unchanged_before_boot=True,
                   unacknowledged_and_unknown_selection_refused=True, selected_data_verified=True)

        name = "missing-predecessor"
        case = cases[name]
        sandbox = harness.home / "sandboxes" / name
        before = inventory(sandbox, case["external"])
        refused = harness.run(name + "-no-invented-bytes", "self", "repair", name, *maintenance, required=False)
        assert 0 < refused.returncode < 124
        assert before == inventory(sandbox, case["external"])
        assert not (sandbox / ".storage-migration").exists()
        record(name, passed=True, refused=True, original_disks_unchanged=True)
    except Exception as error:
        record("recovery-verification", passed=False, error=str(error))
        raise
    finally:
        harness.shutdown()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--candidate-firmware", required=True, type=Path)
    parser.add_argument("--label", default="explicit-recovery")
    parser.add_argument("--legacy-writers-stopped", action="store_true")
    verify(parser.parse_args())


if __name__ == "__main__":
    main()
