#!/usr/bin/env python3
"""Verify investigation of refused fixtures from legacy_storage_migration.py.

The output must be a disposable fixture home already qualified by the migration harness.
Neither scripted nor interactive repair may choose a disk view or rewrite these inputs.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from legacy_storage_migration import Harness, inventory, read_manifest
from legacy_storage_preview import catalog_state, repair_in_terminal


def verify(args):
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
            assert entry["inspection"]["candidates"], entry
            catalog = catalog_state(harness.home)
            refused = harness.run(name + "-script-needs-investigation", "self", "repair", "--sandbox", name,
                                  "--format", "json", required=False)
            assert refused.returncode == 2 and "investigation" in refused.stdout, refused.stdout
            interactive = repair_in_terminal(harness, name + "-interactive-investigation", name)
            assert interactive.returncode == 2 and "Couldn't safely repair" in interactive.stdout
            assert not (sandbox / ".storage-migration").exists()
            assert not (sandbox / "state-layout.json").exists()
            assert before == inventory(sandbox, case["external"])
            assert catalog_state(harness.home) == catalog
            record(name, passed=True, scripted_and_interactive_refusal=True,
                   original_disks_and_catalog_unchanged=True, no_candidate_selected=True)

        name = "missing-predecessor"
        case = cases[name]
        sandbox = harness.home / "sandboxes" / name
        before = inventory(sandbox, case["external"])
        refused = repair_in_terminal(harness, name + "-no-invented-bytes", name)
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
    parser.add_argument("--label", default="investigation")
    verify(parser.parse_args())


if __name__ == "__main__":
    main()
