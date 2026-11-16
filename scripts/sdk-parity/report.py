#!/usr/bin/env python3
"""Render old/new executed-scenario evidence without promoting source coverage to E2E.

Original failures and corrected-harness attempts are retained independently.
An equal method name or two equal failures never becomes a parity pass.
"""

import argparse
import csv
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path


def read_attempts(evidence):
    rows = []
    for sdk in ("python", "node"):
        for file in sorted(evidence.glob(f"{sdk}-*.xml")):
            phase = "old" if "-old" in file.name else "new"
            corrected = "corrected" in file.name
            for case in ET.parse(file).iter("testcase"):
                failure = case.find("failure")
                if failure is None:
                    failure = case.find("error")
                status = (
                    "FAIL"
                    if failure is not None
                    else "SKIP"
                    if case.find("skipped") is not None
                    else "PASS"
                )
                name = case.get("name", "")
                rows.append(
                    {
                        "sdk": "Python" if sdk == "python" else "TypeScript",
                        "phase": phase,
                        "case": name,
                        "status": status,
                        "corrected": corrected,
                        "evidence": file.name,
                        "detail": (failure.text or "")[:4000]
                        if failure is not None
                        else "",
                    }
                )
    for phase in ("old", "new"):
        for suffix in ("", "-corrected"):
            file = evidence / f"go-{phase}{suffix}.jsonl"
            if not file.exists():
                continue
            output = {}
            for line in file.read_text().splitlines():
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                name = event.get("Test")
                if not name:
                    continue
                output[name] = output.get(name, "") + event.get("Output", "")
                if event.get("Action") in ("pass", "fail", "skip"):
                    rows.append(
                        {
                            "sdk": "Go",
                            "phase": phase,
                            "case": name,
                            "status": event["Action"].upper(),
                            "corrected": bool(suffix),
                            "evidence": file.name,
                            "detail": output[name][-4000:]
                            if event["Action"] == "fail"
                            else "",
                        }
                    )
        for suffix in (
            "",
            "-recovered",
            "-jobs",
            "-ssh",
            "-tls-retry",
            "-network-fixture-first",
            "-network-corrected",
            "-helpers",
            "-full-progress",
            "-full-lifecycle",
            "-full-cancellation",
        ):
            file = evidence / f"rust-{phase}{suffix}.jsonl"
            if not file.exists():
                continue
            started = set()
            finished = set()
            for line in file.read_text().splitlines():
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if event.get("type") != "test":
                    continue
                name = event["name"]
                if event.get("event") == "started":
                    started.add(name)
                if event.get("event") in ("ok", "failed", "ignored"):
                    finished.add(name)
                    rows.append(
                        {
                            "sdk": "Rust",
                            "phase": phase,
                            "case": name,
                            "status": {
                                "ok": "PASS",
                                "failed": "FAIL",
                                "ignored": "SKIP",
                            }[event["event"]],
                            "corrected": "corrected" in suffix,
                            "evidence": file.name,
                            "detail": event.get("stdout", "")[-4000:],
                        }
                    )
            for name in sorted(started - finished):
                rows.append(
                    {
                        "sdk": "Rust",
                        "phase": phase,
                        "case": name,
                        "status": "INCOMPLETE",
                        "corrected": "corrected" in suffix,
                        "evidence": file.name,
                        "detail": "Started without a terminal test event",
                    }
                )
        for suffix in ("", "-additional", "-corrected"):
            file = evidence / f"ruby-{phase}{suffix}.log"
            if not file.exists():
                continue
            text = file.read_text()
            headers = list(re.finditer(r"^  (test_\w+):", text, re.MULTILINE))
            for index, match in enumerate(headers):
                block = text[
                    match.start() : headers[index + 1].start()
                    if index + 1 < len(headers)
                    else len(text)
                ]
                # A header alone is not a pass: interrupted runs have no completion time.
                complete = re.search(r": \(\d+\.\d+\)", block) is not None
                status = (
                    "FAIL"
                    if re.search(r"^(?:Failure|Error):", block, re.MULTILINE)
                    else "SKIP"
                    if "Omission:" in block
                    else "PASS"
                    if complete
                    else "INCOMPLETE"
                )
                rows.append(
                    {
                        "sdk": "Ruby",
                        "phase": phase,
                        "case": match[1],
                        "status": status,
                        "corrected": "corrected" in suffix,
                        "evidence": file.name,
                        "detail": block[-4000:] if status != "PASS" else "",
                    }
                )
    return rows


# Reviewed semantic changes must not become "replicated" merely because names match.
ACCEPTED_CHANGES = {
    (
        "Rust",
        "detach_disarms_parent_watchdog_for_attached_sandbox",
    ): "Detach now preserves the receiver; the new test also verifies use before dropping it.",
    (
        "Go",
        "TestOwnsLifecycleAfterDetachOrConnect",
    ): "Detach now preserves a usable receiver; repeated detach and retained ownership assertions were added.",
}


# Explicit, deliberately partial links; matching a scenario never qualifies an entire finding.
FINDING_EVIDENCE = {
    "R-02": [("Go", "UnifiedReceiver"), ("Rust", "parent_exit_stops")],
    "R-04": [
        ("Python", "live_config_observes"),
        ("TypeScript", "reads configuration changes"),
    ],
    "RD-02": [("Rust", "exec_stream_deadlines")],
    "RD-03": [("Python", "stale_receiver")],
    "RD-04": [("Rust", "ssh_exec_killed")],
    "RD-08": [
        ("Python", "completion_remains"),
        ("TypeScript", "retains completion"),
        ("Go", "LargeOutputAndRepeatable"),
    ],
    "RD-09": [("Go", "FsReadStream"), ("Rust", "ssh_sftp")],
    "PY-01": [("Python", "create_get_list_connect")],
    "PY-02": [("Python", "owned_and_borrowed_scope")],
    "PY-10": [("Python", "create_with_progress")],
    "PY-11": [("Python", "completion_remains")],
    "PY-14": [("Python", "snapshot_create_open")],
    "TS-01": [("TypeScript", "generated secret placeholder")],
    "TS-05": [("TypeScript", "borrowed disposal")],
    "GO-01": [("Go", "BinaryCollectedExecAdapters")],
    "GO-02": [("Go", "LargeOutputAndRepeatable")],
    "GO-04": [("Go", "OwnsLifecycleAfterDetach")],
    "GO-05": [("Go", "CtxCancel"), ("Go", "ContextCancellation")],
    "GO-06": [("Go", "UnifiedReceiver"), ("Go", "DetachedSandboxOutlivesHandle")],
    "GO-I02": [("Go", "ConfiguredShellAdapters")],
    "RB-02": [
        ("Ruby", "typed_error"),
        ("Ruby", "filesystem_error"),
        ("Ruby", "volume_not_found"),
    ],
    "RB-05": [("Ruby", "gc_stops_owned"), ("Ruby", "explicit_stop_timeout")],
    "RB-06": [("Ruby", "release_the_gvl")],
    "UX-04": [("Python", "create_with_progress"), ("TypeScript", "SDK Pull Progress")],
    "UX-05": [
        ("Go", "ListSandboxesWithLabels"),
        ("Python", "list_with_labels"),
        ("TypeScript", "listWith by labels"),
    ],
    "UX-08": [("Rust", "graceful_stop_flushes")],
}


def verdict(old, new, sdk="", case=""):
    a, b = old.get("status", "NOT RUN"), new.get("status", "NOT RUN")
    if b == "PASS" and (
        (sdk, case) in ACCEPTED_CHANGES
        or (sdk == "Python" and case.startswith("test_completion_remains_observable["))
        or (sdk == "TypeScript" and "retains completion after " in case)
    ):
        return "ACCEPTED CHANGE — new passes"
    if a == b == "PASS":
        return (
            "REPLICATED — corrected harness"
            if old.get("corrected") or new.get("corrected")
            else "REPLICATED"
        )
    if a == b == "FAIL":
        return "FAIL BOTH"
    if b == "FAIL":
        return "NEW FAIL — investigate" if a == "PASS" else "FAIL — no passing baseline"
    if b == "PASS":
        return "NEW PASS / NO OLD PASS"
    return "MISSING / SKIPPED"


def resolved_verdict(resolution, old, new):
    """A reviewed fix cannot close a still-failing or unexecuted case."""
    if new.get("status") != "PASS":
        raise ValueError("resolution requires a passing candidate execution")
    if resolution.get("requires_old_pass") and old.get("status") != "PASS":
        raise ValueError("fixture correction requires a passing baseline execution")
    if not resolution.get("reason"):
        raise ValueError("resolution requires an explicit explanation")
    return resolution["verdict"]


def write_csv(file, rows, fields):
    with file.open("w") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def test_inventory(root):
    """Source inventory includes unrun tests; parameterized cases remain symbolic."""
    rows = []
    for sdk, directory in [
        ("Rust", "rust"),
        ("TypeScript", "node-ts"),
        ("Python", "python"),
        ("Go", "go"),
        ("Ruby", "ruby"),
    ]:
        for file in (root / "sdk" / directory).rglob("*"):
            if not file.is_file() or any(
                p in file.parts
                for p in ("node_modules", "target", ".venv", "dist", "__pycache__")
            ):
                continue
            relative = str(file.relative_to(root))
            if file.suffix not in (".rs", ".go", ".py", ".ts", ".rb") or not (
                sdk == "Rust" or "test" in relative or "/integration/" in relative
            ):
                continue
            text = file.read_text(errors="replace")
            patterns = {
                "Python": r"^\s*(?:async )?def (test_\w+)\(",
                "Go": r"^func (Test\w+)\(",
                "Ruby": r"^\s*def (test_\w+)",
                "TypeScript": r'\b(?:it|test)(?:\.(?:skip|only|todo))?\(\s*["\x27]([^"\x27]+)',
                "Rust": r"#\[(?:tokio::)?(?:test|msb_test)(?:\([^\]]*\))?\][\s\S]{0,800}?(?:async\s+)?fn\s+(\w+)\(",
            }
            for match in re.finditer(patterns[sdk], text, re.MULTILINE):
                rows.append(
                    {
                        "sdk": sdk,
                        "case": match[1],
                        "file": relative,
                        "line": text.count("\n", 0, match.start()) + 1,
                        "evidence_level": "SOURCE ONLY — existence does not establish E2E coverage",
                    }
                )
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--followup-evidence", type=Path)
    parser.add_argument("--resolutions", type=Path)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--roadmap", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    attempts = read_attempts(args.evidence)
    if args.followup_evidence:
        for row in read_attempts(args.followup_evidence):
            row["round"] = 1
            row["evidence"] = "followup/" + row["evidence"]
            attempts.append(row)
    resolutions = json.loads(args.resolutions.read_text()) if args.resolutions else {}
    write_csv(
        args.out / "execution-attempts.csv",
        attempts,
        ["sdk", "phase", "case", "status", "corrected", "evidence", "detail"],
    )
    (args.out / "execution-attempts.json").write_text(
        json.dumps(attempts, indent=2) + "\n"
    )
    paired = {}
    for row in sorted(
        attempts, key=lambda row: (row.get("round", 0), row["corrected"])
    ):
        paired.setdefault((row["sdk"], row["case"]), {})[row["phase"]] = row
    comparisons = []
    for (sdk, case), versions in sorted(paired.items()):
        old = versions.get("old", {})
        new = versions.get("new", {})
        a = old.get("status", "NOT RUN")
        b = new.get("status", "NOT RUN")
        result = verdict(old, new, sdk, case)
        history = [row for row in attempts if row["sdk"] == sdk and row["case"] == case]
        # A successful unmodified rerun cannot erase an earlier behavioral failure.
        if (
            b == "PASS"
            and any(
                row["phase"] == "new" and row["status"] == "FAIL" for row in history
            )
            and not new.get("corrected")
        ):
            result = "INTERMITTENT — new passed on retry"
        resolution = resolutions.get(f"{sdk}/{case}")
        if resolution:
            result = resolved_verdict(resolution, old, new)
        comparisons.append(
            {
                "sdk": sdk,
                "case": case,
                "old": a,
                "new": b,
                "verdict": result,
                "evidence": "; ".join(
                    dict.fromkeys(row["evidence"] for row in history)
                ),
                "note": resolution["reason"]
                if resolution
                else ACCEPTED_CHANGES.get((sdk, case), ""),
            }
        )
    write_csv(
        args.out / "scenario-verdicts.csv",
        comparisons,
        ["sdk", "case", "old", "new", "verdict", "evidence", "note"],
    )
    sources = test_inventory(args.source)
    for row in sources:
        matches = [
            case
            for case in comparisons
            if case["sdk"] == row["sdk"]
            and (
                case["case"] == row["case"]
                or case["case"].startswith(row["case"] + "[")
                or case["case"].endswith(" > " + row["case"])
            )
        ]
        row["executed_scenarios"] = "; ".join(case["case"] for case in matches)
        row["audit_status"] = (
            "SEE SCENARIO VERDICTS — matching name only"
            if matches
            else "NO MATCHING EXECUTED SCENARIO IN THIS AUDIT"
        )
    write_csv(
        args.out / "test-source-inventory.csv",
        sources,
        [
            "sdk",
            "case",
            "file",
            "line",
            "audit_status",
            "executed_scenarios",
            "evidence_level",
        ],
    )
    api = json.loads((args.inventory / "public-api.json").read_text())
    entries = {}
    for item in api:
        entries.setdefault((item["sdk"], item["symbol"], item["kind"]), {})[
            item["phase"]
        ] = item
    surface = []
    for (sdk, symbol, kind), versions in sorted(entries.items()):
        surface.append(
            {
                "sdk": sdk,
                "symbol": symbol,
                "kind": kind,
                "old_present": "old" in versions,
                "new_present": "new" in versions,
                "verdict": "UNVERIFIED PER-SYMBOL E2E — declaration comparison only",
                "source_change": "same declaration name"
                if len(versions) == 2
                else "added"
                if "new" in versions
                else "removed or renamed",
                "file": versions.get("new", versions.get("old")).get("file", ""),
                "line": versions.get("new", versions.get("old")).get("line", ""),
            }
        )
    write_csv(
        args.out / "api-surface-verdicts.csv",
        surface,
        [
            "sdk",
            "symbol",
            "kind",
            "old_present",
            "new_present",
            "source_change",
            "verdict",
            "file",
            "line",
        ],
    )
    findings = []
    for line in args.roadmap.read_text().splitlines():
        if re.match(r"^\| [A-Z]+-[A-Z]?\d+ \|", line):
            columns = [x.strip() for x in line.strip("|").split("|")]
            references = FINDING_EVIDENCE.get(columns[0], [])
            related = [
                row
                for row in comparisons
                if any(
                    row["sdk"] == sdk and fragment in row["case"]
                    for sdk, fragment in references
                )
            ]
            findings.append(
                {
                    "id": columns[0],
                    "behavior": columns[1],
                    "decision": columns[3],
                    "verdict": "PARTIAL — linked scenarios; full finding not qualified"
                    if related
                    else "NOT INDIVIDUALLY E2E QUALIFIED",
                    "evidence": "; ".join(
                        f"{row['sdk']}: {row['case']} ({row['verdict']})"
                        for row in related
                    )
                    or "Source/design disposition is not an old/new execution result",
                }
            )
    write_csv(
        args.out / "cleanup-findings.csv",
        findings,
        ["id", "behavior", "decision", "verdict", "evidence"],
    )
    manifest = []
    roots = [("", args.evidence)]
    if args.followup_evidence:
        roots.append(("followup/", args.followup_evidence))
    for prefix, root in roots:
        for file in sorted(root.iterdir()):
            if file.is_file():
                manifest.append(
                    {
                        "file": prefix + file.name,
                        "bytes": file.stat().st_size,
                        "sha256": hashlib.sha256(file.read_bytes()).hexdigest(),
                    }
                )
    (args.out / "evidence-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n"
    )
    summary = {
        sdk: dict(Counter(row["verdict"] for row in comparisons if row["sdk"] == sdk))
        for sdk in sorted({row["sdk"] for row in comparisons})
    }
    (args.out / "summary.json").write_text(
        json.dumps(
            {
                "scenarios": summary,
                "api_rows": len(surface),
                "source_test_rows": len(sources),
                "cleanup_findings": len(findings),
            },
            indent=2,
        )
        + "\n"
    )
    lines = [
        "# Executed SDK behavior comparisons",
        "",
        "Each row is one executed named scenario, not every option combination or public method. `REPLICATED` means both versions passed the corresponding scenario after the documented API migration; it does not assert identical source signatures. Original and corrected-harness attempts are retained in `execution-attempts.csv`. Real remote-provider rows are blocked: no disposable test account.",
        "",
        "| SDK | Scenario | Old | New | Verdict | Evidence | Note |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in comparisons:
        lines.append(
            "| "
            + " | ".join(
                str(row[k]).replace("|", "\\|").replace("\n", " ")
                for k in ["sdk", "case", "old", "new", "verdict", "evidence", "note"]
            )
            + " |"
        )
    (args.out / "executed-scenarios.md").write_text("\n".join(lines) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
