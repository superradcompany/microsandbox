#!/usr/bin/env python3
"""Report sccache health without exposing backend credentials or URLs."""

import json
import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    try:
        result = subprocess.run(
            ["sccache", "--show-stats", "--stats-format=json"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"::warning title=sccache health unavailable::{error}", file=sys.stderr)
        return 0

    if result.returncode != 0:
        print(
            f"::warning title=sccache health unavailable::{result.stderr.strip()}",
            file=sys.stderr,
        )
        return 0

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        print(f"::warning title=sccache health unavailable::{error}", file=sys.stderr)
        return 0
    stats = payload.get("stats", payload)
    hits = sum(stats.get("cache_hits", {}).get("counts", {}).values())
    misses = sum(stats.get("cache_misses", {}).get("counts", {}).values())
    write_errors = stats.get("cache_write_errors", 0)
    read_errors = stats.get("cache_read_errors", 0)
    writes = stats.get("cache_writes", 0)
    total = hits + misses
    hit_rate = hits / total * 100 if total else 0

    summary = (
        f"sccache: {hits} hits, {misses} misses, {writes} writes, "
        f"{write_errors} write errors, {read_errors} read errors "
        f"({hit_rate:.1f}% hit rate)"
    )
    print(summary)

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with Path(step_summary).open("a", encoding="utf-8") as output:
            output.write(f"### Compiler cache\n\n{summary}\n")

    if write_errors or read_errors:
        print(
            "::warning title=sccache backend errors::"
            f"{write_errors} cache writes and {read_errors} cache reads failed; "
            "inspect repository cache capacity and upload limits"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
