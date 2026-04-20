#!/usr/bin/env python3
"""Docker vs Microsandbox fsmeta-focused filesystem benchmarks."""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import statistics
import subprocess
import sys
import textwrap
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


#--------------------------------------------------------------------------------------------------
# Constants
#--------------------------------------------------------------------------------------------------

DEFAULT_IMAGE = "python:3.12"
DEFAULT_ITERATIONS = 100
DEFAULT_TIMEOUT = 3600
OUTPUT_DIR = Path("build/bench/fsmeta")
SCHEMA_VERSION = 1
LAYER_HINT_THRESHOLD = 8

# Guest-side harness. Workloads define `run_once() -> dict` and optionally
# `setup()` (called once) and `before_each()` (called before every iteration).
# Iterations are passed via argv to avoid string replacement in guest code.
_GUEST_PREFIX = textwrap.dedent("""\
    import json, os, sys, time
    _n = int(sys.argv[1])
""")

_GUEST_SUFFIX = textwrap.dedent("""\
    _sfn = setup if 'setup' in dir() else None
    _bfn = before_each if 'before_each' in dir() else None
    if _sfn: _sfn()
    if _bfn: _bfn()
    run_once()
    _times, _meta = [], None
    for _ in range(_n):
        if _bfn: _bfn()
        _t0 = time.perf_counter()
        _meta = run_once()
        _times.append(time.perf_counter() - _t0)
    print(json.dumps({"times": _times, **(_meta or {})}))
""")

_STDLIB_TREE_HELPERS = textwrap.dedent("""\
    import sysconfig
    _root = sysconfig.get_paths()["stdlib"]
    _dirs = []
    _py_files = []
    _hit_targets = []
    _iter = 0

    def _ensure_tree():
        if _dirs:
            return

        stack = [_root]
        while stack:
            path = stack.pop()
            _dirs.append(path)
            first_file = None

            try:
                with os.scandir(path) as it:
                    for entry in it:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            if first_file is None:
                                first_file = entry.path
                            if entry.name.endswith(".py"):
                                _py_files.append(entry.path)
            except (PermissionError, OSError):
                pass

            if first_file is not None:
                _hit_targets.append((path, first_file))

    def setup():
        _ensure_tree()

    def before_each():
        global _iter
        _iter += 1

    def _miss_path(path, idx):
        return os.path.join(path, f".__msb_fsmeta_missing__{_iter:05d}_{idx:06d}")
""")

WORKLOADS: dict[str, str] = {
    "metadata_scan_stdlib": _STDLIB_TREE_HELPERS + textwrap.dedent("""\
        def run_once():
            entries = 0
            for path in _dirs:
                try:
                    with os.scandir(path) as it:
                        for entry in it:
                            entries += 1
                            entry.stat(follow_symlinks=False)
                except (PermissionError, OSError):
                    pass
            return {"dirs": len(_dirs), "entries": entries}
    """),

    "readdir_rescan_stdlib": _STDLIB_TREE_HELPERS + textwrap.dedent("""\
        _passes = 10

        def run_once():
            entries = 0
            for _ in range(_passes):
                for path in _dirs:
                    try:
                        with os.scandir(path) as it:
                            for entry in it:
                                entries += 1
                                entry.is_dir(follow_symlinks=False)
                    except (PermissionError, OSError):
                        pass
            return {"dirs": len(_dirs), "entries": entries, "passes": _passes}
    """),

    "negative_lookup_stdlib": _STDLIB_TREE_HELPERS + textwrap.dedent("""\
        def run_once():
            misses = 0
            for idx, path in enumerate(_dirs):
                try:
                    os.stat(_miss_path(path, idx))
                except FileNotFoundError:
                    misses += 1
                except (PermissionError, OSError):
                    pass
            return {"dirs": len(_dirs), "misses": misses}
    """),

    "hit_miss_mix_stdlib": _STDLIB_TREE_HELPERS + textwrap.dedent("""\
        def run_once():
            hits = 0
            misses = 0
            for idx, (parent, hit_path) in enumerate(_hit_targets):
                try:
                    os.stat(hit_path)
                    hits += 1
                except (PermissionError, OSError):
                    pass

                try:
                    os.stat(_miss_path(parent, idx))
                except FileNotFoundError:
                    misses += 1
                except (PermissionError, OSError):
                    pass
            return {"targets": len(_hit_targets), "hits": hits, "misses": misses}
    """),

    "read_all_py_stdlib": _STDLIB_TREE_HELPERS + textwrap.dedent("""\
        def run_once():
            total = 0
            files = 0
            for path in _py_files:
                try:
                    with open(path, "rb") as f:
                        total += len(f.read())
                    files += 1
                except (PermissionError, OSError):
                    pass
            return {"files": files, "bytes": total}
    """),

    "concurrent_negative_lookup_4t": _STDLIB_TREE_HELPERS + textwrap.dedent("""\
        import threading

        def _probe_chunk(paths, base_idx, result, idx):
            misses = 0
            for offset, path in enumerate(paths):
                try:
                    os.stat(_miss_path(path, base_idx + offset))
                except FileNotFoundError:
                    misses += 1
                except (PermissionError, OSError):
                    pass
            result[idx] = misses

        def run_once():
            n = len(_dirs)
            chunk_size = max(1, (n + 3) // 4)
            chunks = [_dirs[i:i+chunk_size] for i in range(0, n, chunk_size)]
            results = [0] * len(chunks)
            threads = []

            for i, chunk in enumerate(chunks):
                t = threading.Thread(
                    target=_probe_chunk,
                    args=(chunk, i * chunk_size, results, i),
                )
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

            return {"dirs": n, "misses": sum(results), "threads": len(chunks)}
    """),

    "concurrent_readdir_4t": _STDLIB_TREE_HELPERS + textwrap.dedent("""\
        import threading

        def _scan_chunk(paths, result, idx):
            entries = 0
            for path in paths:
                try:
                    with os.scandir(path) as it:
                        for entry in it:
                            entries += 1
                            entry.is_dir(follow_symlinks=False)
                except (PermissionError, OSError):
                    pass
            result[idx] = entries

        def run_once():
            n = len(_dirs)
            chunk_size = max(1, (n + 3) // 4)
            chunks = [_dirs[i:i+chunk_size] for i in range(0, n, chunk_size)]
            results = [0] * len(chunks)
            threads = []

            for i, chunk in enumerate(chunks):
                t = threading.Thread(target=_scan_chunk, args=(chunk, results, i))
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

            return {"dirs": n, "entries": sum(results), "threads": len(chunks)}
    """),
}


#--------------------------------------------------------------------------------------------------
# Functions: Helpers
#--------------------------------------------------------------------------------------------------


def build_guest_code(workload: str) -> str:
    return _GUEST_PREFIX + workload + _GUEST_SUFFIX


def run_cmd(
    cmd: list[str],
    timeout: int,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and proc.returncode != 0:
        msg = proc.stderr.strip() or proc.stdout.strip() or f"failed: {' '.join(cmd)}"
        raise RuntimeError(msg)
    return proc


def try_cleanup(cmd: list[str], timeout: int = 30) -> None:
    # Best-effort teardown: swallow subprocess/OS failures (already torn down,
    # permission issues, timeouts) so benchmark runs don't abort on cleanup.
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.SubprocessError, OSError):
        pass


def require_bin(path: str, label: str) -> str:
    resolved = shutil.which(path)
    if not resolved:
        sys.exit(f"{label} not found: {path}")
    return resolved


def summarize(payload: dict[str, Any], wall_seconds: float) -> dict[str, Any]:
    times = payload["times"]
    return {
        **payload,
        "median_s": statistics.median(times),
        "mean_s": statistics.mean(times),
        "stdev_s": statistics.stdev(times) if len(times) > 1 else 0.0,
        "min_s": min(times),
        "max_s": max(times),
        "wall_s": wall_seconds,
    }


def inspect_image(reference: str, msb: str, timeout: int) -> dict[str, Any]:
    proc = run_cmd([msb, "image", "inspect", reference, "--format", "json"], timeout=timeout)
    if proc.returncode != 0:
        return {"error": proc.stderr.strip() or proc.stdout.strip()}

    payload = json.loads(proc.stdout)
    return {
        "digest": payload.get("digest"),
        "layer_count": payload.get("layer_count"),
        "size_bytes": payload.get("size_bytes"),
    }


#--------------------------------------------------------------------------------------------------
# Functions: Benchmark
#--------------------------------------------------------------------------------------------------


def pull_images(
    images: list[str],
    msb: str,
    docker: str,
    timeout: int,
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for image in images:
        t0 = time.perf_counter()
        run_cmd([docker, "pull", image], timeout=timeout, check=True)
        docker_s = time.perf_counter() - t0

        t0 = time.perf_counter()
        run_cmd([msb, "pull", image, "--quiet"], timeout=timeout, check=True)
        msb_s = time.perf_counter() - t0

        result[image] = {"docker_pull_s": docker_s, "msb_pull_s": msb_s}
    return result


def run_workload(
    name: str,
    guest_code: str,
    iterations: int,
    image: str,
    msb: str,
    docker: str,
    timeout: int,
) -> dict[str, Any]:
    suffix = uuid.uuid4().hex[:8]
    dkr_name = f"bench-dkr-{suffix}"
    msb_name = f"bench-msb-{suffix}"

    result: dict[str, Any] = {}
    try:
        run_cmd(
            [docker, "run", "-d", "--name", dkr_name, image, "sleep", "infinity"],
            timeout=timeout,
            check=True,
        )
        run_cmd(
            [msb, "create", "-n", msb_name, image, "--quiet"],
            timeout=timeout,
            check=True,
        )

        runtimes = {
            "docker": [docker, "exec", dkr_name, "python", "-c", guest_code, str(iterations)],
            "microsandbox": [msb, "exec", msb_name, "--", "python", "-c", guest_code, str(iterations)],
        }

        for runtime, cmd in runtimes.items():
            t0 = time.perf_counter()
            proc = run_cmd(cmd, timeout=timeout)
            wall = time.perf_counter() - t0

            if proc.returncode == 0:
                result[runtime] = summarize(json.loads(proc.stdout), wall)
            else:
                result[runtime] = {
                    "error": proc.stderr.strip() or proc.stdout.strip(),
                    "returncode": proc.returncode,
                    "wall_s": wall,
                }
    finally:
        try_cleanup([docker, "rm", "-f", dkr_name])
        try_cleanup([msb, "stop", msb_name])
        try_cleanup([msb, "remove", msb_name])

    return result


#--------------------------------------------------------------------------------------------------
# Functions: Reporting
#--------------------------------------------------------------------------------------------------


def fmt_time(seconds: float) -> str:
    """Format a duration with auto-scaled units."""
    if seconds < 1e-3:
        return f"{seconds * 1e6:.1f} \u00b5s"
    if seconds < 1.0:
        return f"{seconds * 1e3:.2f} ms"
    return f"{seconds:.3f} s"


def print_table(headers: list[str], rows: list[list[str]], aligns: str) -> None:
    """Print an aligned table. aligns: string of 'l'/'r' per column."""
    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]

    def fmt_row(cells: list[str]) -> str:
        parts = []
        for cell, w, a in zip(cells, widths, aligns):
            parts.append(cell.ljust(w) if a == "l" else cell.rjust(w))
        return "  ".join(parts)

    print(fmt_row(headers))
    print("  ".join("\u2500" * w for w in widths))
    for row in rows:
        print(fmt_row(row))


def print_report(doc: dict[str, Any]) -> None:
    config = doc["config"]
    versions = doc["versions"]
    images = config["images"]
    image_details = doc.get("image_details", {})

    print()
    print("Docker vs Microsandbox \u2014 fsmeta Benchmark")
    if len(images) == 1:
        print(f"  Image:      {images[0]}")
    else:
        print(f"  Images:     {', '.join(images)}")
    print(f"  Iterations: {config['iterations']}")
    print(f"  Docker:     {versions['docker']}")
    print(f"  msb:        {versions['msb']}")

    for image, workloads in doc["results"].items():
        print(f"\n  {image}")

        detail = image_details.get(image, {})
        if "layer_count" in detail and detail["layer_count"] is not None:
            print(f"  Layers:     {detail['layer_count']}")
            if detail["layer_count"] < LAYER_HINT_THRESHOLD:
                print(
                    "  Note:       Flat image; use 8+ layers for a stronger merged-view signal"
                )
        elif "error" in detail:
            print(f"  Image info:  {detail['error']}")

        rows: list[list[str]] = []
        for name, data in workloads.items():
            d = data.get("docker", {})
            m = data.get("microsandbox", {})
            if "median_s" in d and "median_s" in m:
                ratio = d["median_s"] / m["median_s"]
                rows.append([
                    name,
                    fmt_time(d["median_s"]),
                    fmt_time(m["median_s"]),
                    f"{ratio:.2f}x",
                    f"\u00b1{fmt_time(m.get('stdev_s', 0))}",
                ])
            else:
                d_s = fmt_time(d["median_s"]) if "median_s" in d else d.get("error", "error")[:30]
                m_s = fmt_time(m["median_s"]) if "median_s" in m else m.get("error", "error")[:30]
                rows.append([name, d_s, m_s, "\u2014", "\u2014"])

        if rows:
            print_table(
                ["Workload", "Docker (med)", "msb (med)", "docker/msb", "msb \u03c3"],
                rows,
                "lrrrr",
            )
    print()


def print_comparison(current: dict[str, Any], baseline: dict[str, Any]) -> None:
    base_name = baseline.get("run_name", "baseline")

    for image in current["results"]:
        cur_workloads = current["results"][image]
        base_workloads = baseline.get("results", {}).get(image, {})

        if not base_workloads:
            print(f"\n  {image}: no baseline data")
            continue

        rows: list[list[str]] = []
        for name, cur in cur_workloads.items():
            base = base_workloads.get(name)
            if not base:
                rows.append([name, "\u2014", "\u2014", "\u2014", "\u2014"])
                continue

            cur_m = cur.get("microsandbox", {})
            base_m = base.get("microsandbox", {})
            if "median_s" not in cur_m or "median_s" not in base_m:
                rows.append([name, "\u2014", "\u2014", "\u2014", "\u2014"])
                continue

            speedup = base_m["median_s"] / cur_m["median_s"]

            normalized = "\u2014"
            cur_d = cur.get("docker", {})
            base_d = base.get("docker", {})
            if "median_s" in cur_d and "median_s" in base_d:
                base_ratio = base_m["median_s"] / base_d["median_s"]
                cur_ratio = cur_m["median_s"] / cur_d["median_s"]
                normalized = f"{base_ratio / cur_ratio:.2f}x"

            rows.append([
                name,
                fmt_time(base_m["median_s"]),
                fmt_time(cur_m["median_s"]),
                f"{speedup:.2f}x",
                normalized,
            ])

        if rows:
            print(f"\n  {image} vs \"{base_name}\"")
            print_table(
                ["Workload", "Before (msb)", "After (msb)", "Speedup", "Normalized"],
                rows,
                "lrrrr",
            )
    print()


#--------------------------------------------------------------------------------------------------
# Functions: Main
#--------------------------------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Docker vs Microsandbox fsmeta-focused benchmarks")
    p.add_argument("--image", action="append", default=None)
    p.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--msb-bin", default="msb")
    p.add_argument("--docker-bin", default="docker")
    p.add_argument("--run-name", default=None)
    p.add_argument("--output", default=None)
    p.add_argument("--baseline", default=None)
    p.add_argument("--skip-pull", action="store_true")
    p.add_argument("--workload", action="append", choices=sorted(WORKLOADS))
    return p.parse_args()


def main() -> int:
    args = parse_args()
    msb = require_bin(args.msb_bin, "msb")
    docker = require_bin(args.docker_bin, "docker")

    run_name = args.run_name or "bench-fsmeta"
    images = args.image or [DEFAULT_IMAGE]
    workload_names = args.workload or list(WORKLOADS)

    if args.output:
        out = Path(args.output)
    else:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe = "".join(c if c.isalnum() or c in "-_" else "-" for c in run_name)
        out = OUTPUT_DIR / f"{ts}-{safe}.json"

    msb_ver = run_cmd([msb, "--version"], timeout=30, check=True).stdout.strip()
    docker_ver = run_cmd(
        [docker, "info", "--format", "{{.ServerVersion}}"], timeout=30, check=True
    ).stdout.strip()

    doc: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "run_name": run_name,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "host": {"platform": platform.platform(), "python": sys.version},
        "config": {
            "images": images,
            "iterations": args.iterations,
            "timeout": args.timeout,
            "workloads": workload_names,
            "layer_hint_threshold": LAYER_HINT_THRESHOLD,
        },
        "versions": {"msb": msb_ver, "docker": docker_ver},
        "pull": None,
        "image_details": {},
        "results": {},
    }

    if not args.skip_pull:
        doc["pull"] = pull_images(images, msb, docker, args.timeout)

    for image in images:
        doc["results"][image] = {}
        for name in workload_names:
            code = build_guest_code(WORKLOADS[name])
            doc["results"][image][name] = run_workload(
                name, code, args.iterations, image, msb, docker, args.timeout,
            )
        doc["image_details"][image] = inspect_image(image, msb, args.timeout)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"Wrote {out}\n")

    print_report(doc)

    if args.baseline:
        baseline = json.loads(Path(args.baseline).read_text())
        print_comparison(doc, baseline)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
