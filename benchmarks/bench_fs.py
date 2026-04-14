#!/usr/bin/env python3
"""Docker vs Microsandbox filesystem benchmarks."""

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

DEFAULT_IMAGE = "python:3.12-slim"
DEFAULT_ITERATIONS = 100
DEFAULT_TIMEOUT = 3600
OUTPUT_DIR = Path("build/bench/fs")
SCHEMA_VERSION = 2

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

WORKLOADS: dict[str, str] = {
    # -- Rootfs / read-only -----------------------------------------------

    "metadata_scan_stdlib": textwrap.dedent("""\
        import sysconfig
        _root = sysconfig.get_paths()["stdlib"]

        def run_once():
            count = 0
            stack = [_root]
            while stack:
                for entry in os.scandir(stack.pop()):
                    count += 1
                    entry.stat(follow_symlinks=False)
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(entry.path)
            return {"entries": count}
    """),

    "read_all_py_stdlib": textwrap.dedent("""\
        import sysconfig
        _root = sysconfig.get_paths()["stdlib"]

        def run_once():
            files, total = 0, 0
            stack = [_root]
            while stack:
                for entry in os.scandir(stack.pop()):
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(entry.path)
                    elif entry.is_file(follow_symlinks=False) and entry.name.endswith(".py"):
                        files += 1
                        with open(entry.path, "rb") as f:
                            total += len(f.read())
            return {"files": files, "bytes": total}
    """),

    "deep_tree_traverse": textwrap.dedent("""\
        import tempfile

        _base = None

        def _make_tree(path, depth, width, files_per):
            for i in range(files_per):
                with open(os.path.join(path, f"f{i}.dat"), "wb") as f:
                    f.write(b"x" * 512)
            if depth > 0:
                for d in range(width):
                    sub = os.path.join(path, f"d{d}")
                    os.mkdir(sub)
                    _make_tree(sub, depth - 1, width, files_per)

        def setup():
            global _base
            _base = tempfile.mkdtemp(dir="/tmp")
            _make_tree(_base, depth=3, width=8, files_per=5)

        def run_once():
            count = 0
            for root, dirs, files in os.walk(_base):
                for name in files:
                    os.stat(os.path.join(root, name))
                    count += 1
            return {"files": count}
    """),

    "random_read_stdlib": textwrap.dedent("""\
        import random, sysconfig
        _root = sysconfig.get_paths()["stdlib"]
        _files = []

        def setup():
            for root, dirs, files in os.walk(_root):
                for f in files:
                    _files.append(os.path.join(root, f))

        def run_once():
            total = 0
            indices = random.sample(range(len(_files)), min(200, len(_files)))
            for i in indices:
                try:
                    with open(_files[i], "rb") as f:
                        total += len(f.read())
                except (PermissionError, OSError):
                    pass
            return {"files": len(indices), "bytes": total}
    """),

    # -- Write path -------------------------------------------------------

    "small_file_create_1k": textwrap.dedent("""\
        import shutil, tempfile
        _payload = b"x" * 4096

        def run_once():
            base = tempfile.mkdtemp(dir="/tmp")
            try:
                for i in range(1000):
                    with open(os.path.join(base, f"f{i:05d}.dat"), "wb") as f:
                        f.write(_payload)
                return {"files": 1000, "bytes": 1000 * len(_payload)}
            finally:
                shutil.rmtree(base)
    """),

    "mid_file_create_100": textwrap.dedent("""\
        import shutil, tempfile
        _payload = b"x" * (64 * 1024)

        def run_once():
            base = tempfile.mkdtemp(dir="/tmp")
            try:
                for i in range(100):
                    with open(os.path.join(base, f"f{i:05d}.dat"), "wb") as f:
                        f.write(_payload)
                return {"files": 100, "bytes": 100 * len(_payload)}
            finally:
                shutil.rmtree(base)
    """),

    "seq_write_fsync_16m": textwrap.dedent("""\
        import tempfile
        _size = 16 * 1024 * 1024
        _chunk = b"x" * (1024 * 1024)

        def run_once():
            fd, path = tempfile.mkstemp(dir="/tmp")
            try:
                with os.fdopen(fd, "wb", closefd=True) as f:
                    remaining = _size
                    while remaining:
                        f.write(_chunk[:min(len(_chunk), remaining)])
                        remaining -= min(len(_chunk), remaining)
                    f.flush()
                    os.fsync(f.fileno())
                return {"bytes": _size}
            finally:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
    """),

    "shm_write_fsync_16m": textwrap.dedent("""\
        import tempfile
        _size = 16 * 1024 * 1024
        _chunk = b"x" * (1024 * 1024)

        def run_once():
            fd, path = tempfile.mkstemp(dir="/dev/shm")
            try:
                with os.fdopen(fd, "wb", closefd=True) as f:
                    remaining = _size
                    while remaining:
                        f.write(_chunk[:min(len(_chunk), remaining)])
                        remaining -= min(len(_chunk), remaining)
                    f.flush()
                    os.fsync(f.fileno())
                return {"bytes": _size}
            finally:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
    """),

    # -- Read-back --------------------------------------------------------

    "seq_read_16m": textwrap.dedent("""\
        import tempfile
        _size = 16 * 1024 * 1024
        _path = None

        def setup():
            global _path
            fd, _path = tempfile.mkstemp(dir="/tmp")
            with os.fdopen(fd, "wb") as f:
                remaining = _size
                chunk = b"x" * (1024 * 1024)
                while remaining:
                    n = min(len(chunk), remaining)
                    f.write(chunk[:n])
                    remaining -= n

        def run_once():
            total = 0
            with open(_path, "rb") as f:
                while True:
                    data = f.read(1024 * 1024)
                    if not data:
                        break
                    total += len(data)
            return {"bytes": total}
    """),

    "mmap_read_16m": textwrap.dedent("""\
        import mmap, tempfile
        _size = 16 * 1024 * 1024
        _path = None

        def setup():
            global _path
            fd, _path = tempfile.mkstemp(dir="/tmp")
            with os.fdopen(fd, "wb") as f:
                remaining = _size
                chunk = b"x" * (1024 * 1024)
                while remaining:
                    n = min(len(chunk), remaining)
                    f.write(chunk[:n])
                    remaining -= n

        def run_once():
            with open(_path, "rb") as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
                    total, offset = 0, 0
                    while offset < len(m):
                        end = min(offset + 1024 * 1024, len(m))
                        total += len(m[offset:end])
                        offset = end
            return {"bytes": total}
    """),

    # -- Lifecycle --------------------------------------------------------

    "file_delete_1k": textwrap.dedent("""\
        import tempfile
        _base = None
        _payload = b"x" * 4096

        def before_each():
            global _base
            _base = tempfile.mkdtemp(dir="/tmp")
            for i in range(1000):
                with open(os.path.join(_base, f"f{i:05d}.dat"), "wb") as f:
                    f.write(_payload)

        def run_once():
            count = 0
            for entry in os.scandir(_base):
                os.unlink(entry.path)
                count += 1
            os.rmdir(_base)
            return {"files": count}
    """),

    "rename_1k": textwrap.dedent("""\
        import shutil, tempfile
        _base = None
        _payload = b"x" * 4096

        def before_each():
            global _base
            if _base:
                shutil.rmtree(_base, ignore_errors=True)
            _base = tempfile.mkdtemp(dir="/tmp")
            for i in range(1000):
                with open(os.path.join(_base, f"f{i:05d}.dat"), "wb") as f:
                    f.write(_payload)

        def run_once():
            count = 0
            for entry in os.scandir(_base):
                os.rename(entry.path, entry.path + ".renamed")
                count += 1
            return {"files": count}
    """),

    # -- Mixed / concurrent -----------------------------------------------

    "mixed_read_write": textwrap.dedent("""\
        import sysconfig, tempfile, shutil
        _root = sysconfig.get_paths()["stdlib"]
        _py_files = []

        def setup():
            for root, dirs, files in os.walk(_root):
                for f in files:
                    if f.endswith(".py"):
                        _py_files.append(os.path.join(root, f))

        def run_once():
            reads, writes = 0, 0
            base = tempfile.mkdtemp(dir="/tmp")
            try:
                for i in range(500):
                    with open(_py_files[i % len(_py_files)], "rb") as f:
                        data = f.read()
                    reads += 1
                    with open(os.path.join(base, f"w{i:05d}.dat"), "wb") as f:
                        f.write(data[:4096] if len(data) > 4096 else data)
                    writes += 1
                return {"reads": reads, "writes": writes}
            finally:
                shutil.rmtree(base)
    """),

    "concurrent_read_4t": textwrap.dedent("""\
        import sysconfig, threading
        _root = sysconfig.get_paths()["stdlib"]
        _files = []

        def setup():
            for root, dirs, files in os.walk(_root):
                for f in files:
                    if f.endswith(".py"):
                        _files.append(os.path.join(root, f))

        def _read_chunk(paths, result, idx):
            total = 0
            for p in paths:
                try:
                    with open(p, "rb") as f:
                        total += len(f.read())
                except (PermissionError, OSError):
                    pass
            result[idx] = total

        def run_once():
            n = len(_files)
            chunk_size = (n + 3) // 4
            chunks = [_files[i:i+chunk_size] for i in range(0, n, chunk_size)]
            results = [0] * len(chunks)
            threads = []
            for i, chunk in enumerate(chunks):
                t = threading.Thread(target=_read_chunk, args=(chunk, results, i))
                threads.append(t)
                t.start()
            for t in threads:
                t.join()
            return {"files": n, "bytes": sum(results), "threads": len(chunks)}
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
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception:
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

    print()
    print("Docker vs Microsandbox \u2014 Filesystem Benchmark")
    if len(images) == 1:
        print(f"  Image:      {images[0]}")
    else:
        print(f"  Images:     {', '.join(images)}")
    print(f"  Iterations: {config['iterations']}")
    print(f"  Docker:     {versions['docker']}")
    print(f"  msb:        {versions['msb']}")

    for image, workloads in doc["results"].items():
        print(f"\n  {image}")

        rows: list[list[str]] = []
        for name, data in workloads.items():
            d = data.get("docker", {})
            m = data.get("microsandbox", {})
            if "median_s" in d and "median_s" in m:
                ratio = m["median_s"] / d["median_s"]
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
                ["Workload", "Docker (med)", "msb (med)", "msb/docker", "msb \u03c3"],
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
    p = argparse.ArgumentParser(description="Docker vs Microsandbox filesystem benchmarks")
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

    run_name = args.run_name or "bench"
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
        },
        "versions": {"msb": msb_ver, "docker": docker_ver},
        "pull": None,
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
