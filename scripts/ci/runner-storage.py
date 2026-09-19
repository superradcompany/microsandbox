#!/usr/bin/env python3
"""Bound disposable per-user CI caches and fail early on insufficient disk space."""

import argparse
import os
from pathlib import Path
import shutil
import sys


GIB = 1024**3
# Installed toolchains, credentials, npm logs, and source/build trees are not caches
# owned by this policy. Keep small caches warm; evict oversized caches as a unit.
CACHE_LIMITS = {".cache/uv": GIB, ".npm/_cacache": GIB // 2,
                ".cache/go-build": GIB // 2}


def prune_caches(home: Path) -> None:
    home = home.resolve(strict=True)
    if home == Path("/") or home.stat().st_uid != os.getuid():
        raise ValueError("cache cleanup requires an owned, non-root home directory")
    for relative, limit in CACHE_LIMITS.items():
        path = home / relative
        # Do not follow a symlink in any path component, even within the home.
        if path.resolve() != path or path.is_symlink():
            raise ValueError(f"refusing symlinked cache: {path}")
        if not path.exists():
            continue
        if not path.is_dir() or path.stat().st_uid != os.getuid():
            raise ValueError(f"refusing unowned or non-directory cache: {path}")
        # Count allocated blocks, not logical size (caches may contain sparse files).
        size = 0
        for root, dirs, files in os.walk(path, followlinks=False):
            for name in dirs + files:
                size += (Path(root) / name).lstat().st_blocks * 512
            if size > limit:
                break
        if size > limit:
            print(f"Evict oversized rebuildable cache: {path}", flush=True)
            shutil.rmtree(path)


def check_headroom(path: Path, minimum_gib: int) -> None:
    free = shutil.disk_usage(path).free
    if free < minimum_gib * GIB:
        raise RuntimeError(f"runner disk has {free / GIB:.1f} GiB free; "
                           f"at least {minimum_gib} GiB is required before this job starts. "
                           "Reclaim runner caches or reduce concurrent disk-heavy jobs.")
    print(f"Runner disk headroom: {free / GIB:.1f} GiB free")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--finish", action="store_true",
                        help="prune caches after a job without failing its result for low space")
    args = parser.parse_args()
    try:
        # This is intentionally not a general-purpose developer-home cleanup tool.
        if os.environ.get("GITHUB_ACTIONS") != "true":
            raise ValueError("run only inside GitHub Actions")
        workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
        minimum = int(os.environ.get("MSB_CI_MIN_FREE_GIB", "25"))
        if minimum < 1:
            raise ValueError("MSB_CI_MIN_FREE_GIB must be positive")
        prune_caches(Path.home())
        if not args.finish:
            check_headroom(workspace, minimum)
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
