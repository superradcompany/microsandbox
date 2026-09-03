#!/usr/bin/env python3

"""Smoke-test local database upgrades from recent microsandbox releases."""

from __future__ import annotations

import json
import os
import platform
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Any


ROOT_DIR = Path(__file__).resolve().parents[3]
DEFAULT_REPOSITORY = "superradcompany/microsandbox"


class SmokeError(Exception):
    """An expected smoke-test failure with a concise user-facing message."""


def github_request(url: str) -> urllib.request.Request:
    """Build an authenticated GitHub request when CI provides a token."""
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "microsandbox-upgrade-smoke",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token := os.environ.get("GH_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    return urllib.request.Request(url, headers=headers)


def load_json(url: str) -> Any:
    """Load JSON from the GitHub API."""
    with urllib.request.urlopen(github_request(url), timeout=30) as response:
        return json.load(response)


def released_versions(repository: str) -> list[str]:
    """Return the two latest stable release tags, or an explicit override."""
    if override := os.environ.get("MSB_UPGRADE_FROM_VERSIONS"):
        return override.split()

    releases = load_json(f"https://api.github.com/repos/{repository}/releases?per_page=10")
    return [
        release["tag_name"]
        for release in releases
        if not release["draft"] and not release["prerelease"]
    ][:2]


def platform_asset() -> str:
    """Return the release asset name for the current host."""
    systems = {"Darwin": "darwin", "Linux": "linux"}
    machines = {
        "arm64": "aarch64",
        "aarch64": "aarch64",
        "x86_64": "x86_64",
        "amd64": "x86_64",
    }
    try:
        system = systems[platform.system()]
        machine = machines[platform.machine().lower()]
    except KeyError as error:
        raise SmokeError(
            f"unsupported smoke-test platform: {platform.system()} {platform.machine()}"
        ) from error
    return f"msb-{system}-{machine}"


def download_release_binary(repository: str, version: str, destination: Path) -> None:
    """Download one released msb binary for this host."""
    release = load_json(
        f"https://api.github.com/repos/{repository}/releases/tags/{version}"
    )
    asset_name = platform_asset()
    asset = next(
        (candidate for candidate in release["assets"] if candidate["name"] == asset_name),
        None,
    )
    if asset is None:
        raise SmokeError(f"release {version} has no {asset_name} asset")

    with urllib.request.urlopen(
        github_request(asset["browser_download_url"]), timeout=30
    ) as response, destination.open("wb") as output:
        shutil.copyfileobj(response, output)
    destination.chmod(
        destination.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    )


def run_msb(binary: Path, *arguments: str, home: Path | None = None) -> None:
    """Run msb with output hidden unless the command fails."""
    environment = os.environ.copy()
    if home is not None:
        environment["MSB_HOME"] = str(home)
    result = subprocess.run(
        [str(binary), *arguments],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SmokeError(f"{binary} {' '.join(arguments)} exited with {result.returncode}")


def schema_baseline(binary: Path) -> dict[str, Any]:
    """Read the hidden schema compatibility metadata from an msb binary."""
    result = subprocess.run(
        [str(binary), "__schema-baseline", "--json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        raise SmokeError(f"failed to read schema baseline from {binary}")
    return json.loads(result.stdout)


def verify_migration_set(
    version: str,
    old_baseline: dict[str, Any],
    candidate_baseline: dict[str, Any],
    database_path: Path,
) -> None:
    """Verify released identifiers survive and the candidate fully migrates."""
    old_migrations = old_baseline["migrations"]
    candidate_migrations = candidate_baseline["migrations"]
    if len(old_migrations) != len(set(old_migrations)):
        raise SmokeError(f"{version} reports duplicate migration identifiers")
    if len(candidate_migrations) != len(set(candidate_migrations)):
        raise SmokeError("candidate reports duplicate migration identifiers")

    missing = sorted(set(old_migrations) - set(candidate_migrations))
    if missing:
        raise SmokeError(
            f"candidate removed migrations shipped by {version}: {', '.join(missing)}"
        )

    with sqlite3.connect(database_path) as database:
        applied = {
            row[0] for row in database.execute("SELECT version FROM seaql_migrations")
        }
    expected = set(candidate_migrations)
    if applied != expected:
        raise SmokeError(
            "candidate database migration set does not match its schema baseline; "
            f"missing={sorted(expected - applied)}, "
            f"unexpected={sorted(applied - expected)}"
        )


def verify_upgrade(
    repository: str,
    version: str,
    candidate: Path,
    candidate_baseline: dict[str, Any],
    smoke_root: Path,
) -> None:
    """Create a released database and open it twice with the candidate."""
    release_dir = smoke_root / version
    release_dir.mkdir(parents=True)
    old_msb = release_dir / "msb"
    old_home = release_dir / "home"

    download_release_binary(repository, version, old_msb)
    old_baseline = schema_baseline(old_msb)
    run_msb(old_msb, "list", home=old_home)

    # Opening twice verifies both the upgrade and its steady-state/idempotent path.
    run_msb(candidate, "list", home=old_home)
    run_msb(candidate, "list", home=old_home)
    verify_migration_set(
        version,
        old_baseline,
        candidate_baseline,
        old_home / "db" / "msb.db",
    )
    print(f"upgrade smoke passed: {version} -> candidate")


def main() -> int:
    """Run the previous-release upgrade smoke test."""
    candidate = Path(os.environ.get("MSB_BIN", ROOT_DIR / "build" / "msb"))
    repository = os.environ.get("MSB_UPGRADE_SMOKE_REPO", DEFAULT_REPOSITORY)
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        raise SmokeError(f"msb binary is not executable: {candidate}")

    versions = released_versions(repository)
    if not versions:
        raise SmokeError("no released versions found for upgrade smoke test")

    candidate_baseline = schema_baseline(candidate)
    with tempfile.TemporaryDirectory(prefix="msb-upgrade-smoke-") as temp_dir:
        smoke_root = Path(temp_dir)
        for version in versions:
            verify_upgrade(
                repository,
                version,
                candidate,
                candidate_baseline,
                smoke_root,
            )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, KeyError, ValueError, SmokeError) as error:
        raise SystemExit(f"error: {error}") from error
