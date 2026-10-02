#!/usr/bin/env python3

"""Smoke-test local database upgrades from recent microsandbox releases."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import tarfile
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
    return f"microsandbox-{system}-{machine}.tar.gz"


def firmware_name() -> str:
    """Match the firmware filenames shipped in the supported release bundles."""
    return "libkrunfw.5.dylib" if platform.system() == "Darwin" else "libkrunfw.so.5.6.1"


def unpack_release(archive: Path, checksums: str, destination: Path) -> None:
    """Verify the bundle and extract only its executable and matching firmware."""
    hashes = [line.split()[0] for line in checksums.splitlines()
              if len(line.split()) == 2 and line.split()[1].lstrip("*") == archive.name]
    with archive.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    if hashes != [digest]:
        raise SmokeError("release bundle checksum missing, duplicated, or mismatched")
    with tarfile.open(archive, "r:gz") as bundle:
        members = []
        for name in ("msb", firmware_name()):
            matches = [member for member in bundle.getmembers()
                       if member.name == name or (
                           name == firmware_name() and platform.system() == "Linux"
                           and member.name.startswith("libkrunfw.so.5.")
                           and "/" not in member.name)]
            if len(matches) != 1 or not matches[0].isfile():
                raise SmokeError(f"expected one regular release file: {name}")
            members.append(matches[0])
        # Do not apply archive paths, links, ownership, or permissions. Validate
        # both members before writing either half of the runtime pair.
        for member in members:
            target = destination / ("msb" if member.name == "msb" else firmware_name())
            with bundle.extractfile(member) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)
            target.chmod(0o700 if member.name == "msb" else 0o600)


def download_release_binary(repository: str, version: str, destination: Path) -> None:
    """Download the verified runtime pair, not a standalone executable."""
    release = load_json(
        f"https://api.github.com/repos/{repository}/releases/tags/{version}"
    )
    asset_name = platform_asset()
    for name in (asset_name, "checksums.sha256"):
        assets = [asset for asset in release["assets"] if asset["name"] == name]
        if len(assets) != 1:
            raise SmokeError(f"release {version} must have exactly one {name} asset")
        with urllib.request.urlopen(
            github_request(assets[0]["browser_download_url"]), timeout=60
        ) as response, (destination.parent / name).open("wb") as output:
            shutil.copyfileobj(response, output)
    unpack_release(
        destination.parent / asset_name,
        (destination.parent / "checksums.sha256").read_text(),
        destination.parent,
    )


def fixture_environment(binary: Path, home: Path) -> dict[str, str]:
    """Keep ambient runtime, agent, backend, and user configuration out of fixtures."""
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("MSB_")}
    environment.update(MSB_HOME=str(home), MSB_PATH=str(binary), MSB_BACKEND="local",
                       MSB_CONFIG_PATH=str(home / "config.json"), NO_COLOR="1")
    # Candidate CI artifacts and released bundles both contain this pair.
    environment["MSB_LIBKRUNFW_PATH"] = str(binary.parent / firmware_name())
    return environment


def run_msb(binary: Path, *arguments: str, home: Path | None = None) -> None:
    """Run msb with output hidden unless the command fails."""
    assert home is not None, "smoke commands require an isolated home"
    home.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [str(binary), *arguments],
        env=fixture_environment(binary, home),
        cwd=home,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
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
        timeout=30,
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
    """Verify released identifiers survive and the candidate applies its full schema."""
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
    # This is a CLI upgrade test, not a promise that an old catalog reader can
    # reopen a newer schema. Already-running old VMs have a separate live fixture.
    expected = set(candidate_migrations)
    if applied != expected:
        raise SmokeError(
            "database does not contain the candidate migration set after upgrade; "
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

    # Opening twice verifies compatibility and its steady-state/idempotent path.
    run_msb(candidate, "list", home=old_home)
    with sqlite3.connect(old_home / "db" / "msb.db") as database:
        upgraded_schema = database.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name"
        ).fetchall()
    run_msb(candidate, "list", home=old_home)
    verify_migration_set(
        version,
        old_baseline,
        candidate_baseline,
        old_home / "db" / "msb.db",
    )
    with sqlite3.connect(old_home / "db" / "msb.db") as database:
        current_schema = database.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name"
        ).fetchall()
    if current_schema != upgraded_schema:
        raise SmokeError(f"second candidate open changed the upgraded {version} schema")
    print(f"upgrade smoke passed: {version} -> candidate; repeat open is idempotent")


def main() -> int:
    """Run the previous-release upgrade smoke test."""
    candidate = Path(os.environ.get("MSB_BIN", ROOT_DIR / "build" / "msb")).resolve()
    repository = os.environ.get("MSB_UPGRADE_SMOKE_REPO", DEFAULT_REPOSITORY)
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        raise SmokeError(f"msb binary is not executable: {candidate}")

    versions = released_versions(repository)
    if not versions:
        raise SmokeError("no released versions found for upgrade smoke test")

    candidate_baseline = schema_baseline(candidate)
    with tempfile.TemporaryDirectory(prefix="msb-upgrade-smoke-") as temp_dir:
        smoke_root = Path(temp_dir)
        fresh_home = smoke_root / "candidate-fresh"
        run_msb(candidate, "list", home=fresh_home)
        verify_migration_set(
            "candidate", candidate_baseline, candidate_baseline, fresh_home / "db" / "msb.db"
        )
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
