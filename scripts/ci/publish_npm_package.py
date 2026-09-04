#!/usr/bin/env python3
"""Publish npm packages idempotently after verifying immutable contents."""

from __future__ import annotations

import argparse
import json
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path


NPM_REGISTRY = "https://registry.npmjs.org"
USER_AGENT = "microsandbox-release-ci (https://github.com/superradcompany/microsandbox)"


@dataclass(frozen=True)
class Package:
    """An npm package directory and its immutable registry identity."""

    directory: Path
    name: str
    version: str

    @property
    def spec(self) -> str:
        """Return the registry package and version selector."""
        return f"{self.name}@{self.version}"


def parse_args() -> argparse.Namespace:
    """Parse package directories from the command line."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "packages", type=Path, nargs="+", help="npm package directories"
    )
    return parser.parse_args()


def load_package(directory: Path) -> Package:
    """Load an npm package identity from a package directory."""
    manifest_path = directory / "package.json"
    manifest = json.loads(manifest_path.read_text())
    try:
        name = manifest["name"]
        version = manifest["version"]
    except KeyError as error:
        raise SystemExit(f"missing {error.args[0]} in {manifest_path}") from error
    if not isinstance(name, str) or not isinstance(version, str):
        raise SystemExit(f"invalid npm package identity in {manifest_path}")
    return Package(directory, name, version)


def request_json(url: str) -> dict[str, object] | None:
    """Fetch registry JSON, returning None only for an absent version."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def registry_integrity(package: Package) -> str | None:
    """Return the published tarball integrity for a package version."""
    encoded_name = urllib.parse.quote(package.name, safe="@")
    encoded_version = urllib.parse.quote(package.version, safe="")
    metadata = request_json(f"{NPM_REGISTRY}/{encoded_name}/{encoded_version}")
    if metadata is None:
        return None
    dist = metadata.get("dist")
    integrity = dist.get("integrity") if isinstance(dist, dict) else None
    if not isinstance(integrity, str):
        raise SystemExit(f"npm registry omitted dist.integrity for {package.spec}")
    return integrity


def pack_integrity(package: Package) -> str:
    """Build the local npm tarball manifest and return its integrity."""
    result = subprocess.run(
        ["npm", "pack", "--dry-run", "--json"],
        cwd=package.directory,
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(result.stdout)
    if not isinstance(payload, list) or len(payload) != 1:
        raise SystemExit(f"unexpected npm pack output for {package.spec}")
    packed = payload[0]
    if packed.get("name") != package.name or packed.get("version") != package.version:
        raise SystemExit(f"npm pack identity mismatch for {package.spec}")
    integrity = packed.get("integrity")
    if not isinstance(integrity, str):
        raise SystemExit(f"npm pack omitted integrity for {package.spec}")
    return integrity


def publish_package(package: Package) -> None:
    """Publish a missing version or verify an identical existing version."""
    local_integrity = pack_integrity(package)
    remote_integrity = registry_integrity(package)
    if remote_integrity is not None:
        if remote_integrity != local_integrity:
            raise SystemExit(f"{package.spec} exists with different contents")
        print(f"{package.spec} already published; integrity matches", flush=True)
        return

    print(f"publishing {package.spec}", flush=True)
    subprocess.run(
        ["npm", "publish", "--access", "public"],
        cwd=package.directory,
        check=True,
    )


def main() -> None:
    """Publish each requested npm package in command-line order."""
    args = parse_args()
    for directory in args.packages:
        publish_package(load_package(directory))


if __name__ == "__main__":
    main()
