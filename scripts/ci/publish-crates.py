#!/usr/bin/env python3
"""Publish the intended Rust release closure in dependency-order waves."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path


DEFAULT_ROOTS = (
    "microsandbox-agentd",
    "microsandbox-cli",
    "microsandbox-metrics-collector",
)
USER_AGENT = "microsandbox-release-ci (https://github.com/superradcompany/microsandbox)"


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    dependencies: frozenset[str]

    @property
    def archive(self) -> Path:
        return Path("target/package") / f"{self.name}-{self.version}.crate"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", action="store_true", help="print the publication waves only")
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="validate package manifests and assemble registry-independent crates",
    )
    parser.add_argument("--timeout", type=int, default=180, help="registry visibility timeout")
    parser.add_argument("--root", action="append", dest="roots", help="published root crate")
    return parser.parse_args()


def cargo_metadata() -> dict[str, object]:
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def publication_closure(metadata: dict[str, object], roots: tuple[str, ...]) -> dict[str, Package]:
    raw_packages = {package["name"]: package for package in metadata["packages"]}
    missing = sorted(set(roots) - raw_packages.keys())
    if missing:
        raise SystemExit(f"unknown release root crates: {', '.join(missing)}")

    selected: set[str] = set()
    pending = list(roots)
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        raw = raw_packages[name]
        if raw.get("publish") == []:
            raise SystemExit(f"release crate {name} has publish = false")
        selected.add(name)
        # Optional normal/build dependencies must be publishable even when a
        # feature is currently off. Dev-only workspace helpers never ship.
        pending.extend(
            dependency["name"]
            for dependency in raw["dependencies"]
            if dependency.get("kind") != "dev"
            and dependency.get("path") is not None
            and dependency["name"] in raw_packages
        )

    packages = {}
    for name in selected:
        raw = raw_packages[name]
        dependencies = frozenset(
            dependency["name"]
            for dependency in raw["dependencies"]
            if dependency.get("kind") != "dev"
            and dependency.get("path") is not None
            and dependency["name"] in selected
        )
        packages[name] = Package(name, raw["version"], dependencies)
    return packages


def dependency_waves(packages: dict[str, Package]) -> list[list[Package]]:
    remaining = set(packages)
    published: set[str] = set()
    waves: list[list[Package]] = []
    while remaining:
        ready = sorted(
            (packages[name] for name in remaining if packages[name].dependencies <= published),
            key=lambda package: package.name,
        )
        if not ready:
            blocked = ", ".join(sorted(remaining))
            raise SystemExit(f"workspace dependency cycle in release crates: {blocked}")
        waves.append(ready)
        published.update(package.name for package in ready)
        remaining.difference_update(package.name for package in ready)
    return waves


def request_json(url: str) -> dict[str, object] | None:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def registry_checksum(package: Package) -> str | None:
    url = f"https://crates.io/api/v1/crates/{package.name}/{package.version}"
    response = request_json(url)
    if response is None:
        return None
    return response["version"]["checksum"]


def archive_checksum(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def sparse_index_url(name: str) -> str:
    # crates.io follows Cargo's length-sensitive sparse-index sharding scheme.
    lowered = name.lower()
    if len(lowered) == 1:
        path = f"1/{lowered}"
    elif len(lowered) == 2:
        path = f"2/{lowered}"
    elif len(lowered) == 3:
        path = f"3/{lowered[0]}/{lowered}"
    else:
        path = f"{lowered[:2]}/{lowered[2:4]}/{lowered}"
    return f"https://index.crates.io/{path}"


def version_is_indexed(package: Package) -> bool:
    request = urllib.request.Request(
        sparse_index_url(package.name),
        headers={"User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            for line in response:
                if json.loads(line)["vers"] == package.version:
                    return True
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
    return False


def wait_until_indexed(packages: list[Package], timeout: int) -> None:
    deadline = time.monotonic() + timeout
    pending = {package.name: package for package in packages}
    delay = 1
    while pending:
        for name, package in list(pending.items()):
            if version_is_indexed(package):
                print(
                    f"{package.name} {package.version} is visible in the sparse index",
                    flush=True,
                )
                del pending[name]
        if not pending:
            return
        if time.monotonic() >= deadline:
            names = ", ".join(sorted(pending))
            raise SystemExit(f"timed out waiting for crates.io sparse index: {names}")
        print(f"waiting {delay}s for crates.io: {', '.join(sorted(pending))}", flush=True)
        time.sleep(delay)
        delay = min(delay * 2, 20)


def list_package_files(packages: list[Package]) -> None:
    """Validate each package manifest without resolving unpublished dependencies."""
    for package in sorted(packages, key=lambda item: item.name):
        subprocess.run(["cargo", "package", "-p", package.name, "--list"], check=True)


def package_all(packages: list[Package]) -> None:
    for package in sorted(packages, key=lambda item: item.name):
        subprocess.run(["cargo", "package", "-p", package.name, "--no-verify"], check=True)


def publish(waves: list[list[Package]], timeout: int) -> None:
    for number, wave in enumerate(waves, start=1):
        # Cargo normalizes path dependencies to registry dependencies while it
        # packages a crate. Package one wave at a time, after the prior wave is
        # indexed, so a brand-new release never tries to resolve unpublished
        # internal versions.
        package_all(wave)
        newly_published = []
        names = ", ".join(package.name for package in wave)
        print(f"publishing wave {number}: {names}", flush=True)
        for package in wave:
            remote_checksum = registry_checksum(package)
            if remote_checksum is not None:
                local_checksum = archive_checksum(package.archive)
                if local_checksum != remote_checksum:
                    raise SystemExit(
                        f"{package.name} {package.version} exists with a different checksum"
                    )
                print(f"{package.name} {package.version} already published; checksum matches")
                continue
            subprocess.run(
                ["cargo", "publish", "-p", package.name, "--no-verify"],
                check=True,
            )
            newly_published.append(package)
        if newly_published:
            wait_until_indexed(newly_published, timeout)


def main() -> None:
    args = parse_args()
    roots = tuple(args.roots or DEFAULT_ROOTS)
    waves = dependency_waves(publication_closure(cargo_metadata(), roots))
    print(json.dumps([[package.name for package in wave] for wave in waves], indent=2))
    if args.validate_only:
        packages = [package for wave in waves for package in wave]
        list_package_files(packages)
        # Only the first wave is registry-independent. Higher waves can be
        # assembled once these archives have actually been published and
        # indexed, which publish() enforces without fixed sleeps.
        package_all(waves[0])
    elif not args.plan:
        publish(waves, args.timeout)


if __name__ == "__main__":
    main()
