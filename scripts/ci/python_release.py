#!/usr/bin/env python3
"""Collect isolated Python artifacts and publish one trusted-publisher project."""

import argparse
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.request import urlopen
import zipfile


TARGETS = (
    "darwin-aarch64", "linux-aarch64", "linux-x86_64",
    "windows-aarch64", "windows-x86_64",
)
PACKAGES = ("microsandbox", "microsandbox-core", "microsandbox-local", "microsandbox-remote")
CORE = "microsandbox-core"
# All builders emit core with the same filename. Select one UTF-8 Unix build,
# never whichever parallel artifact extraction happens to finish last.
CORE_TARGET = "darwin-aarch64"


def inspect_wheel(path):
    """Read every ZIP member so central-directory-only checks cannot miss damage."""
    with zipfile.ZipFile(path) as archive:
        bad = archive.testzip()
        if bad:
            raise ValueError(f"corrupt wheel member: {path}: {bad}")
        metadata = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        if len(metadata) != 1:
            raise ValueError(f"expected one METADATA in {path}")
        info = BytesParser().parsebytes(archive.read(metadata[0]))
    name = info.get("Name", "").lower().replace("_", "-")
    version = info.get("Version")
    if name not in PACKAGES or not version:
        raise ValueError(f"unexpected package metadata in {path}")
    if not path.name.startswith(name.replace("-", "_") + "-"):
        raise ValueError(f"filename/metadata package mismatch: {path}")
    return name, version


def collect(source, destination):
    if destination.exists() and any(destination.iterdir()):
        raise ValueError(f"output directory must be empty: {destination}")
    expected_dirs = {f"python-sdk-{target}" for target in TARGETS}
    if {path.name for path in source.iterdir()} != expected_dirs:
        raise ValueError("expected exactly the five isolated python-sdk target directories")
    selected = {}
    core_filename = None
    versions = {}
    for target in TARGETS:
        directory = source / f"python-sdk-{target}"
        found = set()
        for path in sorted(directory.glob("*.whl")):
            package, version = inspect_wheel(path)
            if package in found:
                raise ValueError(f"duplicate {package} wheel in {directory}")
            found.add(package)
            if package == CORE:
                if not path.name.endswith("-py3-none-any.whl"):
                    raise ValueError(f"core wheel must be platform independent: {path}")
                if core_filename is not None and path.name != core_filename:
                    raise ValueError("core wheel filenames differ across targets")
                core_filename = path.name
                if target != CORE_TARGET:
                    continue
            if path.name in selected:
                raise ValueError(f"duplicate platform wheel filename: {path.name}")
            if package in versions and versions[package] != version:
                raise ValueError(f"mixed versions for {package}")
            versions[package] = version
            selected[path.name] = path
        if found != set(PACKAGES):
            raise ValueError(f"missing packages in {directory}: {set(PACKAGES) - found}")
    # Validate every input before copying; consumers never see a partially
    # accepted artifact set, and each destination file has exactly one writer.
    destination.mkdir(parents=True, exist_ok=True)
    for name, path in sorted(selected.items()):
        shutil.copyfile(path, destination / name)
    return list(sorted(selected))


def package_wheels(directory, package):
    # Match the distribution separator, not a broad microsandbox* glob which
    # would send other projects through this job's OIDC identity.
    wheels = sorted(directory.glob(package.replace("-", "_") + "-*.whl"))
    expected = 1 if package == CORE else len(TARGETS)
    if len(wheels) != expected:
        raise ValueError(f"expected {expected} wheels for {package}, found {len(wheels)}")
    identities = {inspect_wheel(path) for path in wheels}
    if len(identities) != 1 or next(iter(identities))[0] != package:
        raise ValueError(f"mixed package names or versions for {package}")
    return wheels, next(iter(identities))[1]


def wait_for_index(package, version, wheels, attempts=30, delay=10):
    expected = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in wheels}
    url = f"https://pypi.org/pypi/{package}/{version}/json"
    for attempt in range(attempts):
        try:
            with urlopen(url, timeout=15) as response:
                files = {item["filename"]: item["digests"]["sha256"] for item in json.load(response)["urls"]}
            for name, digest in expected.items():
                if name in files and files[name] != digest:
                    raise ValueError(f"PyPI already contains different bytes for {name}")
            if expected.items() <= files.items():
                return
        except HTTPError as error:
            error.close()
            if error.code != 404 and error.code != 429 and error.code < 500:
                raise
        except (URLError, TimeoutError):
            pass
        if attempt + 1 < attempts:
            print(f"Waiting for PyPI to index {package} {version} ({attempt + 1}/{attempts})", flush=True)
            time.sleep(delay)
    raise RuntimeError(f"PyPI did not index all {package} {version} wheels after {attempts} checks")


def publish(directory, package):
    wheels, version = package_wheels(directory, package)
    # Explicit OIDC and duplicate detection make retries credential-free and
    # idempotent. uv checks existing file hashes rather than replacing files.
    subprocess.run([
        "uv", "publish", "--trusted-publishing", "always",
        "--check-url", "https://pypi.org/simple/", *map(str, wheels),
    ], check=True)
    # Core's job must not unblock its dependents until the exact wheel is public.
    wait_for_index(package, version, wheels)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    collector = commands.add_parser("collect")
    collector.add_argument("--source", type=Path, required=True)
    collector.add_argument("--destination", type=Path, required=True)
    publisher = commands.add_parser("publish")
    publisher.add_argument("--directory", type=Path, required=True)
    publisher.add_argument("--package", choices=PACKAGES, required=True)
    args = parser.parse_args()
    if args.command == "collect":
        print("\n".join(collect(args.source, args.destination)))
    else:
        publish(args.directory, args.package)


if __name__ == "__main__":
    main()
