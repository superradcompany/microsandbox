#!/usr/bin/env python3
"""Validate the complete cross-platform release payload before publication."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
import zipfile
from pathlib import Path


RELEASE_FILES = {
    "agentd-aarch64",
    "agentd-x86_64",
    "libkrunfw-darwin-aarch64.dylib",
    "libkrunfw-linux-aarch64.so",
    "libkrunfw-linux-x86_64.so",
    "libkrunfw-windows-aarch64.dll",
    "libkrunfw-windows-x86_64.dll",
    "libmicrosandbox_go_ffi-darwin-arm64.dylib",
    "libmicrosandbox_go_ffi-linux-amd64.so",
    "libmicrosandbox_go_ffi-linux-arm64.so",
    "libmicrosandbox_go_ffi-windows-amd64.dll",
    "libmicrosandbox_go_ffi-windows-arm64.dll",
    "microsandbox-darwin-aarch64.tar.gz",
    "microsandbox-linux-aarch64.tar.gz",
    "microsandbox-linux-x86_64.tar.gz",
    "microsandbox-windows-aarch64.tar.gz",
    "microsandbox-windows-aarch64.zip",
    "microsandbox-windows-x86_64.tar.gz",
    "microsandbox-windows-x86_64.zip",
    "msb-darwin-aarch64",
    "msb-linux-aarch64",
    "msb-linux-x86_64",
    "msb-windows-aarch64.exe",
    "msb-windows-x86_64.exe",
    "msb-metrics-darwin-aarch64",
    "msb-metrics-linux-aarch64",
    "msb-metrics-linux-x86_64",
    "msb-metrics-windows-aarch64.exe",
    "msb-metrics-windows-x86_64.exe",
}

UNIX_RELEASE_BUNDLES = {
    "microsandbox-darwin-aarch64.tar.gz",
    "microsandbox-linux-aarch64.tar.gz",
    "microsandbox-linux-x86_64.tar.gz",
}

WHEEL_MSB_PATH = "microsandbox/_bundled/bin/msb"

NODE_PACKAGES = {
    "darwin-arm64": ("microsandbox.darwin-arm64.node", "msb", "libkrunfw.5.dylib"),
    "linux-arm64-gnu": (
        "microsandbox.linux-arm64-gnu.node",
        "msb",
        "libkrunfw.so.5.6.1",
    ),
    "linux-x64-gnu": (
        "microsandbox.linux-x64-gnu.node",
        "msb",
        "libkrunfw.so.5.6.1",
    ),
    "win32-arm64-msvc": ("microsandbox.win32-arm64-msvc.node", "msb.exe", "libkrunfw.dll"),
    "win32-x64-msvc": ("microsandbox.win32-x64-msvc.node", "msb.exe", "libkrunfw.dll"),
}

WHEEL_PLATFORMS = {
    "darwin-aarch64": re.compile(r"macosx.*_arm64\.whl$"),
    "linux-aarch64": re.compile(r"manylinux.*_aarch64\.whl$"),
    "linux-x86_64": re.compile(r"manylinux.*_x86_64\.whl$"),
    "windows-aarch64": re.compile(r"win_arm64\.whl$"),
    "windows-x86_64": re.compile(r"win_amd64\.whl$"),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-dir", type=Path, required=True)
    parser.add_argument("--node-dir", type=Path, required=True)
    parser.add_argument("--python-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    return parser.parse_args()


def require_nonempty(path: Path, errors: list[str]) -> None:
    if not path.is_file():
        errors.append(f"missing file: {path}")
    elif path.stat().st_size == 0:
        errors.append(f"empty file: {path}")


def require_executable(mode: int, description: str, errors: list[str]) -> None:
    if mode & 0o111 != 0o111:
        errors.append(f"non-executable {description}: mode {mode & 0o777:#05o}")


def validate_bundle_executable(path: Path, errors: list[str]) -> None:
    if not path.is_file() or path.stat().st_size == 0:
        return

    try:
        with tarfile.open(path, "r:gz") as archive:
            member = archive.getmember("msb")
            require_executable(member.mode, f"msb in {path.name}", errors)
    except (KeyError, OSError, tarfile.TarError) as error:
        errors.append(f"invalid Unix release bundle {path}: {error}")


def validate_wheel_executable(path: Path, errors: list[str]) -> None:
    if not path.is_file() or path.stat().st_size == 0:
        return

    try:
        with zipfile.ZipFile(path) as archive:
            member = archive.getinfo(WHEEL_MSB_PATH)
            require_executable(
                member.external_attr >> 16,
                f"{WHEEL_MSB_PATH} in {path.name}",
                errors,
            )
    except (KeyError, OSError, zipfile.BadZipFile) as error:
        errors.append(f"invalid Unix Python wheel {path}: {error}")


def validate_release_files(root: Path, errors: list[str]) -> list[Path]:
    actual = {path.name for path in root.iterdir() if path.is_file()} if root.is_dir() else set()
    for name in sorted(RELEASE_FILES - actual):
        errors.append(f"missing release asset: {name}")
    for name in sorted(actual - RELEASE_FILES):
        errors.append(f"unexpected release asset: {name}")

    files = [root / name for name in sorted(RELEASE_FILES)]
    for path in files:
        require_nonempty(path, errors)
        if path.name in UNIX_RELEASE_BUNDLES:
            validate_bundle_executable(path, errors)
    return files


def validate_node_files(root: Path, errors: list[str]) -> list[Path]:
    files: list[Path] = []
    for package, (binding, executable, library) in NODE_PACKAGES.items():
        artifact = root / f"node-sdk-{package}"
        required = [
            artifact / "native" / binding,
            artifact / "native" / "index.cjs",
            artifact / "native" / "index.d.ts",
            artifact / "npm" / package / binding,
            artifact / "npm" / package / "bin" / executable,
            artifact / "npm" / package / "lib" / library,
        ]
        for path in required:
            require_nonempty(path, errors)
        files.extend(required)
    return files


def validate_wheels(root: Path, errors: list[str]) -> list[Path]:
    wheels = sorted(root.glob("*.whl")) if root.is_dir() else []
    if len(wheels) != len(WHEEL_PLATFORMS):
        errors.append(f"expected {len(WHEEL_PLATFORMS)} wheels, found {len(wheels)}")

    for platform, pattern in WHEEL_PLATFORMS.items():
        matches = [wheel for wheel in wheels if pattern.search(wheel.name)]
        if len(matches) != 1:
            names = ", ".join(wheel.name for wheel in matches) or "none"
            errors.append(f"expected one {platform} wheel, found: {names}")
        elif not platform.startswith("windows-"):
            validate_wheel_executable(matches[0], errors)
    for wheel in wheels:
        require_nonempty(wheel, errors)
    return wheels


def digest(path: Path) -> dict[str, object]:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return {"path": str(path), "size": path.stat().st_size, "sha256": hasher.hexdigest()}


def main() -> None:
    args = parse_args()
    errors: list[str] = []
    files = [
        *validate_release_files(args.release_dir, errors),
        *validate_node_files(args.node_dir, errors),
        *validate_wheels(args.python_dir, errors),
    ]
    if errors:
        raise SystemExit("release payload is incomplete:\n- " + "\n- ".join(errors))

    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    payload = {"files": [digest(path) for path in sorted(files)]}
    args.manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"validated {len(files)} files across every release platform")


if __name__ == "__main__":
    main()
