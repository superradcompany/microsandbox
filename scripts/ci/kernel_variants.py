#!/usr/bin/env python3
"""Prepare and verify libkrunfw feature variants for a release."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


ARCHES = ("x86_64", "aarch64")
TARGET_ARCH = {
    "linux-x86_64": "x86_64",
    "linux-aarch64": "aarch64",
    "darwin-aarch64": "aarch64",
    "windows-x86_64": "x86_64",
    "windows-aarch64": "aarch64",
}
BASELINE = (
    "CONFIG_EXT4_FS",
    "CONFIG_EROFS_FS",
    "CONFIG_FUSE_FS",
    "CONFIG_OVERLAY_FS",
    "CONFIG_DRM_VIRTIO_GPU",
    "CONFIG_VIRTIO_INPUT",
)
SYMBOL = re.compile(r"CONFIG_[A-Z0-9_]+\Z")
GROUP_ID = re.compile(r"[a-z][a-z0-9-]*\Z")
VERSION = re.compile(r"^KERNEL_VERSION = (linux-[\d.]+)$", re.M)
LIBRARY_VERSION = re.compile(r"^FULL_VERSION = ([\d.]+)$", re.M)
PROFILES = Path(__file__).with_name("kernel-variant-profiles.json")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def profile_sha256(path: Path) -> str:
    payload = json.loads(path.read_text())
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def asset_name(target: str, mask: int) -> str:
    extension = {"linux": "so", "darwin": "dylib", "windows": "dll"}[target.split("-")[0]]
    return f"libkrunfw-{target}-m{mask:02d}.{extension}"


def requested_symbols(profiles: Path, mask: int, arch: str) -> tuple[list[str], dict[str, str]]:
    payload = json.loads(profiles.read_text())
    if not isinstance(payload, dict) or set(payload) != {"groups"} or not isinstance(payload["groups"], list):
        raise ValueError("profiles must contain a groups array")
    groups = payload["groups"]
    if len(groups) != 5 or not 0 <= mask < 1 << len(groups):
        raise ValueError("five groups and a mask from 0 to 31 are required")
    names = []
    requested = {}
    for bit, group in enumerate(groups):
        if not isinstance(group, dict) or set(group) != {"id", *ARCHES}:
            raise ValueError("each group needs an id and both guest architectures")
        name = group["id"]
        if not isinstance(name, str) or not GROUP_ID.fullmatch(name) or name in names:
            raise ValueError(f"invalid or duplicate group id: {name!r}")
        names.append(name)
        for guest_arch in ARCHES:
            symbols = group[guest_arch]
            if not isinstance(symbols, dict) or not symbols:
                raise ValueError(f"{name}/{guest_arch} needs symbols")
            for key, value in symbols.items():
                if not isinstance(key, str) or not SYMBOL.fullmatch(key) or value != "y":
                    raise ValueError(f"invalid {name}/{guest_arch} request: {key}={value}")
        if mask & (1 << bit):
            requested.update(group[arch])
    return [name for bit, name in enumerate(names) if mask & (1 << bit)], requested


def kernel_source(firmware: Path) -> Path:
    match = VERSION.search((firmware / "Makefile").read_text())
    if match is None:
        raise ValueError("cannot identify pinned Linux source directory")
    return firmware / match.group(1)


def render_config(base: str, symbols: dict[str, str]) -> str:
    lines = []
    for line in base.splitlines():
        match = re.match(r"(?:# )?(CONFIG_[A-Z0-9_]+)(?:=| is not set)", line)
        if match is None or match.group(1) not in symbols:
            lines.append(line)
    lines.extend(f"{key}={value}" for key, value in sorted(symbols.items()))
    return "\n".join(lines) + "\n"


def resolved_config(path: Path) -> dict[str, str]:
    resolved = {}
    for line in path.read_text().splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            resolved[key] = value
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            resolved[line[2:-11]] = "n"
    return resolved


def prepare(firmware: Path, profiles: Path, mask: int, arch: str) -> None:
    _, symbols = requested_symbols(profiles, mask, arch)
    source = kernel_source(firmware)
    if source.exists():
        raise ValueError(f"kernel source already exists; use a fresh checkout: {source}")
    config = firmware / f"config-libkrunfw_{arch}"
    config.write_text(render_config(config.read_text(), symbols))


def verify(firmware: Path, profiles: Path, mask: int, arch: str) -> dict:
    names, symbols = requested_symbols(profiles, mask, arch)
    config = kernel_source(firmware) / ".config"
    resolved = resolved_config(config)
    missing = [key for key in (*symbols, *BASELINE) if resolved.get(key) != "y"]
    if missing:
        raise ValueError(f"{arch}/mask {mask} unresolved required symbols: {missing}")

    bundle = firmware / "kernel.c"
    version = LIBRARY_VERSION.search((firmware / "Makefile").read_text())
    if version is None:
        raise ValueError("cannot identify libkrunfw library version")
    library = firmware / f"libkrunfw.so.{version.group(1)}"
    for path in (bundle, library):
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing or empty build output: {path}")

    return {
        "schema": 1,
        "mask": mask,
        "groups": names,
        "guest_arch": arch,
        "host_target": f"linux-{arch}",
        "requested_y": sorted(symbols),
        "profile_sha256": profile_sha256(profiles),
        "resolved_config_sha256": sha256(config),
        "kernel_c_sha256": sha256(bundle),
        "library_filename": library.name,
        "library_asset": asset_name(f"linux-{arch}", mask),
        "libkrunfw_sha256": sha256(library),
    }


def record_link(
    kernel_manifest: Path, kernel_bundle: Path, library: Path, target: str, profiles: Path
) -> dict:
    manifest = json.loads(kernel_manifest.read_text())
    arch = TARGET_ARCH[target]
    mask = manifest.get("mask")
    if not isinstance(mask, int) or not 0 <= mask < 32:
        raise ValueError("invalid kernel variant mask")
    names, symbols = requested_symbols(profiles, mask, arch)
    expected = {
        "host_target": f"linux-{arch}",
        "guest_arch": arch,
        "groups": names,
        "requested_y": sorted(symbols),
        "profile_sha256": profile_sha256(profiles),
        "kernel_c_sha256": sha256(kernel_bundle),
    }
    for field, value in expected.items():
        if manifest.get(field) != value:
            raise ValueError(f"{target}/mask {mask} has a mismatched {field}")
    if not library.is_file() or library.stat().st_size == 0:
        raise ValueError(f"missing or empty linked library: {library}")
    manifest.update(
        host_target=target,
        library_filename=library.name,
        library_asset=asset_name(target, mask),
        libkrunfw_sha256=sha256(library),
    )
    return manifest


def index(manifests: Path, profiles: Path) -> dict:
    variants = []
    seen = set()
    for path in sorted(manifests.glob("manifest-*.json")):
        manifest = json.loads(path.read_text())
        target = manifest.get("host_target")
        mask = manifest.get("mask")
        if target not in TARGET_ARCH or not isinstance(mask, int) or not 0 <= mask < 32:
            raise ValueError(f"invalid variant identity: {path}")
        arch = TARGET_ARCH[target]
        expected_name = f"manifest-{target}-m{mask:02d}.json"
        names, symbols = requested_symbols(profiles, mask, arch)
        if (
            path.name != expected_name
            or (target, mask) in seen
            or manifest.get("schema") != 1
            or manifest.get("groups") != names
            or manifest.get("guest_arch") != arch
            or manifest.get("requested_y") != sorted(symbols)
            or manifest.get("profile_sha256") != profile_sha256(profiles)
            or manifest.get("library_asset") != asset_name(target, mask)
        ):
            raise ValueError(f"invalid variant manifest: {path}")
        seen.add((target, mask))
        variants.append(manifest)
    expected = {(target, mask) for target in TARGET_ARCH for mask in range(32)}
    if seen != expected:
        raise ValueError(f"variant manifests incomplete: missing={sorted(expected - seen)}")
    return {"schema": 1, "profile_sha256": profile_sha256(profiles), "variants": variants}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "verify", "record-link", "index"))
    parser.add_argument("--firmware", type=Path, default=Path("vendor/libkrunfw"))
    parser.add_argument("--profiles", type=Path, default=PROFILES)
    parser.add_argument("--mask", type=int)
    parser.add_argument("--arch", choices=ARCHES)
    parser.add_argument("--manifests", type=Path)
    parser.add_argument("--target", choices=TARGET_ARCH)
    parser.add_argument("--kernel-manifest", type=Path)
    parser.add_argument("--kernel-bundle", type=Path)
    parser.add_argument("--library", type=Path)
    args = parser.parse_args()

    if args.command == "index":
        if args.manifests is None:
            parser.error("index requires --manifests")
        print(json.dumps(index(args.manifests, args.profiles), sort_keys=True))
    elif args.command == "record-link":
        if not all((args.target, args.kernel_manifest, args.kernel_bundle, args.library)):
            parser.error("record-link requires --target, --kernel-manifest, --kernel-bundle, and --library")
        print(json.dumps(record_link(args.kernel_manifest, args.kernel_bundle, args.library, args.target, args.profiles), sort_keys=True))
    elif args.mask is None or args.arch is None:
        parser.error(f"{args.command} requires --mask and --arch")
    elif args.command == "prepare":
        prepare(args.firmware, args.profiles, args.mask, args.arch)
    else:
        print(json.dumps(verify(args.firmware, args.profiles, args.mask, args.arch), sort_keys=True))


if __name__ == "__main__":
    main()
