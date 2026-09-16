#!/usr/bin/env python3
"""Reject Linux release artifacts that exceed the supported glibc baseline."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

ELF_MAGIC = b"\x7fELF"
GLIBC_VERSION = re.compile(r"\bGLIBC_(\d+(?:\.\d+)+)\b")
INSTALLER_GLIBC_MIN_VERSION = re.compile(
    r'^LINUX_GLIBC_MIN_VERSION="(?P<version>\d+(?:\.\d+)+)"$', re.MULTILINE
)
ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".tar", ".whl", ".zip")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate the maximum required glibc symbol version in ELF artifacts."
    )
    parser.add_argument(
        "paths",
        type=Path,
        nargs="+",
        help="Files or directories to inspect recursively.",
    )
    parser.add_argument(
        "--max-version",
        default="2.28",
        help="Highest allowed GLIBC symbol version (default: 2.28).",
    )
    parser.add_argument(
        "--installer",
        type=Path,
        help="Installer script whose declared minimum must match --max-version.",
    )
    return parser.parse_args()


def parse_version(value: str) -> tuple[int, ...]:
    """Convert a dotted numeric version to a tuple suitable for comparison."""
    if not re.fullmatch(r"\d+(?:\.\d+)+", value):
        raise ValueError(f"invalid numeric version: {value}")
    return tuple(int(part) for part in value.split("."))


def version_key(version: tuple[int, ...], width: int = 4) -> tuple[int, ...]:
    """Pad versions so 2.28 and 2.28.0 compare as the same baseline."""
    return (*version, *(0 for _ in range(max(0, width - len(version)))))


def parse_glibc_versions(readelf_output: str) -> set[tuple[int, ...]]:
    """Extract every versioned glibc dependency reported by readelf."""
    return {parse_version(match) for match in GLIBC_VERSION.findall(readelf_output)}


def validate_installer_baseline(
    installer: str, maximum: tuple[int, ...]
) -> tuple[int, ...]:
    """Return the installer floor when it matches the audited artifact baseline."""
    match = INSTALLER_GLIBC_MIN_VERSION.search(installer)
    if match is None:
        raise ValueError("installer does not declare LINUX_GLIBC_MIN_VERSION")

    minimum = parse_version(match.group("version"))
    if version_key(minimum) != version_key(maximum):
        rendered_minimum = ".".join(map(str, minimum))
        rendered_maximum = ".".join(map(str, maximum))
        raise ValueError(
            f"installer requires glibc {rendered_minimum}, but release artifacts "
            f"are audited against glibc {rendered_maximum}"
        )
    return minimum


def is_elf(path: Path) -> bool:
    try:
        with path.open("rb") as source:
            return source.read(len(ELF_MAGIC)) == ELF_MAGIC
    except OSError:
        return False


def iter_files(paths: list[Path]) -> Iterator[Path]:
    for path in paths:
        if path.is_dir():
            yield from (
                candidate
                for candidate in sorted(path.rglob("*"))
                if candidate.is_file()
            )
        elif path.is_file():
            yield path
        else:
            raise FileNotFoundError(f"artifact path does not exist: {path}")


def copy_if_elf(source: BinaryIO, destination: Path) -> bool:
    """Copy an archive member only when its first bytes identify an ELF file."""
    prefix = source.read(len(ELF_MAGIC))
    if prefix != ELF_MAGIC:
        return False
    with destination.open("wb") as output:
        output.write(prefix)
        shutil.copyfileobj(source, output)
    return True


def iter_archive_elfs(archive: Path, temporary: Path) -> Iterator[tuple[str, Path]]:
    """Materialize ELF archive members under generated, traversal-safe names."""
    if archive.name.endswith((".whl", ".zip")):
        with zipfile.ZipFile(archive) as package:
            for index, member in enumerate(package.infolist()):
                if member.is_dir():
                    continue
                destination = temporary / f"zip-{index}"
                with package.open(member) as source:
                    if copy_if_elf(source, destination):
                        yield f"{archive}!{member.filename}", destination
        return

    with tarfile.open(archive, mode="r:*") as package:
        for index, member in enumerate(package):
            if not member.isfile():
                continue
            source = package.extractfile(member)
            if source is None:
                continue
            destination = temporary / f"tar-{index}"
            with source:
                if copy_if_elf(source, destination):
                    yield f"{archive}!{member.name}", destination


def read_glibc_versions(path: Path, readelf: str) -> set[tuple[int, ...]]:
    result = subprocess.run(
        [readelf, "--version-info", "--wide", str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    return parse_glibc_versions(result.stdout)


def main() -> None:
    args = parse_args()
    try:
        maximum = parse_version(args.max_version)
    except ValueError as error:
        raise SystemExit(str(error)) from error

    if args.installer is not None:
        try:
            installer = args.installer.read_text()
            validate_installer_baseline(installer, maximum)
        except (OSError, ValueError) as error:
            raise SystemExit(str(error)) from error

    readelf = shutil.which("readelf")
    if readelf is None:
        raise SystemExit("readelf is required to validate Linux glibc compatibility")

    inspected = 0
    failures: list[str] = []
    with tempfile.TemporaryDirectory(
        prefix="microsandbox-glibc-"
    ) as temporary_directory:
        temporary = Path(temporary_directory)
        for artifact in iter_files(args.paths):
            candidates: Iterator[tuple[str, Path]]
            if artifact.name.endswith(ARCHIVE_SUFFIXES):
                candidates = iter_archive_elfs(artifact, temporary)
            elif is_elf(artifact):
                candidates = iter(((str(artifact), artifact),))
            else:
                continue

            for label, candidate in candidates:
                inspected += 1
                versions = read_glibc_versions(candidate, readelf)
                incompatible = sorted(
                    (
                        version
                        for version in versions
                        if version_key(version) > version_key(maximum)
                    ),
                    key=version_key,
                )
                if incompatible:
                    rendered = ", ".join(
                        f"GLIBC_{'.'.join(map(str, version))}"
                        for version in incompatible
                    )
                    failures.append(f"{label}: requires {rendered}")

    if inspected == 0:
        raise SystemExit("no ELF artifacts found in the supplied paths")
    if failures:
        raise SystemExit(
            f"Linux artifacts exceed the GLIBC_{args.max_version} baseline:\n- "
            + "\n- ".join(failures)
        )
    print(f"validated {inspected} ELF artifacts against GLIBC_{args.max_version}")


if __name__ == "__main__":
    main()
