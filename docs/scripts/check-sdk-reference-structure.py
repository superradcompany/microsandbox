#!/usr/bin/env python3
"""Check the shared hierarchy conventions for SDK reference pages."""

from __future__ import annotations

import re
import sys
from pathlib import Path


DOCS_DIR = Path(__file__).resolve().parents[1]
SDK_DIR = DOCS_DIR / "sdk"
SDK_NAMES = ("rust", "typescript", "python", "go")
HEADING_RE = re.compile(r"^(#{2,4})\s+(.+)$", re.MULTILINE)
HTML_RE = re.compile(r"<[^>]+>")
METHOD_TABLE_RE = re.compile(r"^\|\s*(?:Method|Factory|Property\s*/\s*Method)\s*\|", re.MULTILINE)
GENERIC_ROOTS = {
    "attach",
    "boot from a snapshot",
    "cache management",
    "capture and boot",
    "constructors",
    "explicit local variants",
    "instance properties",
    "inspect",
    "manage artifacts",
    "methods",
    "mount factories",
    "move artifacts",
    "run and collect",
    "source factory",
    "stream",
    "stream and attach",
    "take a snapshot",
}


def heading_name(raw: str) -> str:
    """Return the visible text used to compare heading names."""

    return HTML_RE.sub("", raw).split("{#", 1)[0].strip()


def check_page(path: Path) -> list[str]:
    """Return hierarchy errors for one SDK reference page."""

    text = path.read_text()
    headings = [
        (len(match.group(1)), heading_name(match.group(2)), match.start())
        for match in HEADING_RE.finditer(text)
    ]
    roots = [(name, offset) for level, name, offset in headings if level == 2]
    errors: list[str] = []

    seen: set[str] = set()
    for name, _ in roots:
        normalized = name.casefold()
        if normalized in seen:
            errors.append(f'duplicate root section "{name}"')
        seen.add(normalized)

        if normalized in GENERIC_ROOTS or normalized.endswith(" methods"):
            errors.append(f'generic root section "{name}"; use the owning type instead')

    types_roots = [(index, offset) for index, (name, offset) in enumerate(roots) if name == "Types"]
    if not types_roots:
        return errors

    types_index, types_offset = types_roots[0]
    if types_index != len(roots) - 1:
        errors.append('"Types" must be the final root section')

    types_body = text[types_offset:]
    if re.search(r"^####\s+", types_body, re.MULTILINE):
        errors.append('"Types" contains callable member headings')
    if METHOD_TABLE_RE.search(types_body):
        errors.append('"Types" contains a method or factory table')

    type_names = {
        name.casefold()
        for level, name, offset in headings
        if level == 3 and offset > types_offset
    }
    duplicated_types = sorted(type_names & seen)
    for name in duplicated_types:
        errors.append(f'root type "{name}" is duplicated under "Types"')

    return errors


def main() -> int:
    """Check every SDK reference page and print actionable failures."""

    failures: list[str] = []
    pages = [
        path
        for sdk_name in SDK_NAMES
        for path in sorted((SDK_DIR / sdk_name).glob("*.mdx"))
    ]

    for path in pages:
        for error in check_page(path):
            failures.append(f"{path.relative_to(DOCS_DIR)}: {error}")

    if failures:
        print("SDK reference structure check failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"SDK reference structure check passed ({len(pages)} pages).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
