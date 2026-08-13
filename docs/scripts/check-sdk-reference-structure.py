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


def visible_text(raw: str) -> str:
    """Strip the lightweight Markdown used inside reference table cells."""

    raw = re.sub(r"\[([^]]+)\]\([^)]*\)", r"\1", raw)
    raw = re.sub(r"</?(?:a|span|code|div|p)(?:\s[^>]*)?>", "", raw)
    return raw.replace("`", "").strip()


def split_table_row(line: str) -> list[str]:
    """Split a Markdown table row without treating escaped pipes as cells."""

    line = line.strip().removeprefix("|").removesuffix("|")
    cells: list[str] = []
    current: list[str] = []
    escaped = False

    for char in line:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == "|":
            cells.append("".join(current).strip())
            current = []
        else:
            current.append(char)

    cells.append("".join(current).strip())
    return cells


def callable_names(raw: str) -> list[str]:
    """Return callable identifiers from a table cell or member heading."""

    rendered = visible_text(raw)
    names = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)(?:<[^>]+>)?\s*\(", rendered)
    if names:
        return names
    if "/" in rendered:
        return re.findall(r"\b(__[A-Za-z0-9_]+__)\b", rendered)
    return []


def check_callable_tables(section_name: str, body: str) -> list[str]:
    """Require every callable summary row to have a member heading."""

    documented = {
        name
        for match in re.finditer(r"^####\s+(.+)$", body, re.MULTILINE)
        for name in callable_names(match.group(1))
    }
    errors: list[str] = []
    tables = re.findall(r"(?:^\|.*\|\n)+", body, re.MULTILINE)

    for table in tables:
        rows = table.splitlines()
        if len(rows) < 3 or not re.search(r"\b(Method|Member|Factory)\b", rows[0], re.IGNORECASE):
            continue

        headers = [visible_text(cell).casefold() for cell in split_table_row(rows[0])]
        method_column = next(
            (
                index
                for index, value in enumerate(headers)
                if value in {"method", "member", "property / method", "factory"}
            ),
            0,
        )

        for row in rows[2:]:
            cells = split_table_row(row)
            if method_column >= len(cells):
                continue
            for name in callable_names(cells[method_column]):
                if name not in documented:
                    errors.append(f'"{section_name}" documents {name}() only in a table')

    return errors


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

    for index, (name, offset) in enumerate(roots):
        end = roots[index + 1][1] if index + 1 < len(roots) else len(text)
        errors.extend(check_callable_tables(name, text[offset:end]))

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
