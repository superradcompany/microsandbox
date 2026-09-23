#!/usr/bin/env python3
"""Check that generic documentation presents TypeScript before Rust."""

import json
import re
import sys
from pathlib import Path
from typing import List, Optional, Tuple


REPO = Path(__file__).resolve().parent.parent
DOCS = REPO / "docs"
CODE_GROUP = re.compile(r"<CodeGroup>(.*?)</CodeGroup>", re.DOTALL)
CODE_FENCE = re.compile(r"^\s*```(\S+)(?:\s+([^\n]+))?", re.MULTILINE)
EXCLUDED_PREFIXES = (
    Path("changelog"),
    Path("sdk/rust"),
    Path("sdk/typescript"),
    Path("sdk/python"),
    Path("sdk/go"),
)


def language(lexer: str, label: Optional[str]) -> Optional[str]:
    """Return the SDK language represented by a labeled code fence."""

    clean_label = label.strip() if label else ""
    if lexer == "typescript" or clean_label == "TypeScript":
        return "typescript"
    if lexer == "rust" or clean_label == "Rust":
        return "rust"
    return None


def check_code_groups() -> Tuple[List[str], int]:
    """Find generic code groups that put Rust before TypeScript."""

    failures = []
    checked = 0
    for path in sorted(DOCS.rglob("*.mdx")):
        relative = path.relative_to(DOCS)
        if any(
            relative.parts[: len(prefix.parts)] == prefix.parts
            for prefix in EXCLUDED_PREFIXES
        ):
            continue

        text = path.read_text()
        for group in CODE_GROUP.finditer(text):
            languages = [
                detected
                for fence in CODE_FENCE.finditer(group.group(1))
                if (detected := language(fence.group(1), fence.group(2))) is not None
            ]
            if "typescript" not in languages or "rust" not in languages:
                continue

            checked += 1
            if languages.index("rust") < languages.index("typescript"):
                line = text.count("\n", 0, group.start()) + 1
                failures.append(f"{relative}:{line}: place TypeScript before Rust")

    return failures, checked


def check_navigation() -> List[str]:
    """Verify that the TypeScript SDK is the first SDK navigation group."""

    config = json.loads((DOCS / "docs.json").read_text())
    sdk_tab = next(tab for tab in config["navigation"]["tabs"] if tab["tab"] == "SDKs & CLI")
    sdk_group = next(group for group in sdk_tab["groups"] if group["group"] == "SDKs")
    first_sdk = sdk_group["pages"][0]["group"]
    if first_sdk == "TypeScript":
        return []
    return [f"docs.json: SDK navigation starts with {first_sdk}, expected TypeScript"]


def main() -> int:
    """Run all TypeScript-first documentation checks."""

    failures, checked = check_code_groups()
    failures.extend(check_navigation())
    if failures:
        for failure in failures:
            print(f"error: {failure}", file=sys.stderr)
        return 1

    print(f"checked {checked} multilingual code groups and SDK navigation")
    return 0


if __name__ == "__main__":
    sys.exit(main())
