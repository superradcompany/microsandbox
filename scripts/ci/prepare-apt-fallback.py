#!/usr/bin/env python3
"""Copy APT sources with independent Ubuntu mirrors, leaving trust unchanged."""

import re
import sys
from pathlib import Path
from urllib.parse import urlsplit


MIRRORS = {
    "amd64": "https://mirrors.edge.kernel.org/ubuntu/",
    "amd64v3": "https://mirrors.edge.kernel.org/ubuntu/",
    "arm64": "https://mirrors.mit.edu/ubuntu-ports/",
}


def ubuntu_uri(uri):
    parsed = urlsplit(uri)
    # GitHub's x86_64 image uses a local list of Canonical mirrors. Do not
    # reinterpret arbitrary local mirror lists or third-party repositories.
    if uri in ("mirror+file:/etc/apt/apt-mirrors.txt",
               "mirror+file:/etc/apt/apt-mirrors-security.txt"):
        return True
    if parsed.scheme not in ("http", "https") or parsed.query or parsed.fragment:
        return False
    host = parsed.hostname or ""
    if parsed.path.rstrip("/") == "/ubuntu":
        return (host == "archive.ubuntu.com" or host.endswith(".archive.ubuntu.com")
                or host == "security.ubuntu.com")
    return host == "ports.ubuntu.com" and parsed.path.rstrip("/") == "/ubuntu-ports"


def rewrite_sources(text, deb822, mirror):
    """Only rewrite URI values; preserve suites, components and every option."""
    replacements = 0

    def replace(match):
        nonlocal replacements
        if ubuntu_uri(match.group()):
            replacements += 1
            return mirror
        return match.group()

    lines = []
    in_uris = False
    for line in text.splitlines(keepends=True):
        if deb822:
            if line.lower().startswith("uris:"):
                in_uris = True
                line = line[:5] + re.sub(r"\S+", replace, line[5:])
            elif in_uris and line[:1].isspace() and line.strip():
                line = re.sub(r"\S+", replace, line)
            elif not line.startswith("#"):
                in_uris = False
        else:
            entry = re.match(r"(\s*deb(?:-src)?\s+(?:\[[^\]\n]*\]\s+)?)(\S+)(.*)",
                             line, re.DOTALL)
            if entry:
                line = entry[1] + re.sub(r"\S+", replace, entry[2]) + entry[3]
        lines.append(line)
    return "".join(lines), replacements


def prepare_sources(source_dir, destination, architecture):
    if architecture not in MIRRORS:
        raise ValueError(f"No Ubuntu fallback configured for {architecture}")
    mirror = MIRRORS[architecture]
    parts = destination / "sources.list.d"
    parts.mkdir(mode=0o755)
    (destination / "lists").mkdir(mode=0o755)
    files = [source_dir / "sources.list"]
    files += sorted((source_dir / "sources.list.d").glob("*.list"))
    files += sorted((source_dir / "sources.list.d").glob("*.sources"))
    replacements = 0
    for source in files:
        if not source.is_file():
            continue
        text, count = rewrite_sources(source.read_text(), source.suffix == ".sources", mirror)
        replacements += count
        target = destination / "sources.list" if source == files[0] else parts / source.name
        target.write_text(text)
        target.chmod(0o644)
    # An empty primary file avoids falling back to the system's sources.list.
    (destination / "sources.list").touch(mode=0o644, exist_ok=True)
    if not replacements:
        raise ValueError("No recognized Ubuntu sources to replace; keeping system sources unchanged")
    print(f"::warning::Using Ubuntu fallback mirror {mirror}", flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: prepare-apt-fallback.py <temporary-directory> <architecture>")
    try:
        prepare_sources(Path("/etc/apt"), Path(sys.argv[1]), sys.argv[2])
    except (OSError, ValueError) as error:
        sys.exit(f"::error::{error}")
