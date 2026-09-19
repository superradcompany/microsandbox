"""Verify source fixtures against every pinned historical Git tag, without network I/O."""

import hashlib
import json
from pathlib import Path
import subprocess


def git(repository: Path, *arguments: str) -> str:
    return subprocess.check_output(["git", *arguments], cwd=repository).decode().strip()


def verify() -> None:
    directory = Path(__file__).resolve().parent
    repository = directory.parents[2]
    manifest = json.loads((directory / "manifest.json").read_text())
    fixture = (directory / manifest["records_file"]).read_text()
    # The hash covers the import and exact extracted declarations; the fixture's
    # explanatory comment is intentionally outside the historical record hash.
    fixture_records = fixture[fixture.index("use serde") :]
    for anchor in manifest["versions"]:
        version = anchor["version"]
        source_ref = version + ":" + manifest["source_path"]
        source = git(repository, "show", source_ref)
        start = source.index("/// A control request from the SDK.")
        end = source.index("/// Everything the control listener can reach:")
        records = source[start:end].rstrip()
        start = source.index("impl std::fmt::Debug for SecretValue {")
        end = source.index("\n}\n", start) + 3
        debug = source[start:end].strip()
        extracted = "use serde::{Deserialize, Serialize};\n\n" + records + "\n\n" + debug + "\n"
        checks = {
            "exact record declarations": extracted == fixture_records,
            "record SHA-256": hashlib.sha256(extracted.encode()).hexdigest() == anchor["records_sha256"],
            "tag commit": git(repository, "rev-parse", version + "^{commit}") == anchor["commit"],
            "control source blob": git(repository, "rev-parse", source_ref) == anchor["control_blob"],
        }
        for label, passed in checks.items():
            if not passed:
                raise SystemExit(f"{version}: {label} differs from the pinned fixture")
    print(f"Verified exact declarations, SHA-256, commits, and blobs for {len(manifest['versions'])} tags.")


if __name__ == "__main__":
    verify()
