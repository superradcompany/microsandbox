"""Give a repaired full wheel shared core wrappers without relinking its native payload."""

import argparse
import base64
import csv
import hashlib
import io
import zipfile
from pathlib import Path

from stage_distributions import VERSION, full_wrapper_files


def rewrite(path):
    with zipfile.ZipFile(path) as archive:
        entries = {
            entry.filename: (entry, archive.read(entry.filename)) for entry in archive.infolist()
        }
    for name in list(entries):
        if (
            name.startswith("microsandbox/")
            and name.count("/") == 1
            and (name.endswith((".py", ".pyi")) or name.endswith("py.typed"))
        ):
            del entries[name]
    for name, content in full_wrapper_files().items():
        entry = zipfile.ZipInfo(name)
        entry.external_attr = 0o100644 << 16
        entries[name] = entry, content
    metadata = next(name for name in entries if name.endswith(".dist-info/METADATA"))
    entry, content = entries[metadata]
    text = content.decode()
    header, separator, body = text.partition("\n\n")
    dependency = f"Requires-Dist: microsandbox-core=={VERSION}"
    if dependency not in header:
        header += "\n" + dependency
    entries[metadata] = entry, (header + separator + body).encode()
    record_name = next(name for name in entries if name.endswith(".dist-info/RECORD"))
    record = io.StringIO(newline="")
    writer = csv.writer(record)
    for name, (_, content) in sorted(entries.items()):
        if name == record_name:
            continue
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        writer.writerow((name, "sha256=" + digest, len(content)))
    writer.writerow((record_name, "", ""))
    entries[record_name] = entries[record_name][0], record.getvalue().encode()
    temporary = path.with_suffix(".rewritten")
    with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as archive:
        for _name, (entry, content) in sorted(entries.items()):
            archive.writestr(entry, content, compress_type=zipfile.ZIP_DEFLATED)
    temporary.replace(path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheels", type=Path)
    args = parser.parse_args()
    wheels = list(args.wheels.glob("microsandbox-*.whl"))
    if not wheels:
        raise SystemExit("no full wheel to reconcile")
    for wheel in wheels:
        rewrite(wheel)
        print(wheel)
