#!/usr/bin/env python3
"""Build independently selected release native providers and record measured bytes.

The manifest's gzip sizes are standalone reproducible comparisons, not registry
transfer sizes. Packaging checks measure actual package archives separately.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--profile", default="release")
    parser.add_argument("--target")
    parser.add_argument("--sdks", nargs="+", default=["go", "node", "python"], choices=["go", "node", "python"])
    parser.add_argument("--providers", nargs="+", default=["remote", "local", "full"], choices=["local", "remote", "full"])
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    host = subprocess.check_output(["rustc", "-vV"], text=True).split("host: ")[1].splitlines()[0]
    target = args.target or host
    windows = "windows" in target
    darwin = "apple" in target
    extension = ".dll" if windows else ".dylib" if darwin else ".so"
    prefix = "" if windows else "lib"
    cargo_target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
    if not cargo_target.is_absolute():
        cargo_target = ROOT / cargo_target
    artifact_dir = cargo_target / (args.target or "") / ("debug" if args.profile == "dev" else args.profile)
    entries = []
    manifest = out / "native-manifest.json"
    if manifest.exists():
        entries = json.loads(manifest.read_text())["artifacts"]
    version = json.loads(subprocess.check_output(["cargo", "metadata", "--no-deps", "--format-version", "1"], cwd=ROOT, text=True))["packages"][0]["version"]
    for kind in args.providers:
        for sdk, crate, library in [("go", "microsandbox-go", "microsandbox_go_ffi"), ("node", "microsandbox-node", "microsandbox_node"), ("python", "microsandbox-py", "_microsandbox")]:
            if sdk not in args.sdks:
                continue
            features = [kind]
            if sdk == "python":
                features += ["pyo3/extension-module"]
                if kind != "full":
                    features += ["provider-package"]
            command = ["cargo", "rustc", "--locked", "-p", crate, "--profile", args.profile, "--no-default-features", "--features", ",".join(features), "--crate-type", "cdylib"]
            if args.target:
                command += ["--target", args.target]
            # macOS Python extensions resolve CPython symbols from the host interpreter.
            if sdk == "python" and darwin:
                command += ["--", "-C", "link-arg=-Wl,-undefined,dynamic_lookup"]
            print(" ".join(command), flush=True)
            subprocess.run(command, cwd=ROOT, check=True)
            source = artifact_dir / f"{prefix}{library}{extension}"
            suffix = ".node" if sdk == "node" else ".pyd" if sdk == "python" and windows else extension
            destination = out / f"microsandbox-{sdk}-{kind}-{target}{suffix}"
            shutil.copy2(source, destination)
            raw = destination.read_bytes()
            # Use deterministic timestamps so measurements are repeatable.
            compressed = gzip.compress(raw, compresslevel=9, mtime=0)
            entry = dict(sdk=sdk, provider=kind, target=target, version=version, profile=args.profile, file=destination.name, bytes=len(raw), gzip_bytes=len(compressed), sha256=hashlib.sha256(raw).hexdigest())
            entries = [old for old in entries if (old["sdk"], old["provider"], old["target"]) != (sdk, kind, target)] + [entry]
            manifest.write_text(json.dumps({"schema":1, "artifacts":entries}, indent=2) + "\n")
            print(json.dumps(entry), flush=True)


if __name__ == "__main__":
    main()
