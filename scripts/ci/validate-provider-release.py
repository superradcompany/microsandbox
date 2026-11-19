#!/usr/bin/env python3
"""Fail release promotion unless every selected provider artifact is present and intact."""
import argparse
import hashlib
import json
from pathlib import Path

TARGETS = {
 "aarch64-apple-darwin": ("darwin-aarch64", "darwin-arm64"),
 "x86_64-unknown-linux-gnu": ("linux-x86_64", "linux-x64-gnu"),
 "aarch64-unknown-linux-gnu": ("linux-aarch64", "linux-arm64-gnu"),
 "x86_64-pc-windows-msvc": ("windows-x86_64", "win32-x64-msvc"),
 "aarch64-pc-windows-msvc": ("windows-aarch64", "win32-arm64-msvc"),
}


def validate(node, go, version):
 errors=[]
 for triple,(release,platform) in TARGETS.items():
  for sdk,root in (("go",go/f"go-providers-{release}"),("node",node/f"node-providers-{platform}")):
   manifest=root/"native-manifest.json"
   if not manifest.is_file(): errors.append(f"missing manifest: {manifest}");continue
   entries=json.loads(manifest.read_text())["artifacts"]
   for kind in ("local","remote"):
    matches=[row for row in entries if row["sdk"]==sdk and row["provider"]==kind and row["target"]==triple]
    if len(matches)!=1: errors.append(f"missing or duplicate {sdk}/{kind}/{triple}");continue
    row=matches[0]
    if row["version"]!=version or row["profile"]!="release": errors.append(f"wrong version/profile: {sdk}/{kind}/{triple}")
    artifact=root/row["file"] if sdk=="go" else root/"npm"/f"{kind}-{platform}"/f"microsandbox-{kind}.node"
    if not artifact.is_file(): errors.append(f"missing artifact: {artifact}");continue
    if artifact.stat().st_size!=row["bytes"] or hashlib.sha256(artifact.read_bytes()).hexdigest()!=row["sha256"]: errors.append(f"artifact integrity mismatch: {artifact}")
   if sdk=="node":
    for package in ("core","local","remote","full",f"local-{platform}",f"remote-{platform}"):
     directory=root/"npm"/package
     try: metadata=json.loads((directory/"package.json").read_text())
     except (OSError,ValueError): errors.append(f"invalid package: {directory}");continue
     if metadata["version"]!=version: errors.append(f"wrong package version: {directory}")
     if package!="full" and any(file.name in ("msb","msb.exe") or "libkrunfw" in file.name for file in directory.rglob("*")): errors.append(f"runtime in lean package: {directory}")
 if errors: raise SystemExit("provider release is incomplete:\n- "+"\n- ".join(errors))


if __name__=="__main__":
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument("--node",type=Path,required=True)
 parser.add_argument("--go",type=Path,required=True)
 parser.add_argument("--version",required=True)
 args=parser.parse_args()
 validate(args.node,args.go,args.version)
 print("All local/remote Node and Go provider artifacts verified")
