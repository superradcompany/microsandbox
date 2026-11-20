#!/usr/bin/env python3
"""Assemble provider packages from a build-sdk-providers manifest; never publish."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
TARGETS = {
 # Match the release workflow deployment floor; a lower wheel tag would let
 # pip install libraries on macOS versions they cannot support.
 "aarch64-apple-darwin": ("darwin-arm64", "macosx_14_0_arm64"),
 "x86_64-unknown-linux-gnu": ("linux-x64-gnu", "linux_x86_64"),
 "aarch64-unknown-linux-gnu": ("linux-arm64-gnu", "linux_aarch64"),
 "x86_64-pc-windows-msvc": ("win32-x64-msvc", "win_amd64"),
 "aarch64-pc-windows-msvc": ("win32-arm64-msvc", "win_arm64"),
}


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument("--manifest",type=Path,required=True)
 parser.add_argument("--out",type=Path,required=True)
 parser.add_argument("--runtime",type=Path,help="Complete bin/lib tree, required to stage the full Python wheel")
 parser.add_argument("--sdks",nargs="+",default=["node","python","go"],choices=["node","python","go"])
 args=parser.parse_args()
 manifest=args.manifest.resolve()
 artifacts=json.loads(manifest.read_text())["artifacts"]
 targets={item["target"] for item in artifacts}
 if len(targets)!=1: raise SystemExit("stage each target independently")
 target=targets.pop()
 node_target, wheel_target=TARGETS[target]
 out=args.out.resolve()
 for sdk in args.sdks:
  selected={entry["provider"]:manifest.parent/entry["file"] for entry in artifacts if entry["sdk"]==sdk}
  if sdk!="go" and not {"local","remote"}<=selected.keys(): raise SystemExit(f"missing {sdk} provider artifact")
  if sdk=="node":
   command=["node",str(ROOT/"sdk/node-ts/scripts/stage-distribution.mjs"),"--out",str(out/"npm"),"--target",node_target,
     "--local-binding",str(selected["local"]),"--remote-binding",str(selected["remote"]),"--full"]
  elif sdk=="python":
   command=[sys.executable,str(ROOT/"sdk/python/scripts/stage_distributions.py"),"--out",str(out/"wheels"),"--platform",wheel_target,
     "--local-binding",str(selected["local"]),"--remote-binding",str(selected["remote"])]
   if args.runtime:
    if "full" not in selected: raise SystemExit("full Python artifact is required with runtime")
    command += ["--full-binding",str(selected["full"]),"--full-runtime-dir",str(args.runtime.resolve())]
  else:
   command=[sys.executable,str(ROOT/"sdk/go/scripts/stage-distributions.py"),"--out",str(out/"go"),"--full"]
  subprocess.run(command,cwd=ROOT,check=True)
 out.mkdir(parents=True, exist_ok=True)
 (out / "native-manifest.json").write_bytes(manifest.read_bytes())
 # Linux wheels deliberately carry a linux_* staging tag. auditwheel repair must
 # validate/bundle dependencies before a release process can label them manylinux.
 print(out)


if __name__=="__main__": main()
