#!/usr/bin/env python3
"""Build lean wheels inside the platform's existing native build environment."""
import argparse
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--target")
    parser.add_argument("--manylinux", help="auditwheel target, e.g. manylinux_2_28_x86_64")
    args = parser.parse_args()
    out = args.out.resolve()
    with tempfile.TemporaryDirectory(prefix="msb-python-providers-") as temp:
        temp = Path(temp)
        native = temp / "native"
        command = [sys.executable, str(ROOT / "scripts/ci/build-sdk-providers.py"), "--out", str(native), "--sdks", "python", "--providers", "local", "remote"]
        if args.target:
            command += ["--target", args.target]
        subprocess.run(command, check=True)
        staged = temp / "staged"
        subprocess.run([sys.executable, str(ROOT / "scripts/ci/stage-sdk-providers.py"), "--manifest", str(native / "native-manifest.json"), "--out", str(staged), "--sdks", "python"], check=True)
        out.mkdir(parents=True, exist_ok=True)
        for wheel in (staged / "wheels").glob("*.whl"):
            if args.manylinux and not wheel.name.endswith("-any.whl"):
                subprocess.run(["auditwheel", "repair", "--plat", args.manylinux, "--wheel-dir", str(out), str(wheel)], check=True)
            else:
                import shutil
                shutil.copy2(wheel, out / wheel.name)
        (out / "native-manifest.json").write_bytes((native / "native-manifest.json").read_bytes())


if __name__ == "__main__":
    main()
