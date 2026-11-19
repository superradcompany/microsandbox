#!/usr/bin/env python3
"""Check that native SDK providers compile without inheriting the full SDK feature set."""

import argparse
import subprocess

PACKAGES = ("microsandbox-node", "microsandbox-py", "microsandbox-go")
LOCAL_IMPLEMENTATION = (
    "microsandbox-runtime ",
    "microsandbox-image ",
    "microsandbox-db ",
    "microsandbox-migration ",
    "msb_krun ",
)


def check(provider: str) -> None:
    selection = ["--no-default-features", "--features", provider]
    for package in PACKAGES:
        command = ["cargo", "tree", "-p", package, *selection,
                   "--edges", "normal", "--prefix", "none", "--format", "{p} {f}"]
        tree = subprocess.check_output(command, text=True)
        core = next(line for line in tree.splitlines() if line.startswith("microsandbox v"))
        features = set(core.rsplit(" ", 1)[-1].split(","))
        required = {"local"} if provider == "local" else {"cloud"}
        forbidden = {"cloud"} if provider == "local" else {"local"}
        forbidden |= {"download-binaries", "embed-binaries"}
        if not required <= features or forbidden & features:
            raise SystemExit(f"{package}/{provider}: unexpected core features: {core}")
        if provider == "remote":
            leaked = [line for line in tree.splitlines() if line.startswith(LOCAL_IMPLEMENTATION)]
            if leaked:
                raise SystemExit(f"{package}/remote links local implementation: {leaked}")
        subprocess.run(["cargo", "check", "-p", package, *selection], check=True)
        print(f"{package}/{provider}: provider isolation verified", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("provider", choices=("local", "remote", "all"), default="all", nargs="?")
    args = parser.parse_args()
    for provider in ("local", "remote") if args.provider == "all" else (args.provider,):
        check(provider)
