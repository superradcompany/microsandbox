#!/usr/bin/env python3
"""Prepare isolated candidate/released SDKs without rebuilding old native bindings."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib

from baseline import GO_FFI, sha256


def run(command, cwd, env=None):
    subprocess.run([str(item) for item in command], cwd=cwd, env=env, check=True, timeout=1800)


def copy_tree(source, destination):
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns(
        "target", "node_modules", ".venv", "__pycache__", ".git"))


def prepare(args):
    source = args.workspace.resolve(strict=True)
    baseline = args.baseline.resolve(strict=True)
    artifacts = args.artifacts.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    release = json.loads((baseline / "baseline.json").read_text())
    candidate_version = tomllib.loads((source / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    candidate_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    manifest = dict(language=args.language, candidate_commit=candidate_sha, baseline=release, sdks={})
    for generation, version in (("candidate", candidate_version), ("released", release["version"])):
        if args.language == "ruby" and generation == "released" and not release["ruby_released"]:
            manifest["unavailable"] = "No modern Ruby SDK has been published; reverse Ruby coverage is unavailable."
            continue
        sdk = output / generation
        sdk.mkdir()
        record = dict(version=version, generation=generation)
        if args.language == "python":
            if generation == "candidate":
                wheels = list((artifacts / "python").glob("*.whl"))
                if len(wheels) != 1:
                    raise ValueError("expected one candidate wheel")
                shutil.copy2(wheels[0], sdk / wheels[0].name)
            else:
                run([sys.executable, "-m", "pip", "download", "--only-binary=:all:", "--no-deps",
                     "--dest", sdk, f"microsandbox=={version}"], sdk)
            record["wheel"] = next(sdk.glob("*.whl")).name
        elif args.language == "node":
            app = sdk / "app"
            app.mkdir()
            if generation == "candidate":
                # Use the native and JS payloads produced by this exact CI run.
                # Do not publish/install a fake platform package into an old SDK.
                package = app / "node_modules/microsandbox"
                copy_tree(source / "sdk/node-ts", package)
                types = app / "node_modules/@microsandbox/types"
                copy_tree(source / "packages/microsandbox-types/typescript", types)
                native = package / "native/microsandbox.linux-x64-gnu.node"
                if not native.is_file() or not (package / "dist/index.js").is_file():
                    raise ValueError("candidate Node build artifacts are missing")
            else:
                (app / "package.json").write_text(json.dumps({"private": True, "dependencies": {
                    "microsandbox": version}}) + "\n")
                run(["npm", "install", "--ignore-scripts", "--omit=dev"], app)
                native = app / "node_modules/@superradcompany/microsandbox-linux-x64-gnu/microsandbox.linux-x64-gnu.node"
            shutil.copy2(source / "scripts/compatibility/scenarios/node.cjs", app / "scenario.cjs")
            record["native_hash"] = sha256(native)
        elif args.language == "go":
            app = sdk / "app"
            app.mkdir()
            shutil.copy2(source / "scripts/compatibility/scenarios/go/main.go", app / "main.go")
            module = "github.com/superradcompany/microsandbox/sdk/go"
            mod = f"module compatibility-fixture\n\ngo 1.24\n\nrequire {module} v{version}\n"
            if generation == "candidate":
                mod += f"\nreplace {module} => {source / 'sdk/go'}\n"
            (app / "go.mod").write_text(mod)
            ffi = sdk / "libmicrosandbox_go_ffi.so"
            shutil.copy2(artifacts / "go/libmicrosandbox_go_ffi.so" if generation == "candidate"
                         else baseline / GO_FFI, ffi)
            env = dict(os.environ, CGO_ENABLED="1", GOWORK="off", MICROSANDBOX_FFI_PATH=str(ffi))
            run(["go", "mod", "tidy"], app, env)
            run(["go", "build", "-tags", "microsandbox_ffi_path", "-o", sdk / "scenario", "."], app, env)
            # Keep dependency provenance, not the candidate's absolute replace path.
            metadata = subprocess.check_output(["go", "list", "-m", "-json", module], cwd=app, env=env, text=True)
            (sdk / "dependency.json").write_text(metadata)
            resolved = json.loads(metadata)
            if generation == "released" and (resolved.get("Version") != f"v{version}" or "Replace" in resolved):
                raise ValueError("released Go module was replaced or resolved to another version")
            if generation == "candidate" and Path(resolved.get("Replace", {}).get("Dir", "")).resolve() != source / "sdk/go":
                raise ValueError("candidate Go module did not use this checkout")
            record["native_hash"] = sha256(ffi)
        elif args.language == "rust":
            app = sdk / "app"
            copy_tree(source / "scripts/compatibility/scenarios/rust", app)
            manifest_path = app / "Cargo.toml"
            template = manifest_path.read_text()
            # The fixture template carries a marker dependency for substitution.
            dependency = f'path = "{source / "sdk/rust"}"' if generation == "candidate" else f'version = "={version}"'
            template, replaced = re.subn(r'microsandbox = \{[^\n]+\}',
                f'microsandbox = {{ {dependency}, default-features = false, features = ["local", "net"] }}', template)
            if replaced != 1:
                raise ValueError("fixture must declare one microsandbox dependency")
            manifest_path.write_text(template)
            env = dict(os.environ, CARGO_TARGET_DIR=str(output / "rust-target"))
            if generation == "candidate":
                shutil.copy2(source / "Cargo.lock", app / "Cargo.lock")
            run(["cargo", "build", "--release", "--manifest-path", manifest_path], app, env)
            metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--format-version", "1",
                "--locked", "--filter-platform", "x86_64-unknown-linux-gnu", "--manifest-path", str(manifest_path)], cwd=app, env=env, text=True))
            core = [package for package in metadata["packages"] if package["name"] == "microsandbox"]
            if len(core) != 1 or core[0]["version"] != version:
                raise ValueError("Rust fixture resolved the wrong SDK version")
            if generation == "released" and not (core[0]["source"] or "").startswith("registry+"):
                raise ValueError("released Rust SDK must come from the registry")
            if generation == "candidate" and Path(core[0]["manifest_path"]).resolve() != source / "sdk/rust/Cargo.toml":
                raise ValueError("candidate Rust SDK did not use this checkout")
            if generation == "released" and any(package["name"].startswith("microsandbox")
                    and not (package["source"] or "").startswith("registry+") for package in metadata["packages"]):
                raise ValueError("released SDK graph contains a substituted microsandbox crate")
            (sdk / "dependency.json").write_text(json.dumps(core[0], indent=2) + "\n")
            binary_name = tomllib.loads(template)["package"]["name"]
            shutil.copy2(output / "rust-target/release" / binary_name, sdk / "scenario")
        elif args.language == "ruby":
            if generation == "candidate":
                # This patch is confined to this build checkout and never applied
                # to a released gem or its extension dependency graph.
                try:
                    run(["rake", "version_check", "cargo:patch_workspace", "gem:stage"], source / "sdk/ruby")
                    abi = subprocess.check_output(["ruby", "-e", r'print RUBY_VERSION[/\d+\.\d+/]'], text=True)
                    env = dict(os.environ, GEM_PLATFORM="x86_64-linux-gnu", RUBY_ABIS=abi)
                    # This is a private test artifact for the runner's one Ruby
                    # ABI, never a release gem or a claim about other Rubies.
                    run(["rake", "gem:platform"], source / "sdk/ruby", env)
                    gems = list((source / "sdk/ruby/pkg").glob("*.gem"))
                    if len(gems) != 1:
                        raise ValueError("expected one candidate Ruby gem")
                    shutil.copy2(gems[0], sdk / gems[0].name)
                    native = source / f"sdk/ruby/lib/microsandbox/{abi}/microsandbox.so"
                    record["native_hash"] = sha256(native)
                finally:
                    run(["rake", "cargo:unpatch_workspace"], source / "sdk/ruby")
            else:
                run(["gem", "fetch", "microsandbox", "--version", version,
                     "--platform", "x86_64-linux-gnu"], sdk)
        else:
            raise ValueError(f"unknown language: {args.language}")
        # Store hashes for provenance across build and VM runners. Large build
        # target directories are deliberately not included in the upload.
        record["files"] = {str(path.relative_to(sdk)): sha256(path) for path in sdk.rglob("*")
                           if path.is_file()}
        manifest["sdks"][generation] = record
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("workspace", "baseline", "artifacts", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--language", choices=["rust", "python", "node", "go", "ruby"], required=True)
    prepare(parser.parse_args())
