#!/usr/bin/env python3
"""Run the bidirectional live SDK/runtime matrix in disposable Linux/KVM homes."""

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time

from baseline import sha256


PAIRS = (("candidate", "released"), ("released", "candidate"),
         ("released", "released"), ("candidate", "candidate"))


def environment(home, runtime, firmware, explicit):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("MSB_", "MICROSANDBOX_", "PYTHON", "RUBY", "GEM_"))
           and key not in ("LD_PRELOAD", "NODE_PATH", "NODE_OPTIONS", "NAPI_RS_NATIVE_LIBRARY_PATH")}
    env.update(MSB_HOME=str(home), MSB_BACKEND="local", MSB_CONFIG_PATH=str(home / "config.json"),
               LD_LIBRARY_PATH=str(firmware.parent), NO_COLOR="1")
    env["PATH"] = str(home / "bin") + os.pathsep + env["PATH"]
    if explicit:
        env["MSB_PATH"] = str(runtime)
        env["MSB_LIBKRUNFW_PATH"] = str(firmware)
    return env


def run(command, env, cwd, log, timeout=900):
    """Reap the test process group before attempting fixture VM cleanup."""
    with subprocess.Popen([str(item) for item in command], env=env, cwd=cwd,
                          stdout=log, stderr=subprocess.STDOUT, start_new_session=True) as process:
        try:
            returncode = process.wait(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            raise
    if returncode:
        raise subprocess.CalledProcessError(returncode, command)


def schema(home):
    database = home / "db/msb.db"
    if not database.exists():
        return None
    with closing(sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)) as connection:
        return connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name").fetchall(), \
            connection.execute("SELECT version FROM seaql_migrations ORDER BY version").fetchall()


def cleanup(home, runtimes, env, log):
    errors = []
    for runtime in runtimes:
        clean_env = dict(env, MSB_PATH=str(runtime))
        def msb(*args):
            result = subprocess.run([str(runtime), *args], env=clean_env, cwd=home,
                                    capture_output=True, text=True, timeout=30)
            log.write(result.stdout + result.stderr)
            result.check_returncode()
            return result.stdout
        try:
            inventory = json.loads(msb("list", "--format", "json"))
            for entry in inventory:
                try:
                    if entry["status"] not in ("Stopped", "Crashed"):
                        msb("stop", entry["name"], "--force")
                    msb("rm", entry["name"])
                except Exception as error:
                    errors.append(str(error))
            remaining = json.loads(msb("list", "--format", "json"))
            if not remaining:
                # Recovery is allowed during teardown, never in the scenario.
                return
            errors.append(f"remaining records: {remaining}")
        except Exception as error:
            errors.append(str(error))
    raise RuntimeError(f"fixture cleanup failed for {home}: {errors}")


def installed_sdk(language, payload, record, scripts, setup_log):
    env = dict(os.environ)
    if language == "python":
        venv = payload / "venv"
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
        python = venv / "bin/python"
        run([python, "-m", "pip", "install", "--no-deps", payload / record["wheel"]], env, payload, setup_log)
        native = list(venv.rglob("_microsandbox*.so"))
        if len(native) != 1:
            raise ValueError("expected one Python native extension")
        record["native_hash"] = sha256(native[0])
        return [str(python), str(scripts / "scenarios/python.py")], {}, payload
    if language == "node":
        return ["node", str(payload / "app/scenario.cjs")], {}, payload / "app"
    if language == "go":
        (payload / "scenario").chmod(0o700)
        return [str(payload / "scenario")], {"MICROSANDBOX_FFI_PATH": str(payload / "libmicrosandbox_go_ffi.so")}, payload
    if language == "rust":
        (payload / "scenario").chmod(0o700)
        return [str(payload / "scenario")], {}, payload
    if language == "ruby":
        gems = list(payload.glob("*.gem"))
        if len(gems) != 1:
            raise ValueError("expected one Ruby gem")
        gem_home = payload / "gems"
        env.update(GEM_HOME=str(gem_home), GEM_PATH=str(gem_home))
        run(["gem", "install", "--local", "--no-document", gems[0]], env, payload, setup_log)
        return ["ruby", str(scripts / "scenarios/ruby.rb")], {"GEM_HOME": str(gem_home), "GEM_PATH": str(gem_home)}, payload
    raise ValueError(language)


def validate_report(report, evidence, expected_hash=None):
    cases = report.get("cases", report.get("passed", []))
    if report.get("status") != "passed" or not isinstance(cases, list) or not cases:
        raise ValueError("scenario did not report successful nonempty coverage")
    if "cases" in report:
        if any(not isinstance(case, dict) or case.get("status") != "passed"
               or not case.get("checks") for case in cases):
            raise ValueError("scenario contains incomplete or failed cases")
    elif any(not isinstance(case, str) or not case.strip() for case in cases):
        raise ValueError("scenario contains invalid passed checks")
    if not evidence:
        raise ValueError("scenario never verified a live VM executable")
    for line in evidence:
        entry = json.loads(line)
        if not isinstance(entry, dict) or not entry.get("sandbox") or not entry.get("runtimes"):
            raise ValueError("invalid live runtime evidence")
        for runtime in entry["runtimes"]:
            digest = runtime.get("sha256", "")
            if not isinstance(runtime.get("pid"), int) or runtime["pid"] <= 0 \
                    or not re.fullmatch(r"[0-9a-f]{64}", digest) \
                    or (expected_hash is not None and digest != expected_hash):
                raise ValueError("invalid live runtime identity")


def validate_manifest(manifest):
    required = {"candidate", "released"}
    if manifest["language"] == "ruby" and not manifest["baseline"]["ruby_released"]:
        if not manifest.get("unavailable"):
            raise ValueError("missing released Ruby coverage must be reported explicitly")
        required = {"candidate"}
    if set(manifest["sdks"]) != required:
        raise ValueError("required SDK artifacts are missing or unexpected")
    for record in manifest["sdks"].values():
        if not record.get("files"):
            raise ValueError("SDK artifact inventory is empty")


def execute(args):
    if platform.system() != "Linux" or platform.machine() != "x86_64" or not os.access("/dev/kvm", os.R_OK | os.W_OK):
        raise RuntimeError("this qualification requires accessible Linux x86-64 KVM; it cannot be skipped")
    scripts = Path(__file__).resolve().parent
    payload = args.payload.resolve(strict=True)
    baseline = args.baseline.resolve(strict=True)
    current = args.runtime.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    manifest = json.loads((payload / "manifest.json").read_text())
    validate_manifest(manifest)
    release = json.loads((baseline / "baseline.json").read_text())
    if manifest["candidate_commit"] != args.commit or manifest["baseline"] != release:
        raise ValueError("SDK artifacts do not match this candidate and baseline")
    for name, digest in release["hashes"].items():
        if sha256(baseline / name) != digest:
            raise ValueError(f"baseline artifact changed: {name}")
    firmware = list(current.glob("libkrunfw.so.*.*.*"))
    if len(firmware) != 1:
        raise ValueError("expected one candidate firmware")
    runtimes = {"candidate": (current / "msb", firmware[0]),
                "released": (baseline / "msb", baseline / release["firmware"])}
    for binary, _ in runtimes.values():
        binary.chmod(0o700)
    commands = {}
    for generation, record in manifest["sdks"].items():
        for name, digest in record["files"].items():
            if sha256(payload / generation / name) != digest:
                raise ValueError(f"SDK artifact changed: {generation}/{name}")
        with (output / f"setup-{generation}.log").open("w") as log:
            commands[generation] = installed_sdk(manifest["language"], payload / generation, record, scripts, log)
    results = dict(language=manifest["language"], candidate=args.commit, baseline=release,
                   platform="linux-x86_64-kvm", unavailable=manifest.get("unavailable"), cases=[])
    for sdk, runtime in PAIRS:
        if sdk not in commands:
            if manifest["language"] != "ruby" or release["ruby_released"]:
                raise ValueError(f"required SDK missing: {sdk}")
            continue
        for mode in ("explicit-fresh", "installed-existing"):
            label = f"{sdk}-sdk_{runtime}-msb_{mode}"
            case = dict(case=label, status="running")
            results["cases"].append(case)
            started = time.monotonic()
            root = Path(tempfile.mkdtemp(prefix="msb-compat-", dir="/tmp"))
            home = root / "home"
            home.mkdir()
            (home / "config.json").write_text("{}\n")
            (home / "bin").mkdir()
            (home / "lib").mkdir()
            binary, fw = runtimes[runtime]
            shutil.copy2(binary, home / "bin/msb")
            shutil.copy2(fw, home / "lib" / fw.name)
            # The installed path remains self-contained without borrowing the
            # ambient home or an SDK's bundled firmware/Agentd.
            major = fw.name.split(".")[2]
            (home / "lib" / f"libkrunfw.so.{major}").symlink_to(fw.name)
            (home / "lib/libkrunfw.so").symlink_to(fw.name)
            env = environment(home, binary, home / "lib" / fw.name, mode == "explicit-fresh")
            record = manifest["sdks"][sdk]
            command, sdk_env, cwd = commands[sdk]
            env.update(sdk_env)
            env.update(MSB_COMPAT_REPORT=str(output / f"{label}.json"), MSB_COMPAT_CASE="all",
                       MSB_COMPAT_IMAGE=args.image, MSB_COMPAT_SDK_VERSION=record["version"],
                       MSB_COMPAT_SDK_GENERATION=sdk, MSB_COMPAT_SDK_ROOT=str(payload / sdk),
                       MSB_COMPAT_CLI=str(binary), MSB_COMPAT_PYTHON=sys.executable,
                       MSB_COMPAT_VERIFY_RUNTIME=str(scripts / "verify_runtime.py"),
                       MSB_COMPAT_RUNTIME_SHA256=sha256(binary),
                       MSB_COMPAT_RUNTIME_REPORT=str(output / f"{label}-runtime.jsonl"))
            if record.get("native_hash"):
                env["MSB_COMPAT_NATIVE_SHA256"] = record["native_hash"]
            case.update(home=str(home), sdk=record, runtime_sha256=sha256(binary), firmware_sha256=sha256(fw))
            try:
                with (output / f"{label}.log").open("w") as log:
                    if mode == "installed-existing":
                        # This seeds a released CLI catalog even for a candidate
                        # runtime. Neither SDK direction may implicitly migrate it.
                        seed_env = dict(env, MSB_PATH=str(runtimes["released"][0]))
                        run([runtimes["released"][0], "list", "--format", "json"], seed_env, home, log, 60)
                    before = schema(home)
                    run(command, env, cwd, log)
                    report = json.loads(Path(env["MSB_COMPAT_REPORT"]).read_text())
                    evidence = Path(env["MSB_COMPAT_RUNTIME_REPORT"]).read_text().splitlines()
                    validate_report(report, evidence, env["MSB_COMPAT_RUNTIME_SHA256"])
                    if before is not None and before != schema(home):
                        raise AssertionError("SDK access changed the existing released catalog schema")
                    run([binary, "list", "--format", "json"], env, home, log, 60)
                case["status"] = "passed"
            except Exception as error:
                case.update(status="failed", error=repr(error))
            finally:
                try:
                    with (output / f"{label}-cleanup.log").open("w") as log:
                        cleanup(home, [binary, runtimes["candidate"][0]], env, log)
                except Exception as error:
                    case["cleanup_error"] = repr(error)
                    case["status"] = "failed"
                else:
                    # Delete only the fresh directory allocated for this case,
                    # after catalog cleanup. Failed fixture data stays diagnostic.
                    if case["status"] == "passed":
                        shutil.rmtree(root)
                case["seconds"] = round(time.monotonic() - started, 3)
                (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
                print(json.dumps(case), flush=True)
    expected = len([pair for pair in PAIRS if pair[0] in commands]) * 2
    if len(results["cases"]) != expected or any(case["status"] != "passed" for case in results["cases"]):
        raise RuntimeError("SDK/runtime compatibility failed; see results.json and per-case logs")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("payload", "baseline", "runtime", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--image", default="mirror.gcr.io/library/alpine:3.21")
    execute(parser.parse_args())
