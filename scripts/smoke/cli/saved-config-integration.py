#!/usr/bin/env python3
"""Collect private live configuration records and run their six Rust consumers."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

import lifecycle_evidence as evidence

SCRIPTS = Path(__file__).resolve().parent
RELEASE = "0.7.16"
# Test every release in the previous minor line, including security admission failures.
LAUNCH_RELEASES = tuple(f"0.7.{patch}" for patch in range(17))
TESTS = (
    "sandbox::field_presence::tests::runtime_presence_records_preserve_known_and_unknown_fields",
    "sandbox::network_presence_tests::live_network_default_evidence_projects_without_reinventing_old_intent",
    "sandbox::network_presence_tests::live_missing_policy_remains_unknown_when_projected_and_rewritten",
    "snapshot::saved_config::capture_tests::runtime_capture_document_preserves_old_writer_unknowns",
    "snapshot::saved_config::runtime_capture_tests::runtime_capture_live_records",
    "snapshot::saved_config::runtime_capture_tests::runtime_capture_live_init_records",
)


def previous_writer(root):
    helpers = runpy.run_path(str(SCRIPTS / "snapshot-compatibility.py"))
    asset = helpers["release_asset"]()
    for name in (asset, "checksums.sha256"):
        url = f"https://github.com/superradcompany/microsandbox/releases/download/v{RELEASE}/{name}"
        with urllib.request.urlopen(url, timeout=90) as response, (root / name).open("wb") as output:
            shutil.copyfileobj(response, output)
    binary = root / asset
    helpers["verify_download"](binary, (root / "checksums.sha256").read_text(), asset)
    return binary


def released_launch_runtime(args, root, version):
    """Download a complete verified release; never pair an old host with new firmware."""
    helpers = runpy.run_path(str(SCRIPTS / "snapshot-compatibility.py"))
    platform = helpers["release_asset"]().removeprefix("msb-")
    bundle_name = f"microsandbox-{platform}.tar.gz"
    agent_name = f"agentd-{platform.rsplit('-', 1)[1]}"
    released = root / ("released-" + version)
    released.mkdir()
    for name in ("checksums.sha256", bundle_name, agent_name):
        url = f"https://github.com/superradcompany/microsandbox/releases/download/v{version}/{name}"
        with urllib.request.urlopen(url, timeout=90) as response, (released / name).open("wb") as output:
            shutil.copyfileobj(response, output)
    checksums = (released / "checksums.sha256").read_text()
    for name in (bundle_name, agent_name):
        helpers["verify_download"](released / name, checksums, name)
    with tarfile.open(released / bundle_name) as bundle:
        bundle.extractall(released / "bundle", filter="data")
    runtime = released / "bundle/msb"
    firmwares = list((released / "bundle").glob("libkrunfw*"))
    if len(firmwares) != 1:
        raise ValueError("released bundle must contain one firmware artifact")
    if sys.platform == "darwin":
        subprocess.run(["codesign", "--entitlements", args.workspace / "msb-entitlements.plist",
                        "--force", "-s", "-", runtime], check=True)
    actual = subprocess.check_output([runtime, "--version"], text=True, timeout=15).strip()
    if actual != "msb " + version:
        raise ValueError(f"downloaded runtime version mismatch: {actual}")
    return runtime, firmwares[0], released / agent_name


def extract_tests(args, root):
    if args.test_binary:
        return None
    # The archive contains the whole workspace. Re-extracting it for every
    # runtime dominates the matrix and can exhaust the CI step's deadline.
    extracted = root / "tests"
    extracted.mkdir()
    subprocess.run(["cargo-nextest", "nextest", "list", "--archive-file", args.archive,
                    "--extract-to", extracted, "--workspace-remap", args.workspace,
                    "--list-type", "binaries-only"], check=True)
    return extracted / "target"


def nextest_arguments(args, target, test):
    return ["nextest", "run", "--cargo-metadata", target / "nextest/cargo-metadata.json",
            "--binaries-metadata", target / "nextest/binaries-metadata.json",
            "--target-dir-remap", target, "--workspace-remap", args.workspace,
            "--run-ignored=only", "--no-tests", "fail", "-E", f"test(={test})"]


def qualify_launch_runtime(args, root, image, label, binary, firmware, agent, archive_target=None):
    """Keep expected security refusals separate from successful VM lifecycle tests."""
    home = root / ("launch-" + label)
    env = evidence.environment(binary, firmware, home, agent)
    env.update(MSB_LAUNCH_TEST_IMAGE="alpine:3.23", MSB_LAUNCH_TEST_NAME="cross-version")
    advertisement = json.loads(subprocess.check_output([binary, "__launch-protocol"], env=env, text=True, timeout=15))
    protected = advertisement.get("protected_guest_state") is True
    # This boundary is pinned independently of the probe: a regression that drops
    # the security capability must fail, not silently turn a lifecycle test into a refusal.
    expected_protected = label not in {f"0.7.{patch}" for patch in range(12)}
    if protected != expected_protected:
        raise ValueError(f"unexpected protected-storage capability for {label}: {protected}")
    case = ("released_runtime_preserves_lifecycle_data_and_network_policy" if protected
            else "released_runtime_without_protected_storage_is_refused_before_create")
    test = "runtime::launch_contract::tests::" + case
    runner = evidence.Runner(args.binary, env, root / ("launch-" + label + "-logs"))
    runner.run("load", "image", "load", "--input", image)
    passed = False
    try:
        if args.test_binary:
            tests = evidence.Runner(args.test_binary, env, runner.output / "sdk")
            tests.run("lifecycle" if protected else "security-refusal", "--ignored", "--exact", test)
            log = tests.output / ("lifecycle.stdout" if protected else "security-refusal.stdout")
            if "1 passed;" not in log.read_text():
                raise RuntimeError(f"missing test: {test}")
        else:
            tests = evidence.Runner("cargo-nextest", env, runner.output / "sdk")
            tests.run("lifecycle" if protected else "security-refusal", *nextest_arguments(args, archive_target, test))
        passed = True
    finally:
        if not passed:
            runner.run("cleanup", "rm", "--force", "cross-version", required=False)
    version = subprocess.check_output([binary, "--version"], env=env, text=True, timeout=15).strip()
    status = "lifecycle_passed" if protected else "security_refusal_verified"
    (runner.output / "report.json").write_text(json.dumps({"cases": [{"runtime": version, "status": status}]}))
    print(f"{version}: {status}", flush=True)


def launch_qualification(args, root, image, archive_target=None):
    failures = []
    for version in LAUNCH_RELEASES:
        try:
            runtime = released_launch_runtime(args, root, version)
            qualify_launch_runtime(args, root, image, version, *runtime, archive_target=archive_target)
        except Exception as error:
            # Finish the independent pairings and retain each failure in diagnostics.
            failures.append(version)
            output = root / ("launch-" + version + "-logs")
            output.mkdir(exist_ok=True)
            (output / "report.json").write_text(json.dumps({"cases": [{
                "runtime": version, "status": "failed", "error": str(error)}]}))
            print(f"{version}: failed: {error}", file=sys.stderr, flush=True)
    qualify_launch_runtime(args, root, image, "candidate", args.binary, args.firmware, args.agent,
                           archive_target=archive_target)
    if failures:
        raise RuntimeError("runtime qualification failed: " + ", ".join(failures))


def command_image(source, destination):
    # Keep the release image's layers intact. Only the command provenance matters here.
    with tarfile.open(source) as original, tarfile.open(destination, "w") as output:
        manifest = json.load(original.extractfile("manifest.json"))
        if len(manifest) != 1:
            raise ValueError("command fixture needs one image")
        old = manifest[0]["Config"]
        config = json.load(original.extractfile(old))
        config["config"]["Entrypoint"] = []
        config["config"]["Cmd"] = ["sh", "-c", "echo default >/tmp/default-ran"]
        data = json.dumps(config).encode()
        name = hashlib.sha256(data).hexdigest() + ".json"
        manifest[0].update(Config=name, RepoTags=["local/config-evidence:latest"])
        for member in original:
            if member.name not in ("manifest.json", "repositories", old):
                output.addfile(member, original.extractfile(member) if member.isfile() else None)
        for path, content in [(name, data), ("manifest.json", json.dumps(manifest).encode())]:
            member = tarfile.TarInfo(path)
            member.size = len(content)
            output.addfile(member, io.BytesIO(content))


def command_receipts(args, root, image):
    archive = root / "command.tar"
    command_image(image, archive)
    for case in ("new-default", "new-detached"):
        home = root / case
        env = evidence.environment(args.binary, args.firmware, home, args.agent)
        env.update(ORIGIN_HOST="host-sentinel", ORIGIN_OVERRIDE="shadowed-host")
        runner = evidence.Runner(args.binary, env, root / (case + "-logs"))
        runner.run("load", "image", "load", "--input", archive)
        launch = ["run", "-d"] if case == "new-detached" else ["create"]
        launch += ["local/config-evidence:latest", "--name", "rt", "--root-disk", "256M",
                   "--memory", "256M", "--cpus", "1", "--max-duration", "5m",
                   "--env", "ORIGIN_HOST", "--env", "ORIGIN_LITERAL=plain",
                   "--env", "ORIGIN_OVERRIDE", "--env", "ORIGIN_OVERRIDE=explicit",
                   "--script-raw", "task=registered-private-body"]
        if case == "new-detached":
            launch += ["--", "sh", "-c", "echo invocation >/tmp/invocation-ran; exec sleep 300"]
        launched = False
        try:
            runner.run("launch", *launch)
            launched = True
            runner.run("change-script", "exec", "rt", "--", "sh", "-ec",
                       "printf 'observed-script-body\\n' >/.msb/scripts/task; chmod 640 /.msb/scripts/task")
            runner.run("capture", "snapshot", "create", "--sandbox", "rt", "--output", home / "disk.msb")
            receipt, = (home / "sandboxes/rt/last-active/captures").glob("*.json")
            (root / (case + "-receipt.json")).write_text(json.dumps({"record": json.loads(receipt.read_text())}))
        finally:
            # A timed-out stop can leave a live runtime even when the launcher failed.
            try:
                runner.run("stop", "stop", "--force", "rt", required=False)
            finally:
                runner.run("remove", "rm", "--force", "rt", required=launched)


def run(args, root):
    archive_target = extract_tests(args, root)
    writer = args.previous_writer or previous_writer(root)
    image = args.image or root / "alpine.tar"
    if args.image is None:
        runner = evidence.Runner(args.binary, evidence.environment(args.binary, args.firmware, root / "image-home"), root / "image-logs")
        runner.run("pull", "image", "pull", "alpine:3.23")
        runner.run("save", "image", "save", "--format", "docker", "--output", image, "alpine:3.23")
    launch_qualification(args, root, image, archive_target)
    common = ["--binary", args.binary, "--agent", args.agent, "--firmware", args.firmware,
              "--image", image, "--temp-root", root]
    previous = ["--runtime", "current", "--releases", root, "--previous-writer", writer, "--support", SCRIPTS]
    for name, extra in (("presence", ["--with-mount", "--with-network-defaults"]),
                        ("policy", ["--with-unrecorded-network-policy"])):
        subprocess.run([sys.executable, SCRIPTS / "saved-presence-evidence.py", *common, *previous,
                        "--output", root / name, *extra], check=True)
    subprocess.run([sys.executable, SCRIPTS / "saved-init-evidence.py", *common, "--old", writer,
                    "--output", root / "init"], check=True)
    command_receipts(args, root, image)
    env = dict(os.environ, MSB_PRESENCE_CAPTURE_FIXTURES=str(root / "presence"),
               MSB_NESTED_PRESENCE_FIXTURES=str(root / "presence/current"),
               MSB_POLICY_PRESENCE_FIXTURES=str(root / "policy"), MSB_POLICY_PRESENCE_CURRENT_ONLY="1",
               MSB_RUNTIME_INIT_CAPTURE_FIXTURES=str(root / "init"), MSB_RUNTIME_CAPTURE_FIXTURES=str(root))
    for test in TESTS:
        if args.test_binary:
            result = subprocess.run([args.test_binary, "--ignored", "--exact", test], env=env, check=True,
                                    stdout=subprocess.PIPE, text=True)
            if "1 passed;" not in result.stdout:
                raise RuntimeError(f"missing test: {test}")
        else:
            subprocess.run(["cargo-nextest", *nextest_arguments(args, archive_target, test)],
                           env=env, check=True)
        print(f"passed {test}", flush=True)


def save_diagnostics(root, output, workspace, error=None):
    """Retain command failures and cleanup outcomes, never private config records."""
    output.mkdir(parents=True, exist_ok=True)
    replacements = {str(root): "<fixture>", str(root.resolve()): "<fixture>",
                    str(workspace): "<workspace>", str(Path.home()): "<host-home>"}

    def redact(value):
        text = str(value)
        for source, replacement in sorted(replacements.items(), key=lambda item: -len(item[0])):
            text = text.replace(source, replacement)
        return text

    result = {"status": "failed" if error else "passed", "commands": [], "cases": [], "reports": []}
    if error:
        result["error_type"] = type(error).__name__
        result["error"] = redact(error)
    for manifest in sorted(root.rglob("commands.json")):
        for command in json.loads(manifest.read_text()):
            row = {key: command[key] for key in ("label", "exit", "seconds", "error_type") if key in command}
            row["suite"] = str(manifest.parent.relative_to(root))
            # Arguments/stdout may contain saved configs or private script bodies.
            # Keep only stderr, bounded in size, and redact temporary/host paths.
            label = command["label"]
            stderr = manifest.parent / (label + ".stderr")
            if Path(label).name == label and stderr.is_file() and not stderr.is_symlink():
                with stderr.open("rb") as source:
                    data = source.read(65537)
                row["stderr"] = redact(data[:65536].decode(errors="replace"))
                row["stderr_truncated"] = len(data) > 65536
            result["commands"].append(row)

    def diagnostic_row(source, suite):
        row = {key: source[key] for key in ("runtime", "status", "remaining_sandboxes",
                                            "remaining_live_runs", "surviving_pids") if key in source}
        row["suite"] = suite
        if "cleanup" in source:
            row["cleanup"] = {key: redact(value) for key, value in source["cleanup"].items()}
        for key in ("error", "cleanup_error"):
            if key in source:
                row[key] = redact(source[key])
        return row

    for report in sorted(root.rglob("report.json")):
        source = json.loads(report.read_text())
        suite = str(report.parent.relative_to(root))
        # Init fixtures put failures and cleanup on the report itself, including
        # failures before any case exists. Apply the same allowlist at both levels.
        result["reports"].append(diagnostic_row(source, suite))
        result["cases"].extend(diagnostic_row(case, suite) for case in source.get("cases", []))
    (output / "diagnostics.json").write_text(json.dumps(result, indent=2) + "\n")
    for row in result["commands"]:
        if row.get("exit") != 0:
            print(f"{row['suite']}/{row['label']}: exit {row.get('exit')}\n{row.get('stderr', '')}",
                  file=sys.stderr, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "agent", "firmware", "workspace"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("image", "previous-writer"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--output", type=Path, default=Path("build/saved-config-integration-results"))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--archive", type=Path)
    mode.add_argument("--test-binary", type=Path)
    args = parser.parse_args()
    for name, path in vars(args).items():
        if isinstance(path, Path):
            setattr(args, name, path.resolve())
    evidence.install_termination_handler()
    # Save bounded diagnostics before TemporaryDirectory removes private records,
    # including on subprocess failure or termination after fixture cleanup.
    with tempfile.TemporaryDirectory(prefix="sce-", dir="/tmp") as tmp:
        failure = None
        try:
            run(args, Path(tmp))
        except BaseException as error:
            failure = error
            raise
        finally:
            save_diagnostics(Path(tmp), args.output, args.workspace, failure)


if __name__ == "__main__":
    if sys.argv[1:] == ["--nextest-filter"]:
        print(" or ".join(f"test(={test})" for test in TESTS))
    else:
        main()
