#!/usr/bin/env python3
"""Exercise the installed Python SDK's v0.7.0 lifecycle contract against one runtime."""

import asyncio
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import traceback
import uuid


REPORT_PATH = Path(os.environ["MSB_COMPAT_REPORT"])
REPORT = {"language": "python", "status": "running", "cases": [], "cleanup_errors": []}
CURRENT = None
MARKER = "compat-python-persistent"
NETWORK_MARKER = "compat-python-network-control"


def save_report():
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(REPORT, indent=2) + "\n")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def checkpoint(name, **details):
    CURRENT["checks"].append({"name": name, **details})
    save_report()


def start_case(name):
    global CURRENT
    CURRENT = {"name": name, "status": "running", "checks": []}
    REPORT["cases"].append(CURRENT)
    save_report()


def installed_sdk():
    import microsandbox as sdk
    import microsandbox._microsandbox as native

    root = Path(os.environ["MSB_COMPAT_SDK_ROOT"]).resolve(strict=True)
    package_path = Path(sdk.__file__).resolve(strict=True)
    native_path = Path(native.__file__).resolve(strict=True)
    expected = os.environ["MSB_COMPAT_SDK_VERSION"]
    distribution = importlib.metadata.distribution("microsandbox")
    digest = hashlib.sha256(native_path.read_bytes()).hexdigest()
    REPORT["sdk"] = {
        "root": str(root), "package_path": str(package_path),
        "package_version": distribution.version, "native_path": str(native_path),
        "native_version": sdk.version(), "native_sha256": digest,
        "python": sys.executable,
    }
    save_report()
    require(package_path.is_relative_to(root), "SDK import escaped the isolated installation")
    require(native_path.is_relative_to(root), "native import escaped the isolated installation")
    require(distribution.version == expected, f"package version is not {expected}")
    require(sdk.version() == expected, f"native SDK version is not {expected}")
    # Match the loaded extension to the wheel's own file inventory, not just its version.
    matches = [entry for entry in distribution.files or []
               if Path(distribution.locate_file(entry)).resolve() == native_path]
    require(len(matches) == 1, "loaded native extension is absent from installed wheel metadata")
    if os.environ.get("MSB_COMPAT_NATIVE_SHA256"):
        require(digest == os.environ["MSB_COMPAT_NATIVE_SHA256"], "native artifact SHA256 mismatch")
    checkpoint("installed-sdk-identity", **REPORT["sdk"])
    return sdk


def process_json(command):
    completed = subprocess.run(command, capture_output=True, text=True, timeout=45, check=False)
    require(completed.returncode == 0,
            f"{command!r} failed ({completed.returncode}): {completed.stderr}")
    return json.loads(completed.stdout)


def verify_runtime(name):
    # This independently examines /proc, proving which executable actually launched the VM.
    result = process_json([
        os.environ.get("MSB_COMPAT_PYTHON", "python3"),
        os.environ["MSB_COMPAT_VERIFY_RUNTIME"], name,
    ])
    checkpoint("live-runtime-identity", sandbox=name, result=result)


class ProbeServer(BaseHTTPRequestHandler):
    def do_GET(self):
        payload = NETWORK_MARKER.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        pass


async def network_probe(sandbox, port):
    # The guest's gateway forwards host connections to loopback. Reading its literal
    # address avoids depending on DNS, which deny-all intentionally also blocks.
    script = ("gateway=$(awk '/^nameserver / {print $2; exit}' /etc/resolv.conf); "
              f'test -n "$gateway" || exit 72; exec wget -T 3 -q -O - "http://$gateway:{port}/"')
    return await sandbox.exec("sh", ["-c", script])


async def output(sandbox, command, args, code=0):
    result = await sandbox.exec(command, args)
    require(result.exit_code == code,
            f"{command} {args!r}: expected exit {code}, got {result.exit_code}: {result.stderr_text}")
    require(result.success == (code == 0), "exec success disagrees with exit code")
    return result.stdout_text


def validate_config(config, name, mounts, denied):
    require(config["name"] == name, "persisted sandbox name changed")
    require(config["resources"]["memory_mib"] == 256, "memory configuration was lost")
    require(config["resources"]["cpus"] == 1, "CPU configuration was lost")
    require(config["image"]["Oci"]["root_disk"] == {"kind": "managed", "size_mib": 128},
            "persistent root disk configuration changed")
    environment = {entry["key"]: entry["value"] for entry in config["env"]}
    require(environment.get("MSB_COMPAT_MARKER") == MARKER, "environment configuration was lost")
    configured_mounts = config["mounts"]
    require(len(configured_mounts) == len(mounts), "mount count changed")
    require({mount["guest"] for mount in configured_mounts} == set(mounts), "mount paths changed")
    require(all(mount["type"] == "Tmpfs" and mount["size_mib"] == 8
                for mount in configured_mounts), "tmpfs mount configuration changed")
    network = config["network"]
    require(network["enabled"] is True, "network interface unexpectedly disabled")
    policy = network.get("policy")
    if denied:
        require(policy == {"default_egress": "deny", "default_ingress": "deny", "rules": []},
                f"deny-all policy changed: {policy!r}")
    else:
        # None is the serialized default-public profile in v0.7.0.
        require(policy is None, f"default networking unexpectedly acquired a policy: {policy!r}")


async def suite():
    require(os.environ.get("MSB_COMPAT_CASE", "all") == "all", "unknown scenario selection")
    start_case("installed-sdk-identity")
    sdk = installed_sdk()
    CURRENT["status"] = "passed"
    owned = set()
    prefix = f"compat-python-{uuid.uuid4().hex[:10]}"
    server = ThreadingHTTPServer(("127.0.0.1", 0), ProbeServer)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    async def remove(name):
        await sdk.Sandbox.remove(name)
        try:
            await sdk.Sandbox.get(name)
        except sdk.SandboxNotFoundError:
            pass
        else:
            raise AssertionError(f"removed sandbox {name} is still in the catalog")
        owned.remove(name)
        checkpoint("remove", sandbox=name)

    try:
        start_case("network-positive-control")
        control_name = f"{prefix}-control"
        owned.add(control_name)
        control = await sdk.Sandbox.create(
            control_name, image=sdk.Image.oci(os.environ["MSB_COMPAT_IMAGE"], root_disk=128),
            memory=256, cpus=1, max_duration=300, network=sdk.Network.allow_all(),
        )
        verify_runtime(control_name)
        probe = await network_probe(control, server.server_port)
        require(probe.success and probe.stdout_text == NETWORK_MARKER,
                f"allow-all network control failed: {probe.stderr_text}")
        checkpoint("host-http-reachable", sandbox=control_name)
        CURRENT["status"] = "passed"
        for index, (label, count, denied) in enumerate([
            ("default-zero-mounts", 0, False),
            ("deny-all-one-mount", 1, True),
            ("default-multiple-mounts", 2, False),
        ]):
            start_case(label)
            name = f"{prefix}-{index}"
            mounts = [f"/compat-tmpfs-{number}" for number in range(count)]
            owned.add(name)
            options = {"network": sdk.Network.none()} if denied else {}
            sandbox = await sdk.Sandbox.create(
                name, image=sdk.Image.oci(os.environ["MSB_COMPAT_IMAGE"], root_disk=128),
                memory=256, cpus=1, max_duration=300, env={"MSB_COMPAT_MARKER": MARKER},
                volumes={mount: sdk.Volume.tmpfs(size_mib=8) for mount in mounts}, **options,
            )
            verify_runtime(name)
            handle = await sdk.Sandbox.get(name)
            config = json.loads(handle.config_json)
            validate_config(config, name, mounts, denied)
            require(str(handle.status) == "running", "new sandbox is not running")
            cli = process_json([os.environ["MSB_COMPAT_CLI"], "inspect", name, "--format", "json"])
            require(cli["name"] == name and cli["status"].lower() == "running",
                    "CLI did not observe the SDK-created running sandbox")
            validate_config(cli["config"], name, mounts, denied)
            checkpoint("create-and-shared-cli-catalog", sandbox=name, id=handle.id, config=config)

            require(await output(sandbox, "sh", ["-c", "printf exec-ok; exit 7"], code=7) == "exec-ok",
                    "exec output was lost")
            require(await output(sandbox, "sh", ["-c", 'printf %s "$MSB_COMPAT_MARKER"']) == MARKER,
                    "guest environment was lost")
            await output(sandbox, "sh", ["-ec", f"printf %s {MARKER} > /compat-marker"])
            for mount in mounts:
                require((await output(sandbox, "stat", ["-f", "-c", "%T", mount])).strip() == "tmpfs",
                        f"{mount} is not mounted as tmpfs")
                await output(sandbox, "sh", ["-ec", f"printf scratch > {mount}/marker"])
            checkpoint("exec-environment-and-mounts", tmpfs_mounts=mounts)

            probe = await network_probe(sandbox, server.server_port)
            require(probe.exit_code == 1 and not probe.stdout_text,
                    "network policy allowed the restricted host HTTP probe")
            control_probe = await network_probe(control, server.server_port)
            require(control_probe.success and control_probe.stdout_text == NETWORK_MARKER,
                    "network control stopped responding during the negative probe")
            checkpoint("network-deny-all" if denied else "network-default-host-denied",
                       exit_code=probe.exit_code, stderr=probe.stderr_text)

            await sandbox.stop()
            require(str((await sdk.Sandbox.get(name)).status) == "stopped", "stop did not persist")
            checkpoint("stop", sandbox=name)
            if index == 0:
                archive_path = Path.cwd() / f"{prefix}.tar"
                archive = await sdk.Snapshot.create_archive(
                    f"{prefix}-disk", archive_path, from_sandbox=name, plain_tar=True,
                )
                require(archive_path.is_file() and archive_path.stat().st_size > 0,
                        "disk archive was not written")
                restored_name = f"{prefix}-restored"
                owned.add(restored_name)
                restored = await sdk.Sandbox.restore(
                    str(archive_path), name=restored_name, max_duration=300,
                )
                verify_runtime(restored_name)
                require(await output(restored, "cat", ["/compat-marker"]) == MARKER,
                        "disk archive restore lost the persistent marker")
                checkpoint("disk-snapshot-archive-restore", archive=archive.path,
                           sandbox=restored_name, bytes=archive_path.stat().st_size)
                await restored.stop()
                await remove(restored_name)

            sandbox = await sdk.Sandbox.start(name)
            verify_runtime(name)
            require(await output(sandbox, "cat", ["/compat-marker"]) == MARKER,
                    "stop/start lost the persistent root marker")
            require(await output(sandbox, "sh", ["-c", 'printf %s "$MSB_COMPAT_MARKER"']) == MARKER,
                    "stop/start lost the environment")
            for mount in mounts:
                await output(sandbox, "test", ["!", "-e", f"{mount}/marker"])
            checkpoint("restart-persistence", sandbox=name, tmpfs_reset=True)
            await sandbox.stop()
            await remove(name)
            CURRENT["status"] = "passed"
            save_report()
        await control.stop()
        await remove(control_name)
    finally:
        # A failed assertion must not strand VMs; only our uniquely named fixtures are touched.
        for name in sorted(owned):
            try:
                handle = await sdk.Sandbox.get(name)
                await handle.destroy(force=True)
            except sdk.SandboxNotFoundError:
                pass
            except Exception as error:
                REPORT["cleanup_errors"].append({"sandbox": name, "error": str(error)})
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)
        save_report()
    require(not REPORT["cleanup_errors"], "fixture cleanup failed")


if __name__ == "__main__":
    save_report()
    try:
        asyncio.run(suite())
    except BaseException as error:
        REPORT["status"] = "failed"
        REPORT["failure"] = {"type": type(error).__name__, "message": str(error),
                             "traceback": traceback.format_exc()}
        if CURRENT is not None:
            CURRENT["status"] = "failed"
        traceback.print_exc()
    else:
        REPORT["status"] = "passed"
    finally:
        save_report()
    sys.exit(0 if REPORT["status"] == "passed" else 1)
