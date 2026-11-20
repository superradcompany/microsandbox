"""Validate staged wheels using offline installs and real provider libraries."""

import argparse
import os
import subprocess
import tempfile
import zipfile
from pathlib import Path


def run(command, *, env=None):
    subprocess.run(command, check=True, timeout=120, env=env)


PROBE = r"""
import asyncio, importlib, json, os, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
import microsandbox_core as core
from microsandbox_core.errors import JobError
import microsandbox_local as local
import microsandbox_remote as remote
assert local.Sandbox is remote.Sandbox is core.Sandbox
assert local.Volume is remote.Volume is core.Volume
assert local.Snapshot is remote.Snapshot is core.Snapshot
assert local.MicrosandboxError is remote.MicrosandboxError
assert local.SandboxStatus is remote.SandboxStatus
requests = []
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        requests.append(self.path)
        assert self.headers['Authorization'] == 'Bearer key'
        value = dict(
            id='original', org_id='org', name='task', slug='task', status='stopped',
            ephemeral=False, created_at='2026-11-16T00:00:00Z',
        )
        if self.path.split('?')[0] == '/v1/sandboxes': value = dict(data=[value])
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.end_headers()
        self.wfile.write(json.dumps(value).encode())
    def log_message(self, *args): pass
server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
async def probe():
    with tempfile.TemporaryDirectory() as home:
        selected = remote.RemoteContext(url=f'http://127.0.0.1:{server.server_port}', api_key='key')
        retained = selected.sandboxes
        destination = local.LocalContext(home=home)
        assert destination.kind is core.ContextKind.LOCAL
        assert selected.kind is core.ContextKind.REMOTE
        sb = await retained.get('task')
        assert isinstance(sb, core.Sandbox)
        assert isinstance(sb.context, core.Context)
        assert isinstance(sb.context.sandboxes, core.Sandboxes)
        observation = await sb.info()
        assert observation['id'] == sb.id and observation['status'] is core.SandboxStatus.STOPPED
        assert await sb.status() is core.SandboxStatus.STOPPED
        # Exercise the new lifecycle symbols through a real remote-only extension.
        for observe in (sb.resize_status, sb.resize_operations, sb.wait_until_resized):
            before = len(requests)
            try: await observe()
            except core.UnsupportedError as error:
                assert 'local backend' in str(error), str(error)
            else: raise AssertionError('remote resize unexpectedly succeeded')
            assert len(requests) == before
        # Unsupported remote jobs must retain their typed error in every package.
        try: await sb.exec_detached('true')
        except JobError: pass
        else: raise AssertionError('remote jobs unexpectedly succeeded')
        assert not await sb.owns_lifecycle
        async with sb as borrowed:
            assert borrowed is sb
        assert (await sb.context.sandboxes.get('task')).id == sb.id
        page = await retained.list()
        assert isinstance(page.sandboxes[0], core.Sandbox)
        assert await sb.wait_for_status('stopped') is None
        # Compare default bindings later under the same configuration as before
        # the probe. While remote is selected, the retained local context wins.
        with patch.dict(os.environ,
            MSB_BACKEND="remote",
            MSB_API_URL=f"http://127.0.0.1:{server.server_port}",
            MSB_API_KEY="key",
        ):
            assert (await core.Sandbox.get("task")).id == sb.id
            before = len(requests)
            try: await destination.sandboxes.get('missing')
            except core.MicrosandboxError: pass
            else: raise AssertionError('missing local sandbox unexpectedly exists')
            assert len(requests) == before
try: asyncio.run(probe())
finally:
    server.shutdown()
    server.server_close()
    thread.join()
"""


# Optional real-runtime coverage exercises native decoders after installing each
# package independently, so the full package cannot mask a lean import defect.
JOBS_PROBE = r"""
import asyncio, importlib, os, uuid
from contextlib import suppress
sdk=importlib.import_module(os.environ['MSB_TEST_PACKAGE'])
from microsandbox_core.jobs import JobExit, JobInfo, JobOutputSource, JobPage, JobState
async def main():
    name='review-jobs-'+uuid.uuid4().hex[:8]
    sb=await sdk.Sandbox.create(name, image='mirror.gcr.io/library/alpine', memory=512, cpus=1)
    try:
        job=await sb.exec_detached('sh', args=['-c','printf job-output; exit 7'])
        outcome=await job.wait()
        assert isinstance(outcome, JobExit) and outcome.code==7
        info=await job.inspect()
        assert isinstance(info, JobInfo) and info.id==job.id and info.state is JobState.EXITED
        page=await sb.list_jobs(all=True)
        assert isinstance(page, JobPage) and any(item.id==job.id for item in page.items)
        logs=await job.logs(sources=[JobOutputSource.STDOUT])
        assert all(entry.source is JobOutputSource.STDOUT for entry in logs)
        assert b'job-output' in b''.join(item.data for item in logs)
        print(os.environ['MSB_TEST_PACKAGE'], 'native wait/inspect/list/output decoded')
    finally:
        with suppress(Exception): await sb.stop()
        await sdk.Sandbox.remove(name)
asyncio.run(main())
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheels", type=Path, required=True)
    parser.add_argument(
        "--full", action="store_true", help="Also check coexistence with the staged full wheel"
    )
    parser.add_argument(
        "--live-jobs-home",
        type=Path,
        help="Opt-in isolated runtime home with a cached alpine image for native job decoding",
    )
    args = parser.parse_args()
    wheels = {}
    for kind in ("core", "local", "remote"):
        candidates = list(args.wheels.glob(f"microsandbox_{kind}-*.whl"))
        if len(candidates) != 1:
            parser.error(f"expected one {kind} wheel")
        wheels[kind] = str(candidates[0].resolve())
        with zipfile.ZipFile(candidates[0]) as archive:
            paths = archive.namelist()
            if any(
                "_bundled/" in path
                or "libkrunfw" in path
                or path.endswith(("/msb", "/msb.exe", "/_cli.py"))
                for path in paths
            ):
                raise RuntimeError(f"{kind} includes runtime payload or launcher")
            if kind == "core" and any(path.endswith((".so", ".dylib", ".pyd")) for path in paths):
                raise RuntimeError("core includes native payload")
    with tempfile.TemporaryDirectory(prefix="msb-python-packages-") as temporary:
        for first, second in (("local", "remote"), ("remote", "local")):
            venv = Path(temporary) / f"{first}-{second}"
            run(["uv", "venv", str(venv)])
            python = str(venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))
            install = ["uv", "pip", "install", "--offline", "--python", python]
            run([*install, wheels["core"]])
            core_probe = "\n".join(
                [
                    "import sys, microsandbox_core",
                    "assert not any(",
                    "    name.startswith(('microsandbox_local', 'microsandbox_remote'))",
                    "    for name in sys.modules",
                    ")",
                ]
            )
            run([python, "-c", core_probe])
            run([*install, wheels[first]])
            run([*install, wheels[second]])
            run([python, "-c", PROBE])
            run(["uv", "pip", "uninstall", "--python", python, f"microsandbox-{first}"])
            constructor = "LocalContext()" if second == "local" else "RemoteContext(api_key='key')"
            provider_probe = "\n".join(
                [
                    f"import microsandbox_{second} as sdk",
                    f"assert sdk.{constructor}.kind == {second!r}",
                ]
            )
            run([python, "-c", provider_probe])
        if args.full:
            full = list(args.wheels.glob("microsandbox-[0-9]*.whl"))
            if len(full) != 1:
                parser.error("--full requires exactly one full wheel")
            venv = Path(temporary) / "full"
            run(["uv", "venv", str(venv)])
            python = str(venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))
            run(
                [
                    "uv",
                    "pip",
                    "install",
                    "--offline",
                    "--python",
                    python,
                    *wheels.values(),
                    str(full[0].resolve()),
                ]
            )
            prefix = (
                "import microsandbox as full\n"
                "from microsandbox_core._native import default_binding\n"
                "original = default_binding()\n"
            )
            suffix = """
from microsandbox.jobs import _decode_exit, _decode_page
assert _decode_exit(dict(code=0, success=True, timed_out=False)).success
assert _decode_page(dict(items=[], next_cursor=None)).items == []
assert full.Sandbox is core.Sandbox and full.MicrosandboxError is core.MicrosandboxError
assert default_binding() is original
"""
            run([python, "-c", prefix + PROBE + suffix])
            run(
                [
                    python,
                    "-c",
                    PROBE + "\nimport microsandbox as full\nassert full.Sandbox is core.Sandbox\n",
                ]
            )
        if args.live_jobs_home:
            for kind in ("local", "full") if args.full else ("local",):
                venv = Path(temporary) / f"jobs-{kind}"
                run(["uv", "venv", str(venv)])
                python = str(venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))
                artifact = str(full[0].resolve()) if kind == "full" else wheels[kind]
                run(
                    [
                        "uv",
                        "pip",
                        "install",
                        "--offline",
                        "--python",
                        python,
                        wheels["core"],
                        artifact,
                    ]
                )
                home = str(args.live_jobs_home.resolve())
                env = dict(
                    os.environ,
                    MSB_HOME=home,
                    MSB_CONFIG_PATH=str(Path(home) / "config.json"),
                    MSB_TEST_PACKAGE="microsandbox" if kind == "full" else "microsandbox_local",
                )
                run([python, "-c", JOBS_PROBE], env=env)
    print(
        "Wheel payloads, shared types, live resource calls, context retention, "
        "offline installs and independent uninstall passed."
    )


if __name__ == "__main__":
    main()
