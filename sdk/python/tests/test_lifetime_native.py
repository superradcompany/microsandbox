"""Opt-in checks against a rebuilt native binding, in an isolated SDK process."""

import os
import runpy
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


def test_remote_scope_and_detach_keep_native_resource_usable(tmp_path):
    library = os.environ.get("MSB_LIFETIME_PYTHON_LIBRARY")
    if not library:
        pytest.skip("requires MSB_LIFETIME_PYTHON_LIBRARY")
    package = tmp_path / "microsandbox"
    shutil.copytree(
        Path(__file__).parents[1] / "microsandbox",
        package,
        ignore=shutil.ignore_patterns("*.so", "*.pyc", "__pycache__"),
    )
    (package / "_microsandbox.so").symlink_to(Path(library).resolve())
    env = {key: value for key, value in os.environ.items() if not key.startswith("MSB_")}
    env.update(PYTHONPATH=str(tmp_path), MSB_HOME=str(tmp_path / "home"))
    script = r"""
import asyncio
import gc
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import threading

requests = []
status = "running"
unavailable = False
class Provider(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_GET(self):
        requests.append(("GET", self.path))
        path = self.path.split("?")[0]
        assert path in ("/v1/sandboxes/by-name/task", "/v1/sandboxes")
        if unavailable:
            self.send_error(503, "unavailable")
            return
        observation = {"id": "original", "org_id": "org", "name": "task",
            "slug": "task", "status": status, "ephemeral": False,
            "created_at": "2026-11-15T00:00:00Z"}
        value = observation
        if path == "/v1/sandboxes":
            value = {"data": [observation], "next_cursor": "next"}
        body = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        requests.append(("POST", self.path))
        self.send_error(500, "scope must not stop a remote run")
    def do_DELETE(self):
        requests.append(("DELETE", self.path))
        self.send_error(500, "scope must not delete a remote resource")

server = HTTPServer(("127.0.0.1", 0), Provider)
threading.Thread(target=server.serve_forever, daemon=True).start()
os.environ.update(MSB_BACKEND="cloud", MSB_API_KEY="test-key",
                  MSB_API_URL=f"http://127.0.0.1:{server.server_port}")
from microsandbox import Sandbox, RemoteContext, SandboxStatus
selected = RemoteContext(url=os.environ["MSB_API_URL"], api_key="test-key")

async def check():
    global status, unavailable
    sb = await selected.sandboxes.get("task")
    assert isinstance(sb, Sandbox)
    assert len(requests) == 1, requests
    page = await selected.sandboxes.list()
    assert len(requests) == 2, requests
    assert page.next_cursor == "next"
    listed = page.sandboxes[0]
    assert isinstance(listed, Sandbox) and listed.id == sb.id
    observation = await listed.info()
    assert observation["status"] is SandboxStatus.RUNNING
    assert observation["created_at"] == datetime(2026, 11, 15, tzinfo=timezone.utc)
    status = "stopped"
    assert await listed.status() is SandboxStatus.STOPPED
    assert observation["status"] is SandboxStatus.RUNNING
    assert await listed.last_failure_message() is None
    try:
        await listed.config()
    except Exception:
        pass
    else:
        raise AssertionError("missing provider configuration returned defaults")
    unavailable = True
    try:
        await listed.info()
    except Exception:
        pass
    else:
        raise AssertionError("failed lookup returned cached data")
    unavailable = False
    status = "running"
    temporary = await selected.sandboxes.get("task")
    fs = temporary.fs
    ssh = temporary.ssh()
    del temporary
    gc.collect()
    before = len(requests)
    for action in (lambda: fs.list("/"), lambda: ssh.open_client()):
        try:
            await action()
        except Exception as error:
            assert "released" in str(error), error
        else:
            raise AssertionError("idle helper retained the released receiver")
    assert len(requests) == before, requests
    await sb.ensure_running()
    await sb.ensure_running()
    identity = sb.id
    async with sb as entered:
        assert entered is sb
        await sb.detach()
        await sb.detach()
        assert not await sb.owns_lifecycle
    assert sb.id == identity
    assert await sb.wait_for_status("running") is None
    failure = RuntimeError("body failed")
    try:
        async with sb:
            raise failure
    except RuntimeError as caught:
        assert caught is failure
    else:
        raise AssertionError("body failure suppressed")
    assert await sb.wait_for_status("running") is None
    assert all(method == "GET" for method, _ in requests), requests

try:
    asyncio.run(check())
finally:
    server.shutdown()
"""
    result = subprocess.run(
        [sys.executable, "-c", script], env=env, text=True, capture_output=True, timeout=30
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("use_core", [False, True])
def test_explicit_contexts_retain_independent_destinations(tmp_path, use_core):
    library = os.environ.get("MSB_LIFETIME_PYTHON_LIBRARY")
    if not library:
        pytest.skip("requires MSB_LIFETIME_PYTHON_LIBRARY")
    package = tmp_path / "microsandbox"
    shutil.copytree(
        Path(__file__).parents[1] / "microsandbox",
        package,
        ignore=shutil.ignore_patterns("*.so", "*.pyc", "__pycache__"),
    )
    (package / "_microsandbox.so").symlink_to(Path(library).resolve())
    env = {key: value for key, value in os.environ.items() if not key.startswith("MSB_")}
    env.update(PYTHONPATH=str(tmp_path), MSB_HOME=str(tmp_path / "home"))
    script = r"""
import asyncio
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import threading
from microsandbox import (
    ComputeType, ContextKind, LocalContext, RemoteContext, Sandbox, Volume, VolumeKind, Snapshot,
)
import os

servers = []
creates = []
def provider(identity):
    class Provider(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            creates.append(body["compute"]["type"])
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
        def do_GET(self):
            assert self.headers["Authorization"] == "Bearer key-" + identity
            observation = {"id": identity, "org_id": "org", "name": "task",
                "slug": "task", "status": "running", "ephemeral": False,
                "created_at": "2026-11-15T00:00:00Z"}
            path = self.path.split("?")[0]
            value = {"data": [observation]} if path == "/v1/sandboxes" else observation
            if path == "/v1/volumes/default":
                value = {"id": identity, "kind": "host", "status": "active",
                         "created_at": observation["created_at"],
                         "updated_at": observation["created_at"]}
            body = json.dumps(value).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    server = HTTPServer(("127.0.0.1", 0), Provider)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    servers.append(server)
    return RemoteContext.with_url(
        f"http://127.0.0.1:{server.server_port}", "key-" + identity, compute_type="shared"
    )

async def check():
    assert RemoteContext(api_key="hosted-key").kind == "remote"
    for construct in (
        lambda: RemoteContext(api_key=""),
        lambda: RemoteContext.with_url("", "key"),
        lambda: RemoteContext.with_url("http://localhost", "key", request_timeout_ms=-1),
    ):
        try:
            construct()
        except Exception:
            pass
        else:
            raise AssertionError("invalid remote constructor accepted")
    a, b = provider("a"), provider("b")
    for selected in (a.replace(), a.replace(compute_type=ComputeType.STANDARD)):
        try:
            await selected.sandboxes.create("task", image="python")
        except Exception as error:
            assert "403" in str(error), error
        else:
            raise AssertionError("fixture should deny creation")
    assert creates == ["shared", "standard"], creates
    assert a.kind is ContextKind.REMOTE and LocalContext().kind is ContextKind.LOCAL
    shared_volume = await a.volumes.get_default()
    assert shared_volume.kind is VolumeKind.DIRECTORY
    assert (await shared_volume.info())["kind"] is shared_volume.kind
    for kind in VolumeKind:
        options = {"size_mib": 256} if kind is VolumeKind.DISK else {}
        volume = await Volume.create("probe-" + kind.value, kind=kind, **options)
        try:
            assert volume.kind is kind and (await volume.info())["kind"] is kind
        finally:
            await volume.destroy()
    for resource in (Sandbox, Volume, Snapshot):
        try:
            resource.remote()
        except Exception:
            pass
        else:
            raise AssertionError("missing credentials accepted")
    os.environ.update(
        MSB_API_URL=f"http://127.0.0.1:{servers[0].server_port}",
        MSB_API_KEY="key-a", MSB_BACKEND="local",
    )
    url_a = os.environ["MSB_API_URL"]
    assert (await RemoteContext(compute_type="shared").sandboxes.get("task")).id == "cloud:a"
    os.environ["MSB_API_KEY"] = "wrong"
    assert (await RemoteContext(api_key="key-a").sandboxes.get("task")).id == "cloud:a"
    os.environ.update(MSB_API_KEY="key-a", MSB_API_URL=f"http://127.0.0.1:{servers[1].server_port}")
    assert (await RemoteContext(url=url_a).sandboxes.get("task")).id == "cloud:a"
    os.environ["MSB_API_URL"] = url_a
    collection = Sandbox.remote()
    for resource in (Sandbox, Volume, Snapshot):
        assert resource.remote().context.kind == "remote"
    os.environ["MSB_BACKEND"] = "remote"
    assert (await Sandbox.get("task")).id == "cloud:a"
    for resource in (Sandbox, Volume, Snapshot):
        assert resource.local().context.kind == "local"
    os.environ.update(MSB_API_URL=f"http://127.0.0.1:{servers[1].server_port}", MSB_API_KEY="key-b")
    assert (await a.replace().sandboxes.get("task")).id == (await collection.get("task")).id
    for overrides in (
        {"api_key": ""}, {"url": ""}, {"request_timeout_ms": -1}, {"compute_type": "invalid"}
    ):
        try:
            a.replace(**overrides)
        except Exception:
            pass
        else:
            raise AssertionError("invalid derived settings accepted")
    b = a.replace(url=f"http://127.0.0.1:{servers[-1].server_port}", api_key="key-b")
    b = b.replace(user_agent="derived-agent")
    assert isinstance(b, RemoteContext)
    first, second = await asyncio.gather(collection.get("task"), Sandbox.ctx(b).get("task"))
    assert first.id != second.id
    del a, b
    assert (await collection.get("task")).id == first.id
    assert (await first.context.sandboxes.get("task")).id == first.id
    assert (await second.context.sandboxes.get("task")).id == second.id
    listed = (await collection.list()).sandboxes[0]
    assert listed.id == first.id
    assert (await listed.info())["id"] == first.id
    for value in (-1, True, 0.5):
        try:
            RemoteContext(api_key="key", request_timeout_ms=value)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid timeout accepted")
try:
    asyncio.run(check())
finally:
    for server in servers:
        server.shutdown()
"""
    if use_core:
        staging = runpy.run_path(str(Path(__file__).parents[1] / "scripts/stage_distributions.py"))
        # Mirror the installed full wheel: native lookups of microsandbox.types
        # must resolve to the very same enum classes exported by the shared core.
        files = {**staging["core_files"](), **staging["full_wrapper_files"]()}
        for name, data in files.items():
            destination = tmp_path / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        script = "import microsandbox\n" + script.replace(
            "from microsandbox import", "from microsandbox_core import"
        )
    result = subprocess.run(
        [sys.executable, "-c", script], env=env, text=True, capture_output=True, timeout=30
    )
    assert result.returncode == 0, result.stdout + result.stderr
