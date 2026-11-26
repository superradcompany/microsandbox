"""Configured destination capture must precede and outlive resource operations."""

import os
import subprocess
import sys


def test_configured_context_retains_metadata_and_authentication(tmp_path):
    script = r"""
import asyncio
import dataclasses
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import microsandbox as msb

hits = []
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        hits.append(self.headers.get("Authorization"))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"data":[]}')
    def log_message(self, *args):
        pass

server = HTTPServer(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
url = f"http://127.0.0.1:{server.server_port}"
config = Path(os.environ["MSB_CONFIG_PATH"])
def select(name):
    config.write_text(json.dumps({"active_profile": name, "profiles": {
        "prod": {"kind": "remote", "url": url, "api_key_ref": "env:MSB_TEST_CONTEXT_KEY"},
        "staging": {
            "kind": "remote", "url": "http://127.0.0.1:9",
            "api_key_ref": "env:MSB_TEST_CONTEXT_KEY"},
    }}))

try:
    select("prod")
    os.environ["MSB_TEST_CONTEXT_KEY"] = "captured-secret"
    destination = msb.configured_context()
    info = destination.info
    assert isinstance(info, msb.ContextInfo)
    assert (info.kind, info.source, info.profile, info.api_url) == (
        "remote", "active_profile", "prod", url
    )
    assert "captured-secret" not in repr(info)
    try:
        info.source = "changed"
        raise AssertionError("mutable metadata")
    except dataclasses.FrozenInstanceError:
        pass
    assert not hits and not Path(os.environ["MSB_HOME"]).exists()
    select("staging")
    os.environ["MSB_TEST_CONTEXT_KEY"] = "changed-secret"
    async def list_retained():
        await destination.sandboxes.list()
    asyncio.run(list_retained())
    assert hits == ["Bearer captured-secret"]
    assert destination.info == info
    assert msb.configured_context().info.profile == "staging"
    os.environ["MSB_PROFILE"] = "prod"
    assert msb.configured_context().info.source == "MSB_PROFILE"
    os.environ["MSB_BACKEND"] = "local"
    local = msb.configured_context()
    assert (local.info.kind, local.info.source, local.info.api_url) == (
        "local", "MSB_BACKEND", None
    )
    del os.environ["MSB_BACKEND"]
    os.environ["MSB_PROFILE"] = "missing"
    try:
        msb.configured_context()
        raise AssertionError("invalid selection accepted")
    except msb.InvalidConfigError:
        pass
finally:
    server.shutdown()
    thread.join()
"""
    env = {k: v for k, v in os.environ.items() if not k.startswith("MSB_")}
    env.update(MSB_CONFIG_PATH=str(tmp_path / "config.json"), MSB_HOME=str(tmp_path / "home"))
    subprocess.run([sys.executable, "-c", script], env=env, check=True, timeout=30)
