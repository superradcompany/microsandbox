"""Read/execute the exact shared inspection fixture; setup/cleanup is external."""
import asyncio
import json
import os
from pathlib import Path
from microsandbox import Sandbox, SandboxNotFoundError

assert os.environ.get("MSB_REMOTE_AUDIT") == "1"
fixture = json.loads(Path(os.environ["MSB_INSPECTION_FIXTURE"]).read_text())
rows = []

async def check(feature, fn):
    try:
        await fn()
        rows.append({"feature": feature, "verdict": "PASS"})
    except Exception as error:
        rows.append({"feature": feature, "verdict": "FAIL", "reason": str(error).replace(os.environ["MSB_API_KEY"], "[redacted]")})
    Path(os.environ["MSB_AUDIT_REPORT"]).write_text(json.dumps({"sdk":"python", "rows":rows}, indent=2)+"\n")

async def main():
    sb = await Sandbox.remote().get(fixture["name"])
    assert sb.id == fixture["id"]
    page = await Sandbox.remote().list()
    while not any(s.id == sb.id for s in page.sandboxes) and page.next_cursor:
        page = await Sandbox.remote().list(cursor=page.next_cursor)
    listed = next(s for s in page.sandboxes if s.id == sb.id)
    for kind, resource in [("get", sb), ("list", listed)]:
        async def config():
            c = await resource.config()
            assert c["kind"] == "remote"
            assert c["spec"]["runtime"]["shell"] == "/bin/bash"
            assert c["spec"]["runtime"]["workdir"] == "/tmp"
            assert c["spec"]["runtime"]["cmd"] == ["configured-default"]
            assert "init" in c["unavailable"]
        async def shell():
            assert (await resource.shell('test -n "$BASH_VERSION" && printf bash')).stdout_text == "bash"
        async def command():
            assert (await resource.exec_default()).stdout_text == "configured-default"
        async def workdir():
            assert (await resource.exec("pwd", [])).stdout_text.strip() == "/tmp"
        for label, fn in [("config",config),("shell",shell),("default_command",command),("workdir",workdir)]:
            await check(kind+"_"+label, fn)

    if os.environ.get("MSB_INSPECTION_DESTROY") == "1":
        await check("destroy", sb.destroy)
        async def absent():
            try:
                await Sandbox.remote().get(fixture["name"])
            except SandboxNotFoundError:
                return
            raise AssertionError("destroyed fixture still exists")
        await check("destroy_absent", absent)

asyncio.run(main())
raise SystemExit(any(r["verdict"] == "FAIL" for r in rows))
