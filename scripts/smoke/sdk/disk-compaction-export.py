import asyncio
import json
import os
import time
from pathlib import Path
from microsandbox import Sandbox, Snapshot, MicrosandboxError

async def measure(label, call):
    start = time.perf_counter()
    value = await call
    print(json.dumps({"test": label, "ms": (time.perf_counter() - start) * 1000, "result": value if isinstance(value, dict) else "PASS"}), flush=True)
    return value

async def main():
    prefix = os.environ.get("QUAL_SOURCE", "compact-managed")
    out = Path(os.environ["QUAL_ROOT"])
    out.mkdir(parents=True, exist_ok=True)
    source = await Sandbox.get(prefix)
    plan = await measure("python-plan", source.compact(dry_run=True))
    assert plan["dry_run"] and plan["input_layers"] >= 2
    await measure("python-stopped-compact", source.compact())
    try:
        await source.compact(layers=1)
        raise AssertionError("one layer accepted")
    except MicrosandboxError:
        pass
    await measure("python-save-since", Snapshot.save(prefix + "-4", str(out / "delta.tar.zst"), since=prefix + "-2"))
    await measure("python-save-last", Snapshot.save(prefix + "-4", str(out / "last.tar"), last_layers=2, plain_tar=True))
    await measure("python-load-base", Snapshot.load(str(out / "delta.tar.zst"), dest=str(out / "imported"), base=prefix + "-2"))
    for variant, disk_only in [("full", False), ("disk", True)]:
        child = None
        try:
            child = await measure("python-restore-" + variant, Sandbox.create("compact-python-" + variant, from_snapshot=str(out / "delta.tar.zst"), snapshot_base=prefix + "-2", disk_only=disk_only))
            result = await child.exec("sh", ["-c", "sha256sum -c /expected && test $(cat /version) = 4"])
            assert result.exit_code == 0
            await measure("python-live-plan-" + variant, child.compact(dry_run=True))
            await measure("python-live-compact-" + variant, child.compact(layers=3))
            result = await child.exec("sh", ["-c", "sha256sum -c /expected"])
            assert result.exit_code == 0
        finally:
            if child:
                await child.stop()

asyncio.run(main())
