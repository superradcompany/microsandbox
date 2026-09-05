"""Cancel an await, not the stopped-disk worker; immediately restart safely.

Run against a stopped main-matrix source with three physical layers. Set
QUAL_SOURCE to its name and use the same isolated MSB_HOME and native SDK.
"""

import asyncio
import json
import os
import time
from pathlib import Path

from microsandbox import Sandbox


async def main():
    name = os.environ.get("QUAL_SOURCE", "compact-managed")
    journal = Path(os.environ["MSB_HOME"]) / "sandboxes" / name / "runtime" / "root-disk.json"
    before = json.loads(journal.read_text())
    assert len(before["layers"]) == 3
    handle = await Sandbox.get(name)
    pending = asyncio.ensure_future(handle.compact(layers=2))
    await asyncio.sleep(0.01)
    # A very fast fixture cannot establish an in-flight cancellation race.
    assert not pending.done(), "operation completed before cancellation test"
    pending.cancel()
    try:
        await pending
    except asyncio.CancelledError:
        pass
    start = time.perf_counter()
    running = await handle.start()
    try:
        result = await running.exec(
            "sh", ["-c", "sha256sum -c /expected && test $(cat /version) = 4"]
        )
        assert result.exit_code == 0
        after = json.loads(journal.read_text())
        assert len(after["layers"]) == 2, "cancelled worker did not finish its chain"
        print(json.dumps({
            "test": name,
            "cancelled_await_then_start_ms": (time.perf_counter() - start) * 1000,
            "layers": 2,
            "result": "PASS",
        }), flush=True)
    finally:
        await running.stop()


asyncio.run(main())
