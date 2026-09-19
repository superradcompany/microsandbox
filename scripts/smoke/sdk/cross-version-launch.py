"""Run with each SDK/runtime pair in a fresh MSB_HOME and an explicitly selected runtime.

Set MSB_PATH and MSB_LIBKRUNFW_PATH to a matching runtime/firmware pair, then run
this file with the old SDK Python environment and again with the current SDK.
The homes must be isolated: this checks launching, not database downgrades.
"""

import asyncio
import os

from microsandbox import Network, Sandbox


async def main():
    for setting in (None, Network.none()):
        name = f"launch-compat-{os.getpid()}-{'default' if setting is None else 'offline'}"
        sandbox = await Sandbox.create(name, image="alpine", memory=256, network=setting)
        try:
            result = await sandbox.exec("sh", ["-c", "printf launch-compatible"])
            assert result.exit_code == 0, result
            assert result.stdout_text == "launch-compatible", result.stdout_text
            if setting is not None:
                denied = await sandbox.exec("sh", ["-c", "wget -T 2 -q -O /dev/null http://1.1.1.1"])
                assert denied.exit_code != 0, "deny-all network policy was lost"
            await sandbox.stop()
            sandbox = await Sandbox.start(name)
            result = await sandbox.exec("sh", ["-c", "printf restarted-compatible"])
            assert result.exit_code == 0, result
            assert result.stdout_text == "restarted-compatible", result.stdout_text
        finally:
            await sandbox.stop()
            await Sandbox.remove(name)
        print(f"PASS create/exec/stop/restart/remove: {name}", flush=True)


asyncio.run(main())
