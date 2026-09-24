"""Phases used by the ignored released_sdk_secret_downgrade CLI test.

Use an isolated MSB_HOME. Create/restart run under SDK/runtime v0.6.18;
edit runs under the candidate SDK/runtime. The Rust test performs the actual
CLI preflight and transactional downgrade between edit and restart.
"""

import asyncio
import importlib.util
import sys
from pathlib import Path

from microsandbox import Sandbox

spec = importlib.util.spec_from_file_location(
    "legacy_secrets", Path(__file__).with_name("legacy-secrets.py")
)
probe_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe_module)


async def main():
    phase = sys.argv[1]
    name = "secret-downgrade"
    if phase == "create":
        from microsandbox import Network, Secret

        sandbox = await Sandbox.create(
            name,
            image="mirror.gcr.io/library/alpine:3.21",
            memory=256,
            max_duration=120,
            detached=True,
            network=Network.allow_all(),
            secrets=[Secret.env("REPRO_TOKEN", value="before-rotation",
                                allow_hosts=[probe_module.HOST], require_tls=False)],
        )
        try:
            result = await sandbox.exec("sh", ["-c", "printf preserved > /root/downgrade-marker"])
            assert result.exit_code == 0
        finally:
            await sandbox.stop()
    elif phase == "edit":
        from microsandbox import ModificationPolicy

        handle = await Sandbox.get(name)
        await handle.modify(
            labels={"downgrade-test": "edited-by-v07"},
            secrets={"REPRO_TOKEN": {"value": probe_module.VALUE}},
            policy=ModificationPolicy.NEXT_START,
        )
    else:
        handle = await Sandbox.get(name)
        sandbox = await handle.start(detached=True)
        try:
            result = await sandbox.exec("cat", ["/root/downgrade-marker"])
            assert result.stdout_text == "preserved"
            await probe_module.probe(sandbox, "scopes-11")
        finally:
            await sandbox.stop()
    print(f"PASS {phase}", flush=True)


asyncio.run(main())
