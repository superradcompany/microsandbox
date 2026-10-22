"""Run with a self-contained disk/full archive and an isolated MSB_HOME."""
import asyncio
import os

import pytest

from microsandbox import PullPolicy, Sandbox, Snapshot


@pytest.mark.asyncio
@pytest.mark.skipif(
    not os.environ.get("MSB_PULL_ARCHIVE"), reason="requires archive and disposable VM home"
)
async def test_snapshot_pull_policy():
    group = (await Snapshot.load("python-pull-history", [os.environ["MSB_PULL_ARCHIVE"]])).snapshot
    checkpoint = await group.head()
    try:
        for policy in (PullPolicy.NEVER, PullPolicy.IF_MISSING, PullPolicy.ALWAYS):
            name = "python-pull-" + policy.value
            child = None
            try:
                options = dict(name=name, pull_policy=policy, ports={0:18080})
                if policy == PullPolicy.NEVER:
                    child = await group.spawn_sandbox(**options)
                else:
                    session = await checkpoint.spawn_sandbox_with_progress(**options)
                    child = await session.result()
                result = await child.shell("printf policy-alive")
                assert result.success and result.stdout_text == "policy-alive"
                print(policy.value, "passed", flush=True)
            finally:
                if child is not None:
                    await child.stop()
                    await Sandbox.remove(name)
    finally:
        await group.remove()

if __name__ == "__main__":
    asyncio.run(test_snapshot_pull_policy())
