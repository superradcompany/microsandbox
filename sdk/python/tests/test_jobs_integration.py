"""Opt-in live checks against an explicitly selected disposable sandbox."""

import asyncio
import os
from contextlib import suppress

import pytest

from microsandbox import JobError, Sandbox


@pytest.mark.skipif(
    not (os.environ.get("MSB_HOME") and os.environ.get("MSB_JOB_TEST_SANDBOX")),
    reason="requires an isolated MSB_HOME and running MSB_JOB_TEST_SANDBOX",
)
async def test_managed_job_ownership_io_and_cancellation():
    sandbox = await (await Sandbox.get(os.environ["MSB_JOB_TEST_SANDBOX"])).connect()
    jobs = []
    attachments = []
    try:
        async with asyncio.timeout(20):
            job = await sandbox.exec_detached("cat")
            jobs.append(job)
            first = await job.attach()
            attachments.append(first)
            with pytest.raises(JobError) as refused:
                await job.attach()
            assert refused.value.code == "input_busy"
            await first.write_stdin(b"\xff\x00\n")
            assert (await first.recv()).value.data == b"\xff\x00\n"
            await first.detach()
            found = await sandbox.get_job(job.id)
            second = await found.attach()
            attachments.append(second)
            await second.write_stdin(b"reattached\n")
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(found.wait(), 0.05)
            assert (await found.inspect()).state == "running"
            await found.eof()
            assert (await found.wait()).success
            await second.detach()
            assert b"".join(x.data for x in await found.logs()) == b"\xff\x00\nreattached\n"
            cursor = None
            while True:
                page = await sandbox.list_jobs(all=True, cursor=cursor)
                if any(info.id == job.id for info in page.items):
                    break
                assert page.next_cursor, "job missing from retained history"
                cursor = page.next_cursor

            finite = await sandbox.exec_detached("cat", stdin=b"finite bytes")
            jobs.append(finite)
            assert (await finite.wait()).success
            assert b"".join(x.data for x in await finite.logs()) == b"finite bytes"

            sleepy = await sandbox.exec_detached("sleep", ["30"])
            jobs.append(sleepy)
            stream = await sleepy.follow_logs()
            pending = asyncio.ensure_future(stream.__anext__())
            await asyncio.sleep(0.05)
            await stream.close()
            with pytest.raises(StopAsyncIteration):
                await pending
    finally:
        for attachment in attachments:
            with suppress(JobError):
                await attachment.detach()
        for job in jobs:
            with suppress(JobError):
                await job.kill()
                await job.wait()
