"""Opt-in live checks against an explicitly selected disposable sandbox."""

import asyncio
import os
from contextlib import suppress

import pytest

from microsandbox import ExecTimeoutError, JobError, Sandbox, Stdin


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

            # Keyword and options-dictionary parsing must retain explicit null separately from
            # omitted input. Otherwise the detached builder leaves cat's pipe open indefinitely.
            for options_dict in [False, True]:
                null = await (
                    sandbox.exec_detached("cat", {"stdin": Stdin.null()})
                    if options_dict
                    else sandbox.exec_detached("cat", stdin=Stdin.null())
                )
                jobs.append(null)
                assert (await null.wait()).success
                assert (await null.inspect()).stdin_closed
            empty = await sandbox.exec_detached("cat", stdin=b"")
            jobs.append(empty)
            assert (await empty.wait()).success
            assert await empty.logs() == []
            assert (await sandbox.exec("cat", stdin=Stdin.null())).success
            with pytest.raises(JobError) as invalid:
                await sandbox.exec_detached("cat", stdin=Stdin.null(), tty=True)
            assert invalid.value.code == "invalid_options"

            sleepy = await sandbox.exec_detached("sleep", ["30"])
            jobs.append(sleepy)
            stream = await sleepy.follow_logs()
            pending = asyncio.ensure_future(stream.__anext__())
            await asyncio.sleep(0.05)
            await stream.close()
            with pytest.raises(StopAsyncIteration):
                # Closing must unblock the receive that was already pending, not just a new one.
                await asyncio.wait_for(pending, timeout=5)
    finally:
        for attachment in attachments:
            with suppress(JobError):
                await attachment.detach()
        for job in jobs:
            with suppress(JobError):
                await job.kill()
                await job.wait()


@pytest.mark.skipif(
    not (os.environ.get("MSB_HOME") and os.environ.get("MSB_JOB_TEST_SANDBOX")),
    reason="requires an isolated MSB_HOME and running MSB_JOB_TEST_SANDBOX",
)
async def test_stream_timeout_without_output_polling():
    sandbox = await (await Sandbox.get(os.environ["MSB_JOB_TEST_SANDBOX"])).connect()
    async with asyncio.timeout(20):
        for tty in [False, True]:
            handle = await sandbox.exec_stream("sleep", ["30"], timeout=0.5, tty=tty)
            try:
                # Cancelling a caller's wait must not remove the execution deadline.
                with pytest.raises(TimeoutError):
                    await asyncio.wait_for(handle.wait(), 0.05)
                await asyncio.sleep(1)
                with pytest.raises(ExecTimeoutError):
                    await handle.collect()
            finally:
                with suppress(Exception):
                    await handle.kill()
        shell = await sandbox.shell_stream("sleep 30", timeout=0.5)
        with pytest.raises(ExecTimeoutError):
            await shell.wait()
        output = await sandbox.exec_stream("echo", ["ok"], timeout=5)
        assert (await output.collect()).stdout_text == "ok\n"
        # Buffered exec keeps its established timeout error contract as well.
        with pytest.raises(ExecTimeoutError):
            await sandbox.exec("sleep", ["30"], timeout=0.5)
