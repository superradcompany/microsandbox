"""Sandbox lifecycle integration tests."""

from __future__ import annotations

import json
from contextlib import suppress

import pytest

from integration.helpers import IMAGE, remove_sandbox, stop_and_remove_sandbox
from microsandbox import Sandbox, SandboxAlreadyExistsError, SandboxNotFoundError


@pytest.mark.asyncio
async def test_create_get_list_connect_stop_start_and_remove(sandbox_name):
    name = sandbox_name("py-sdk-life")
    await remove_sandbox(name)

    sandbox = await Sandbox.create(name, image=IMAGE, cpus=1, memory=512)
    try:
        assert await sandbox.name == name
        assert await sandbox.owns_lifecycle is True

        handles = await Sandbox.list()
        assert any(handle.name == name for handle in handles)

        handle = await Sandbox.get(name)
        assert handle.name == name
        assert handle.status
        assert handle.created_at is not None
        assert json.loads(handle.config_json)

        connected = await handle.connect()
        try:
            assert await connected.name == name
            assert await connected.owns_lifecycle is False
            out = await connected.shell("printf 'connected\\n'")
            assert out.success is True
            assert out.stdout_text == "connected\n"
        finally:
            with suppress(Exception):
                await connected.detach()

        code, success = await sandbox.stop_and_wait()
        assert isinstance(code, int)
        assert isinstance(success, bool)

        restarted = await Sandbox.start(name)
        try:
            assert await restarted.name == name
            out = await restarted.shell("printf 'restarted\\n'")
            assert out.stdout_text == "restarted\n"
        finally:
            await stop_and_remove_sandbox(name, restarted)

        with pytest.raises(SandboxNotFoundError):
            await Sandbox.get(name)
    finally:
        await remove_sandbox(name)


@pytest.mark.asyncio
async def test_replace_rejects_duplicate_then_replaces(sandbox_name):
    name = sandbox_name("py-sdk-replace")
    await remove_sandbox(name)

    first = await Sandbox.create(name, image=IMAGE, cpus=1, memory=512)
    try:
        with pytest.raises(SandboxAlreadyExistsError):
            await Sandbox.create(name, image=IMAGE, cpus=1, memory=512)

        second = await Sandbox.create(name, image=IMAGE, cpus=1, memory=512, replace=True)
        try:
            assert await second.name == name
            out = await second.shell("printf 'replacement\\n'")
            assert out.stdout_text == "replacement\n"
        finally:
            await stop_and_remove_sandbox(name, second)
    finally:
        with suppress(Exception):
            await first.stop_and_wait()
        await remove_sandbox(name)


@pytest.mark.asyncio
async def test_list_with_labels(sandbox_factory, sandbox_name):
    owner = sandbox_name("py-sdk-owner")

    web = await sandbox_factory(prefix="py-sdk-web", labels={"owner": owner, "tier": "web"})
    job = await sandbox_factory(prefix="py-sdk-job", labels={"owner": owner, "tier": "job"})
    other = await sandbox_factory(prefix="py-sdk-other", labels={"owner": owner + "-else"})

    web_name = await web.name
    job_name = await job.name
    other_name = await other.name

    # Single selector → both of this owner's sandboxes, not the other's.
    by_owner = {h.name for h in await Sandbox.list_with(labels={"owner": owner})}
    assert web_name in by_owner
    assert job_name in by_owner
    assert other_name not in by_owner

    # AND of two selectors → only the web sandbox.
    by_owner_web = {
        h.name for h in await Sandbox.list_with(labels={"owner": owner, "tier": "web"})
    }
    assert web_name in by_owner_web
    assert job_name not in by_owner_web
    assert other_name not in by_owner_web
