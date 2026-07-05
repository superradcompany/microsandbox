"""Sandbox.create keyword-argument integration tests."""

from __future__ import annotations

import json
from contextlib import suppress

import pytest

from integration.helpers import IMAGE, remove_sandbox, stop_and_remove_sandbox
from microsandbox import Sandbox


def _config_env(config: dict) -> dict[str, str]:
    return {entry["key"]: entry["value"] for entry in config["env"]}


@pytest.mark.asyncio
async def test_create_kwargs_affect_guest_defaults(sandbox_name):
    name = sandbox_name("py-sdk-create-kwargs")
    await remove_sandbox(name)

    sandbox = await Sandbox.create(
        name,
        image=IMAGE,
        cpus=1,
        memory=512,
        hostname="py-sdk-create-host",
        workdir="/tmp",
        shell="/bin/sh",
        user="nobody",
        env={"PYTHON_CREATE_KWARG": "guest-visible"},
        scripts={
            "create-kwarg-script": (
                "#!/bin/sh\n"
                "printf 'script:%s:%s\\n' \"$(whoami)\" \"$PYTHON_CREATE_KWARG\""
            )
        },
        replace=True,
    )

    try:
        probe = await sandbox.shell(
            'printf "%s:%s:%s:%s\\n" '
            '"$(hostname)" "$(pwd)" "$(whoami)" "$PYTHON_CREATE_KWARG"'
        )
        assert probe.success is True
        assert probe.stdout_text == "py-sdk-create-host:/tmp:nobody:guest-visible\n"

        script = await sandbox.exec("create-kwarg-script")
        assert script.success is True
        assert script.stdout_text == "script:nobody:guest-visible\n"
    finally:
        await stop_and_remove_sandbox(name, sandbox)


@pytest.mark.asyncio
async def test_create_kwargs_round_trip_through_config_json(sandbox_name):
    name = sandbox_name("py-sdk-create-config")
    await remove_sandbox(name)

    sandbox = await Sandbox.create(
        name,
        image=IMAGE,
        cpus=1,
        max_cpus=4,
        memory=512,
        max_memory=2048,
        hostname="py-sdk-config-host",
        workdir="/var",
        shell="/bin/sh",
        user="nobody",
        env={"PYTHON_CONFIG_KWARG": "persisted"},
        scripts={"bootstrap": "echo bootstrap-from-python"},
        entrypoint=["/bin/sh", "-c", "echo entrypoint-from-python"],
        init="auto",
        max_duration=7200.0,
        idle_timeout=1800.0,
        ephemeral=True,
        pull_policy="if_missing",
        log_level="info",
        detached=True,
        replace=True,
    )
    handle = None
    connected = None

    try:
        assert await sandbox.owns_lifecycle is False

        handle = await Sandbox.get(name)
        config = json.loads(handle.config_json)

        assert config["name"] == name
        assert config["resources"]["cpus"] == 1
        assert config["resources"]["max_cpus"] == 4
        assert config["resources"]["memory_mib"] == 512
        assert config["resources"]["max_memory_mib"] == 2048
        assert config["runtime"]["hostname"] == "py-sdk-config-host"
        assert config["runtime"]["workdir"] == "/var"
        assert config["runtime"]["shell"] == "/bin/sh"
        assert config["runtime"]["user"] == "nobody"
        assert _config_env(config)["PYTHON_CONFIG_KWARG"] == "persisted"
        assert config["runtime"]["scripts"]["bootstrap"] == "echo bootstrap-from-python"
        assert config["runtime"]["entrypoint"] == [
            "/bin/sh",
            "-c",
            "echo entrypoint-from-python",
        ]
        assert config["init"]["cmd"] == "auto"
        assert config["pull_policy"] == "IfMissing"
        assert config["runtime"]["log_level"] == "info"
        assert config["lifecycle"]["max_duration_secs"] == 7200
        assert config["lifecycle"]["idle_timeout_secs"] == 1800
        assert config["lifecycle"]["ephemeral"] is True

        sandbox = None

        connected = await handle.connect()
        assert await connected.owns_lifecycle is False
        out = await connected.shell("printf 'detached-create\\n'")
        assert out.success is True
        assert out.stdout_text == "detached-create\n"
    finally:
        if connected is not None:
            with suppress(Exception):
                await connected.detach()
        with suppress(Exception):
            if sandbox is not None:
                await sandbox.stop()
        if handle is None:
            with suppress(Exception):
                handle = await Sandbox.get(name)
        if handle is not None:
            with suppress(Exception):
                await handle.stop(timeout=10.0)
        await remove_sandbox(name)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"max_duration": -1.0}, "max_duration must be non-negative"),
        ({"idle_timeout": -1.0}, "idle_timeout must be non-negative"),
        ({"replace_with_timeout": -1.0}, "replace_with_timeout must be non-negative"),
        ({"pull_policy": "sometimes"}, "invalid pull_policy"),
        ({"log_level": "verbose"}, "invalid log_level"),
    ],
)
async def test_create_kwargs_validate_bad_values(sandbox_name, kwargs, message):
    name = sandbox_name("py-sdk-create-invalid")
    await remove_sandbox(name)

    with pytest.raises(ValueError, match=message):
        await Sandbox.create(name, image=IMAGE, **kwargs)
