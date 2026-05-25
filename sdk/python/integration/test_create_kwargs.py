"""Sandbox.create keyword-argument integration tests."""

from __future__ import annotations

import json
from contextlib import suppress

import pytest

from integration.helpers import IMAGE, remove_sandbox, stop_and_remove_sandbox
from microsandbox import Sandbox


def _config_env(config: dict) -> dict[str, str]:
    return {key: value for key, value in config["env"]}


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
        memory=512,
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
        pull_policy="if_missing",
        log_level="info",
        detached=True,
        replace=True,
    )

    try:
        assert await sandbox.owns_lifecycle is False

        handle = await Sandbox.get(name)
        config = json.loads(handle.config_json)

        assert config["name"] == name
        assert config["cpus"] == 1
        assert config["memory_mib"] == 512
        assert config["hostname"] == "py-sdk-config-host"
        assert config["workdir"] == "/var"
        assert config["shell"] == "/bin/sh"
        assert config["user"] == "nobody"
        assert _config_env(config)["PYTHON_CONFIG_KWARG"] == "persisted"
        assert config["scripts"]["bootstrap"] == "echo bootstrap-from-python"
        assert config["entrypoint"] == [
            "/bin/sh",
            "-c",
            "echo entrypoint-from-python",
        ]
        assert config["init"]["cmd"] == "auto"
        assert config["pull_policy"] == "IfMissing"
        assert config["log_level"] == "info"
        assert config["policy"]["max_duration_secs"] == 7200
        assert config["policy"]["idle_timeout_secs"] == 1800
    finally:
        with suppress(Exception):
            await sandbox.stop_and_wait()
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
