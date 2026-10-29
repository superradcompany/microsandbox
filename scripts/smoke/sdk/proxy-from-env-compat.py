"""Cross-version qualification for ambient host proxy discovery (issue #70).

Run with the current Python SDK against explicitly selected runtime/firmware
pairs. Each phase uses a fresh worker subprocess with its own `MSB_HOME` and an
explicit `MSB_PATH`/`MSB_LIBKRUNFW_PATH`, so cached or default backends cannot
mask the selected executable. The parent supplies the sandbox name, so every
phase addresses the same saved row.

Required:
  --current-msb PATH --current-firmware PATH
  --pre-feature-machine PATH --pre-feature-firmware PATH

Optional, repeated per released v0.6 endpoint you want to qualify:
  --legacy-msb PATH --legacy-firmware PATH

The `--pre-feature-machine` runtime must also pass the SDK's general
launch-contract version gate, which admits only 0.6.x and the exact current
build. Phases 3-5 need such a runtime; against one that gate rejects (0.7.9, for
example) they fail for a reason unrelated to this feature.

Covered:
1. Support-matrix baseline: current SDK + current runtime create/exec/stop/
   start/remove with ambient intent false (ordinary bytes unchanged).
2. Current SDK + real pre-feature machine runtime, ambient true: clean
   upgrade-required refusal before any provisional replacement or process. A
   runtime rejected even earlier by the general launch-contract gate (for
   example 0.7.9, which this SDK refuses for *every* launch) cannot exercise
   this feature's gate, so that phase reports SKIP with the reason instead of
   claiming a refusal it never observed.
3. Real machine restart regression: a running VM with persisted true refuses an
   unrelated restart-backed modification and an ordinary handle restart
   (StopThenStart) selected through the pre-feature machine runtime, leaving raw
   desired/active JSON, status, and the live run untouched, and the VM still
   responds to exec.
4. The CLI `msb restart` path refuses the same saved intent through the
   pre-feature runtime without mutating the row.
5. StartOnly: a stopped sandbox refuses an ordinary handle restart before
   launch, keeping its saved intent.

Nothing here rewrites catalog rows; raw state is read through a read-only SQLite
connection. All names and homes are disposable.
"""

import argparse
import asyncio
import os
import sqlite3
import subprocess
import sys
import tempfile
from contextlib import suppress

# Every spelling the runtime reads; a phase never inherits the shell's proxy setup.
PROXY_VARIABLES = (
    "http_proxy",
    "HTTP_PROXY",
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "no_proxy",
    "NO_PROXY",
)

# `launch_contract::from_version` accepts only 0.6.x and the exact current build,
# and it runs before any network capability probe. Every launch against such a
# runtime is refused, flag or no flag, so an ambient refusal is unobservable there.
LAUNCH_CONTRACT_REJECTION = "no tested sandbox launch contract for runtime"


PHASES = {}


def phase(function):
    PHASES[function.__name__.removeprefix("phase_").replace("_", "-")] = function
    return function


def sandbox_name():
    """The stable name the parent assigned to this qualification run."""
    return os.environ.get("AMBIENT_COMPAT_NAME") or f"ambient-compat-{os.getpid()}"


def worker(entrypoint):
    """Run one phase in a fresh interpreter with its own home and runtime pair."""

    def run(*, msb, firmware, home, phase, extra_environment=None):
        environment = dict(os.environ)
        for name in PROXY_VARIABLES:
            environment.pop(name, None)
        environment.update(
            {
                "MSB_HOME": home,
                "MSB_CONFIG_PATH": os.path.join(home, "config.json"),
                "MSB_PATH": msb,
                "MSB_LIBKRUNFW_PATH": firmware,
                "AMBIENT_COMPAT_PHASE": phase,
                "AMBIENT_COMPAT_NAME": sandbox_name(),
            }
        )
        environment.update(extra_environment or {})
        completed = subprocess.run(
            [sys.executable, entrypoint, "--worker"],
            env=environment,
            capture_output=True,
            text=True,
            timeout=900,
        )
        if completed.returncode != 0:
            raise AssertionError(
                f"{phase} failed:\n{completed.stdout}\n{completed.stderr}"
            )
        return completed.stdout

    return run


def raw_state(home, name):
    """Read desired/active config JSON, status, and the live run identity."""
    database = os.path.join(home, "db", "msb.db")
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        row = connection.execute(
            "select config, active_config, status from sandbox where name = ?", (name,)
        ).fetchone()
        if row is None:
            raise AssertionError(f"sandbox {name} is missing from {database}")
        run = connection.execute(
            "select id, pid from run where sandbox_id = ("
            "select id from sandbox where name = ?) order by id desc limit 1",
            (name,),
        ).fetchone()
        return {"config": row[0], "active_config": row[1], "status": row[2], "run": run}
    finally:
        connection.close()


def assert_refusal(error, context):
    message = str(error)
    assert "ambient host HTTP proxy discovery" in message, f"{context}: {message}"
    assert "upgrade msb" in message, f"{context}: {message}"


async def assert_no_sandbox(name, context):
    """A refusal must not leave a provisional row (or its VM) behind."""
    from microsandbox import Sandbox

    try:
        await Sandbox.get(name)
    except Exception:  # noqa: BLE001 - any lookup failure means there is no row
        return
    raise AssertionError(f"{context}: a provisional sandbox survived the refusal")


@phase
async def phase_current_baseline():
    from microsandbox import Sandbox

    name = sandbox_name()
    sandbox = await Sandbox.create(
        name, image="alpine", memory=256, max_duration=180, proxy_from_env=False
    )
    try:
        result = await sandbox.exec("sh", ["-c", "printf baseline-ok"])
        assert result.exit_code == 0 and result.stdout_text == "baseline-ok", result
        await sandbox.stop()
        sandbox = await Sandbox.start(name)
        result = await sandbox.exec("sh", ["-c", "printf restarted-ok"])
        assert result.exit_code == 0 and result.stdout_text == "restarted-ok", result
    finally:
        # `Sandbox.remove` refuses a running sandbox, so stop first. A sandbox
        # that is already stopped (or never started) still needs removing.
        with suppress(Exception):
            await sandbox.stop()
        await Sandbox.remove(name)
    print("PASS current runtime baseline with ambient intent false", flush=True)


@phase
async def phase_pre_feature_true_refused():
    """Ambient intent against a runtime that does not advertise the capability.

    Admission runs its gates in a fixed order: the launch-contract version gate,
    then `network.http.deny_response`, then the ambient-proxy capability. The
    default `HttpConfig` enables denial responses, so on a capability-less
    runtime that earlier gate would answer a question this phase never asked;
    disabling it leaves the ambient gate as the only candidate refusal.
    """
    from microsandbox import HttpConfig, Network, Sandbox

    name = sandbox_name()
    try:
        await Sandbox.create(
            name,
            image="alpine",
            memory=256,
            max_duration=180,
            network=Network(http=HttpConfig(deny_response=False)),
            proxy_from_env=True,
            replace=True,
        )
    except Exception as error:  # noqa: BLE001 - the refusal type is SDK-wide
        message = str(error)
        if LAUNCH_CONTRACT_REJECTION in message:
            # Pre-existing, feature-agnostic refusal: it is not evidence either way
            # for ambient proxy discovery, so report it instead of passing.
            await assert_no_sandbox(name, "pre-feature create")
            print(
                "SKIP pre-feature runtime rejected by the general launch-contract gate "
                "(not this feature's gate), so the ambient refusal is unobservable: "
                f"{message}",
                flush=True,
            )
            return
        assert_refusal(error, "pre-feature create")
    else:
        raise AssertionError("the pre-feature runtime accepted ambient intent")

    # No provisional row or replacement survived the refusal.
    await assert_no_sandbox(name, "pre-feature create")
    print("PASS pre-feature machine refuses ambient intent before mutation", flush=True)


@phase
async def phase_start_running_true():
    from microsandbox import Sandbox

    sandbox = await Sandbox.create(
        sandbox_name(), image="alpine", memory=256, max_duration=300, proxy_from_env=True
    )
    try:
        result = await sandbox.exec("sh", ["-c", "printf ambient-ok"])
        assert result.exit_code == 0 and result.stdout_text == "ambient-ok", result
    finally:
        # Keep the VM running for the restart phases.
        await sandbox.detach()
    print("PASS started a VM with persisted ambient intent", flush=True)


@phase
async def phase_restart_probe():
    """A restart-backed modification and a StopThenStart restart must refuse first."""
    from microsandbox import ModificationPolicy, Sandbox

    handle = await Sandbox.get(sandbox_name())

    try:
        await handle.modify(workdir="/srv", policy=ModificationPolicy.RESTART)
    except Exception as error:  # noqa: BLE001 - refusal type is SDK-wide
        assert_refusal(error, "restart-backed modify")
    else:
        raise AssertionError("the pre-feature runtime applied the modification")

    try:
        await handle.restart()
    except Exception as error:  # noqa: BLE001
        assert_refusal(error, "StopThenStart restart")
    else:
        raise AssertionError("the pre-feature runtime restarted the sandbox")

    # The VM must still be alive and hold its data.
    sandbox = await handle.connect()
    result = await sandbox.exec("sh", ["-c", "printf still-running"])
    assert result.exit_code == 0 and result.stdout_text == "still-running", result
    print("PASS real pre-feature restart refused without stopping the VM", flush=True)


@phase
async def phase_cli_restart():
    """The CLI restart path must refuse the same saved intent before stopping."""
    cli = os.environ["AMBIENT_COMPAT_CLI"]
    environment = {
        key: os.environ[key]
        for key in ("MSB_HOME", "MSB_CONFIG_PATH", "MSB_PATH", "MSB_LIBKRUNFW_PATH")
        if key in os.environ
    }
    environment["NO_COLOR"] = "1"
    completed = subprocess.run(
        [cli, "restart", sandbox_name()],
        env=environment,
        capture_output=True,
        text=True,
        timeout=300,
    )
    output = f"{completed.stdout}\n{completed.stderr}"
    assert completed.returncode != 0, f"the CLI restart succeeded: {output}"
    assert_refusal(output, "CLI restart")
    print("PASS CLI restart refused through the pre-feature runtime", flush=True)


@phase
async def phase_stop_persisted_true():
    from microsandbox import Sandbox

    handle = await Sandbox.get(sandbox_name())
    await handle.stop()
    print("PASS stopped the persisted-true sandbox for the StartOnly case", flush=True)


@phase
async def phase_start_only_probe():
    from microsandbox import Sandbox

    handle = await Sandbox.get(sandbox_name())
    try:
        await handle.restart()
    except Exception as error:  # noqa: BLE001
        assert_refusal(error, "StartOnly restart")
    else:
        raise AssertionError("the pre-feature runtime started the sandbox")
    print("PASS StartOnly restart refused before launch", flush=True)


@phase
async def phase_cleanup():
    from microsandbox import Sandbox

    try:
        handle = await Sandbox.get(sandbox_name())
        await handle.stop()
    except Exception:  # noqa: BLE001 - already stopped or already removed
        pass
    await Sandbox.remove(sandbox_name())
    print("PASS cleanup", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--current-msb")
    parser.add_argument("--current-firmware")
    parser.add_argument("--pre-feature-machine")
    parser.add_argument("--pre-feature-firmware")
    parser.add_argument("--legacy-msb", action="append", default=[])
    parser.add_argument("--legacy-firmware", action="append", default=[])
    parser.add_argument(
        "--worker",
        action="store_true",
        help="run one phase; the parent supplies the arguments and environment",
    )
    arguments = parser.parse_args()

    if arguments.worker:
        asyncio.run(PHASES[os.environ["AMBIENT_COMPAT_PHASE"]]())
        return

    for name in (
        "current_msb",
        "current_firmware",
        "pre_feature_machine",
        "pre_feature_firmware",
    ):
        if not getattr(arguments, name):
            parser.error(f"--{name.replace('_', '-')} is required")
    if len(arguments.legacy_msb) != len(arguments.legacy_firmware):
        parser.error("--legacy-msb and --legacy-firmware must be supplied in pairs")

    name = sandbox_name()
    run = worker(__file__)
    current_home = tempfile.mkdtemp(prefix="msb-ambient-current-")
    pre_feature_home = tempfile.mkdtemp(prefix="msb-ambient-pre-")
    restart_home = tempfile.mkdtemp(prefix="msb-ambient-restart-")
    print(f"sandbox name: {name}", flush=True)

    print(
        "RUN current SDK + current runtime baseline",
        run(
            msb=arguments.current_msb,
            firmware=arguments.current_firmware,
            home=current_home,
            phase="current-baseline",
        ),
        flush=True,
    )
    print(
        "RUN current SDK + pre-feature machine, ambient true",
        run(
            msb=arguments.pre_feature_machine,
            firmware=arguments.pre_feature_firmware,
            home=pre_feature_home,
            phase="pre-feature-true-refused",
        ),
        flush=True,
    )

    # Real machine restart regression: start under the candidate runtime, then
    # apply restart work through the predecessor.
    print(
        "RUN start a running VM with persisted true",
        run(
            msb=arguments.current_msb,
            firmware=arguments.current_firmware,
            home=restart_home,
            phase="start-running-true",
        ),
        flush=True,
    )
    before = raw_state(restart_home, name)
    assert before["status"] in ("running", "Running"), before
    assert '"proxy_from_env":true' in (before["config"] or ""), before["config"]

    print(
        "RUN pre-feature modify/restart probes",
        run(
            msb=arguments.pre_feature_machine,
            firmware=arguments.pre_feature_firmware,
            home=restart_home,
            phase="restart-probe",
        ),
        flush=True,
    )
    after = raw_state(restart_home, name)
    assert after["config"] == before["config"], "desired configuration changed"
    assert after["active_config"] == before["active_config"], "active configuration changed"
    assert after["status"] == before["status"], "status changed"
    assert after["run"] == before["run"], "the live run was restarted"
    print("PASS pre-feature machine restart refused without mutation", flush=True)

    print(
        "RUN pre-feature CLI restart",
        run(
            msb=arguments.pre_feature_machine,
            firmware=arguments.pre_feature_firmware,
            home=restart_home,
            phase="cli-restart",
            extra_environment={"AMBIENT_COMPAT_CLI": arguments.current_msb},
        ),
        flush=True,
    )
    after_cli = raw_state(restart_home, name)
    assert after_cli == before, "the CLI restart mutated the sandbox"

    # StartOnly: stop under the candidate runtime, then restart through the
    # predecessor. Saved intent must survive the refusal.
    print(
        "RUN stop the persisted-true sandbox",
        run(
            msb=arguments.current_msb,
            firmware=arguments.current_firmware,
            home=restart_home,
            phase="stop-persisted-true",
        ),
        flush=True,
    )
    stopped = raw_state(restart_home, name)
    assert '"proxy_from_env":true' in (stopped["config"] or ""), stopped["config"]
    print(
        "RUN pre-feature StartOnly restart",
        run(
            msb=arguments.pre_feature_machine,
            firmware=arguments.pre_feature_firmware,
            home=restart_home,
            phase="start-only-probe",
        ),
        flush=True,
    )
    after_stop = raw_state(restart_home, name)
    assert after_stop["config"] == stopped["config"], "saved intent changed"
    assert after_stop["status"] == stopped["status"], "status changed"
    print("PASS StartOnly refusal left saved intent untouched", flush=True)

    print(
        "RUN cleanup",
        run(
            msb=arguments.current_msb,
            firmware=arguments.current_firmware,
            home=restart_home,
            phase="cleanup",
        ),
        flush=True,
    )

    for msb, firmware in zip(arguments.legacy_msb, arguments.legacy_firmware):
        legacy_home = tempfile.mkdtemp(prefix="msb-ambient-legacy-")
        print(
            f"RUN legacy endpoint {msb}",
            run(msb=msb, firmware=firmware, home=legacy_home, phase="current-baseline"),
            flush=True,
        )

    print("PASS ambient proxy compatibility qualification", flush=True)


if __name__ == "__main__":
    main()
