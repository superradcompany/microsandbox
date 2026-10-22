"""Shared process supervision and cleanup for lifecycle evidence harnesses."""

import hashlib
import json
import os
import signal
import subprocess
import time
import traceback


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def environment(binary, firmware, home, agent=None):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("MSB_") and key not in ("LD_PRELOAD", "DYLD_INSERT_LIBRARIES")}
    env.update(MSB_HOME=str(home), MSB_PATH=str(binary), MSB_BACKEND="local",
               MSB_CONFIG_PATH=str(home / "config.json"), MSB_LIBKRUNFW_PATH=str(firmware),
               NO_COLOR="1")
    if agent:
        env["MSB_AGENTD_PATH"] = str(agent)
    return env


def install_termination_handler():
    def terminate(signum, _frame):
        # Unwind once through process/VM cleanup. A second TERM must not interrupt
        # that cleanup; a supervisor can still enforce its hard-kill deadline.
        signal.signal(signum, signal.SIG_IGN)
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, terminate)


class Runner:
    def __init__(self, binary, env, output):
        self.binary, self.env, self.output = binary, env, output
        self.commands = []
        output.mkdir(parents=True, exist_ok=True)

    def run(self, label, *args, required=True):
        start = time.monotonic()
        command = [str(self.binary), *map(str, args)]
        # Bound each supervisor and reap its owned process group on interruption.
        # Persistent VMs have a separate lifecycle and are stopped in finally below.
        # No fixture command is interactive: never let a CLI consume the SSH shell
        # script from inherited stdin and silently skip the remaining matrix.
        row = {"label": label, "command": command, "exit": None}
        try:
            with (self.output / f"{label}.stdout").open("w") as stdout, (self.output / f"{label}.stderr").open("w") as stderr:
                with subprocess.Popen(command, env=self.env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                      start_new_session=True) as child:
                    try:
                        row["exit"] = child.wait(timeout=180)
                    except BaseException:
                        try:
                            os.killpg(child.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass  # The command exited between interruption and kill.
                        row["exit"] = child.wait()
                        raise
        except BaseException as error:
            row["error"], row["error_type"] = str(error), type(error).__name__
            raise
        finally:
            row["seconds"] = round(time.monotonic() - start, 3)
            self.commands.append(row)
            (self.output / "commands.json").write_text(json.dumps(self.commands, indent=2) + "\n")
        code = row["exit"]
        print(f"{label}: exit {code}", flush=True)
        if required and code:
            raise RuntimeError(f"{label} failed; see {self.output / (label + '.stderr')}")
        return code


def cleanup(runner, prefix, sandbox, result=None, force=False):
    """Attempt both lifecycle operations before propagating an interruption."""
    result = {} if result is None else result
    interrupted = None
    for operation in ("stop", "rm"):
        try:
            options = ["--force"] if force and operation == "stop" else []
            result[operation] = runner.run(prefix + "-cleanup-" + operation,
                                           operation, *options, sandbox, required=False)
        except BaseException as error:
            result[operation] = str(error)
            if not isinstance(error, Exception):
                interrupted = error
    if interrupted is not None:
        raise interrupted
    return result


def finish_saved_evidence(runner, targets, row, report, output, audit, force=False, prepare=None):
    """Finish every cleanup target and save failure evidence before propagating a signal.

    Callers install each result dictionary in their report before passing it here, so
    an interruption cannot discard partial stop/remove results. Audit remains separate
    from command success: a zero exit alone does not prove that a VM was removed.
    """
    interrupted = None
    try:
        if prepare is not None:
            try:
                prepare()
            except BaseException as error:
                row.update(status="failed", cleanup_error=traceback.format_exc())
                report["status"] = "failed"
                if not isinstance(error, Exception):
                    interrupted = error
        for name, result in targets.items():
            try:
                cleanup(runner, "final-" + name, name, result, force=force)
            except BaseException as error:
                row.update(status="failed", cleanup_error=traceback.format_exc())
                report["status"] = "failed"
                if not isinstance(error, Exception):
                    interrupted = error
            if any(value != 0 for value in result.values()):
                row["status"] = report["status"] = "failed"
        try:
            audit()
        except BaseException as error:
            row.update(status="failed", cleanup_error=traceback.format_exc())
            report["status"] = "failed"
            if not isinstance(error, Exception):
                interrupted = error
    finally:
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    if interrupted is not None:
        raise interrupted
