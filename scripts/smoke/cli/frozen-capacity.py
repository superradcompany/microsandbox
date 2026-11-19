"""Qualify freeze-time capacity and released-peer omission with live disk/full captures."""
import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import subprocess
import tempfile
import time

from lifecycle_evidence import cleanup_sandbox, environment, smoke_home


def qualify(args, case, binary, agent):
    with smoke_home("freeze-", args.temp_root) as home, ExitStack() as cleanup:
        env = environment(binary, args.firmware, home, agent)

        def run(*command, client=binary):
            result = subprocess.run(
                [client, *command], stdin=subprocess.DEVNULL, capture_output=True,
                text=True, env=env, cwd=home, timeout=150, check=False,
            )
            if result.returncode:
                raise RuntimeError(f"{command[0]} failed ({result.returncode}): {result.stderr}")
            return result.stdout.strip()

        def cut(group, *flags, client=binary):
            pattern = "last-active/captures/*.json"
            before = set(home.rglob(pattern))
            run("snap", "create", group, "--sandbox", "source", "--name", "cut", *flags, client=client)
            after = set(home.rglob(pattern)) - before
            assert len(after) == 1, f"{case}/{group} did not publish exactly one receipt"
            return json.loads(after.pop().read_bytes()).get("capacity")

        cleanup.enter_context(cleanup_sandbox(run, "source"))
        run("create", "--name", "source", "--cpus", "2", "--max-cpus", "4",
            "--memory", "512M", "--max-memory", "1G", "alpine:3.20")
        for group, flags in [("disk", ()), ("full", ("--full",))]:
            observed = cut(group, *flags)
            expected = {"cpus": {"observed": 2}, "memory_mib": {"observed": 512}} if case == "current" else None
            assert observed == expected, (case, group, observed)
            print(case, group, observed, flush=True)

        if case == "current":
            assert cut("legacy-client", client=args.previous) is None
            run("modify", "source", "--cpus", "3", "--memory", "768M")
            # Each attempt captures a new cut. Never repeat the resize as a status probe.
            deadline = time.monotonic() + 60
            attempt = 0
            while True:
                observed = cut(f"resized-{attempt}")
                if observed == {"cpus": {"observed": 3}, "memory_mib": {"observed": 768}}:
                    break
                if time.monotonic() >= deadline:
                    raise AssertionError(f"resized capacity did not converge: {observed}")
                attempt += 1
                time.sleep(0.5)
            print("after resize", observed, flush=True)
            run("pause", "source", "--guest-flush", "required")
            assert cut("paused") is None
            run("resume", "source")
        assert run("exec", "source", "--", "echo", "still-running") == "still-running"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("candidate", "previous", "firmware", "agent", "previous-agent"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--temp-root", type=Path, default=Path(tempfile.gettempdir()))
    args = parser.parse_args()
    # Guest commands execute from the disposable home. Anchor all fixture paths first.
    for name, path in vars(args).items():
        setattr(args, name, path.resolve(strict=True))
    for case, binary, agent in (
        ("current", args.candidate, args.agent),
        ("previous-guest", args.candidate, args.previous_agent),
        ("previous-host", args.previous, args.agent),
    ):
        qualify(args, case, binary, agent)
