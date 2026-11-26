#!/usr/bin/env python3
"""Exercise command admission on a real restored disk with candidate and older CLI/runtime pairs."""

import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import subprocess

from lifecycle_evidence import cleanup_sandbox, environment, install_termination_handler, smoke_home


def qualify(candidate, previous, firmware, home):
    env = environment(candidate, firmware, home)
    # Keep sparse-disk and image extraction temporaries on the same test volume.
    env.update(TMPDIR=str(home), TMP=str(home), TEMP=str(home))

    def run(*args, cli=candidate, runtime=candidate, refusal=None):
        result = subprocess.run(
            [cli, *args], env=dict(env, MSB_PATH=str(runtime)), cwd=home, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=150,
        )
        if refusal is None:
            if result.returncode:
                raise RuntimeError(f"{args!r} exited {result.returncode}: {result.stderr}")
        elif result.returncode == 0 or refusal not in (result.stderr + result.stdout).lower():
            raise RuntimeError(f"{args!r} expected refusal {refusal!r}: {result.stderr}")
        return result.stdout.strip()

    with cleanup_sandbox(run, "source"):
        run("create", "--name", "source", "alpine:3.20")
        run("exec", "source", "--", "sh", "-ec", "echo captured >/root/source")
        run("snapshot", "create", "history", "--sandbox", "source")
        with cleanup_sandbox(run, "restored"):
            run("create", "--from-snapshot", "history", "--name", "restored")
            if run("exec", "restored", "--", "cat", "/root/source") != "captured":
                raise RuntimeError("restored disk lost the source file")
            run("stop", "restored")

            # Until ordinary capture publishes portable configuration, seed only the
            # private admission row. Rust reservation tests cover its transactional writer.
            ddl = Path(__file__).resolve().parents[3] / "crates/runtime/lib/client/command_bindings.sql"
            with closing(sqlite3.connect(home / "db/msb.db")) as catalog, catalog:
                catalog.executescript(ddl.read_text())
                sandbox_id, = catalog.execute("SELECT id FROM sandbox WHERE name='restored'").fetchone()
                policy = {"env": {"TOKEN": "token"}, "entrypoint": [], "cmd": ["argv"]}
                catalog.execute("INSERT INTO sandbox_command_bindings(sandbox_id, requirements) VALUES (?, ?)",
                                (sandbox_id, json.dumps(policy)))

            run("start", "restored", cli=previous, runtime=previous, refusal="outstanding command bindings")
            run("start", "restored", cli=previous)
            for cli, options in ((previous, ["-e", "TOKEN=x"]), (candidate, [])):
                for mode in ([], ["-d"]):
                    run("exec", "restored", *mode, *options, "--", "touch", "/tmp/refused",
                        cli=cli, refusal="binding")
            if json.loads(run("jobs", "restored", "--all", "--format", "json"))["items"]:
                raise RuntimeError("a refused command left a registered job")

            run("exec", "restored", "-e", "TOKEN=x", refusal="entrypoint")
            run("exec", "restored", "-e", "TOKEN=x", "--", "sh", "-ec",
                'test ! -e /tmp/refused && test "$TOKEN" = x')
            job = run("exec", "restored", "-d", "-e", "TOKEN=", "--", "sh", "-ec",
                      'test "${TOKEN-unset}" = "" && touch /tmp/approved')
            run("wait", "restored", "--job", job, "--timeout", "30s")
            run("exec", "restored", "-e", "TOKEN=x", "--", "test", "-f", "/tmp/approved")
            run("exec", "source", "--", "test", "-f", "/root/source", cli=previous)
            run("stop", "restored")
            run("start", "restored")
            run("exec", "restored", "--", "touch", "/tmp/refused", cli=previous, refusal="binding")
            run("exec", "restored", "-e", "TOKEN=x", "--", "test", "!", "-e", "/tmp/refused")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("candidate", "previous", "firmware"):
        parser.add_argument("--" + flag, type=Path, required=True)
    parser.add_argument("--temp-root", type=Path)
    args = parser.parse_args()
    install_termination_handler()
    with smoke_home("bg-", args.temp_root) as home:
        qualify(args.candidate.resolve(), args.previous.resolve(), args.firmware.resolve(), home)
    print("Passed restored-disk command admission, job admission, legacy runtime refusal and restart.")
