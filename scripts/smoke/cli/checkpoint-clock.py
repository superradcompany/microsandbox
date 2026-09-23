"""Cross-platform host runner for the static Linux guest clock fixture.

Requires MSB_PATH, MSB_HOME, MSB_LIBKRUNFW_PATH, CLOCK_PROBE, CLOCK_OUT,
and a unique CLOCK_PREFIX. Never reuses an existing sandbox or snapshot.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

binary = os.environ["MSB_PATH"]
out = Path(os.environ["CLOCK_OUT"])
out.mkdir(parents=True, exist_ok=True)
prefix = os.environ["CLOCK_PREFIX"]
source, child, snapshot = prefix + "-source", prefix + "-child", prefix + "-full"
rows = []


def run(label, *args, check=True, timeout=120):
    started = time.perf_counter()
    result = subprocess.run([binary, *args], capture_output=True, timeout=timeout)
    (out / (label + ".stdout")).write_bytes(result.stdout)
    (out / (label + ".stderr")).write_bytes(result.stderr)
    row = {"case": label, "ms": round((time.perf_counter() - started) * 1000, 2), "exit": result.returncode}
    rows.append(row)
    print(json.dumps(row), flush=True)
    if check and result.returncode:
        raise RuntimeError(f"{label}: {result.stderr.decode(errors='replace')}")
    return result


try:
    run("create", "run", "-d", "-n", source,
        "--root-disk", os.environ.get("CLOCK_LAYOUT", "flat:512M"),
        "--cpus", os.environ.get("CLOCK_CPUS", "2"), "--memory", "256M",
        "alpine", "--", "sh", "-c",
        "while [ ! -x /clock-probe ]; do sleep 0.05; done; exec /clock-probe")
    run("copy-probe", "copy", os.environ["CLOCK_PROBE"], source + ":/clock-probe")
    run("chmod-probe", "exec", source, "--", "chmod", "+x", "/clock-probe")
    for attempt in range(30):
        if run("ready-" + str(attempt), "exec", source, "--", "test", "-s", "/tmp/clock-records.csv", check=False).returncode == 0:
            break
        time.sleep(0.05)
    else:
        raise RuntimeError("guest clock fixture did not start")
    run("capture", "snapshot", "create", snapshot, "--from-sandbox", source, "--full", "--info")
    if os.environ.get("CLOCK_INCREMENTAL") == "1":
        snapshot = prefix + "-next"
        run("capture-next", "snapshot", "create", snapshot, "--from-sandbox", source, "--full", "--info")
    if os.environ.get("CLOCK_ARCHIVE") == "1":
        archive = str(out / "clock.msb")
        run("archive", "snapshot", "save", snapshot, archive)
        snapshot = archive
    run("stop-source", "stop", source)
    time.sleep(float(os.environ.get("CLOCK_DELAY", "8")))
    (out / "restore-start.ns").write_text(str(time.time_ns()))
    run("restore", "create", "-n", child, "--from-snapshot", snapshot,
        *(["--forked"] if os.environ.get("CLOCK_FORKED") == "1" else []), "--info")
    (out / "restore-end.ns").write_text(str(time.time_ns()))
    time.sleep(6)
    records = run("records", "exec", child, "--", "cat", "/tmp/clock-records.csv")
    (out / "records.csv").write_bytes(records.stdout)
    subprocess.run([sys.executable, str(Path(__file__).with_name("checkpoint-clock-analyze.py")), str(out)], check=True)
finally:
    for name in (child, source):
        try:
            run("cleanup-" + name, "stop", name, check=False, timeout=20)
        except Exception as error:
            rows.append({"case": "cleanup-" + name, "error": str(error)})
    (out / "results.json").write_text(json.dumps(rows, indent=2))
