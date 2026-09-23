"""Live two-vCPU restore with CPU1 intentionally offline, then onlined again.

Set MSB_PATH, MSB_HOME, MSB_LIBKRUNFW_PATH, CPU_PROBE (guest-architecture
checkpoint CPU fixture), CPU_PREFIX (unique), and CPU_OUT. This requires a
guest with CPU hotplug enabled; unsupported hotplug is a failure, not a pass.
"""
import json
import os
from pathlib import Path
import subprocess
import time

binary = os.environ["MSB_PATH"]
out = Path(os.environ["CPU_OUT"])
out.mkdir(parents=True, exist_ok=True)
prefix = os.environ["CPU_PREFIX"]
source, child = prefix + "-source", prefix + "-child"
rows = []


def run(label, *args, check=True):
    started = time.perf_counter()
    result = subprocess.run([binary, *args], capture_output=True, timeout=90)
    (out / (label + ".stdout")).write_bytes(result.stdout)
    (out / (label + ".stderr")).write_bytes(result.stderr)
    row = {"case": label, "ms": round((time.perf_counter() - started) * 1000, 2), "exit": result.returncode}
    rows.append(row)
    print(json.dumps(row), flush=True)
    if check and result.returncode:
        raise RuntimeError(f"{label}: {result.stderr.decode(errors='replace')}")
    return result.stdout.strip()


try:
    run("create", "create", "alpine", "-n", source, "--root-disk", "flat:512M", "--memory", "256M", "--cpus", "2")
    run("marker", "exec", source, "--", "sh", "-c", "echo captured > /dev/shm/cow-marker")
    run("copy-probe", "copy", os.environ["CPU_PROBE"], source + ":/cpu-probe")
    run("chmod", "exec", source, "--", "chmod", "+x", "/cpu-probe")
    run("cpu1-before", "exec", source, "--", "/cpu-probe", "1")
    run("offline", "exec", source, "--", "sh", "-c", "echo 0 > /sys/devices/system/cpu/cpu1/online")
    assert run("offline-before", "exec", source, "--", "cat", "/sys/devices/system/cpu/cpu1/online") == b"0"
    run("capture", "snapshot", "create", prefix + "-full", "--from-sandbox", source, "--full", "--info")
    run("restore", "create", "-n", child, "--from-snapshot", prefix + "-full",
        *(["--forked"] if os.environ.get("CPU_FORKED") == "1" else []), "--info")
    assert run("offline-after", "exec", child, "--", "cat", "/sys/devices/system/cpu/cpu1/online") == b"0"
    run("cpu0-restored", "exec", child, "--", "/cpu-probe", "0")
    run("online", "exec", child, "--", "sh", "-c", "echo 1 > /sys/devices/system/cpu/cpu1/online")
    run("cpu1-restored", "exec", child, "--", "/cpu-probe", "1")
finally:
    for name in (child, source):
        try:
            run("cleanup-" + name, "stop", name, check=False)
        except Exception as error:
            rows.append({"case": "cleanup-" + name, "error": str(error)})
    (out / "results.json").write_text(json.dumps(rows, indent=2))
