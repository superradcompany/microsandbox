"""Read-only hosted check that waits for the private controller's deletion proof."""

import os
import re
import time

from clients import request


def cleanup_finished(checks, app_id, expected):
    # A workflow's GITHUB_TOKEN cannot forge the separate App's check. Match
    # the run attempt too, so a prior green cleanup cannot satisfy a retry.
    found = {}
    for check in checks:
        identity = check.get("external_id")
        if identity in expected and str(check.get("app", {}).get("id")) == str(app_id):
            if identity not in found or check["id"] > found[identity]["id"]:
                found[identity] = check
    for check in found.values():
        if check["status"] == "completed" and check["conclusion"] != "success":
            raise RuntimeError("Windows infrastructure check failed")
    return set(found) == expected and all(check["status"] == "completed" for check in found.values())


def main():
    repository = os.environ["GITHUB_REPOSITORY"]
    run_id, attempt = int(os.environ["GITHUB_RUN_ID"]), int(os.environ["GITHUB_RUN_ATTEMPT"])
    app_id = int(os.environ["WINDOWS_CI_APP_ID"])
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", repository) or min(run_id, attempt, app_id) <= 0:
        raise ValueError("Invalid check identity")
    headers = {"Authorization": "Bearer " + os.environ["GH_TOKEN"], "Accept": "application/vnd.github+json"}
    base = "https://api.github.com/repos/" + repository
    run = request("GET", base + f"/actions/runs/{run_id}", headers)
    if run["run_attempt"] != attempt:
        raise RuntimeError("Run attempt changed")
    revision = run["head_sha"]
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Invalid revision")
    expected = {f"windows-whp/{run_id}/{attempt}/win{platform}" for platform in (10, 11)}
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        checks = []
        for page in range(1, 11):
            batch = request("GET", base + f"/commits/{revision}/check-runs?filter=all&per_page=100&page={page}", headers)["check_runs"]
            checks.extend(batch)
            if len(batch) < 100:
                break
        if cleanup_finished(checks, app_id, expected):
            print("PASS: both disposable Windows runners and all job resources were deleted")
            return
        time.sleep(15)
    raise TimeoutError("Deletion was not confirmed before the deadline")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # API exceptions may include private diagnostics. The App's check and
        # control-plane logs distinguish setup failures from delayed deletion.
        print("FAIL: Windows infrastructure cleanup was not confirmed; inspect its checks")
        raise SystemExit(1)
