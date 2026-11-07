"""Read-only hosted check that waits for the private controller's deletion proof."""

import os
import re
import time

from clients import attempt_jobs, request


def cleanup_expectations(jobs, run_id, attempt, revision):
    expected = set()
    for platform in (10, 11):
        lanes = [job for job in jobs if job.get("name") == f"Windows WHP ({platform})"]
        if len(lanes) != 1:
            raise ValueError("Expected one job for each Windows lane")
        job = lanes[0]
        if (job.get("run_id") != run_id or job.get("head_sha") != revision
                or job.get("status") != "completed" or job.get("conclusion") in {None, "skipped"}):
            raise ValueError("Windows lane identity or result is invalid")
        labels = job.get("labels", [])
        label = re.fullmatch(rf"msb-whp-{run_id}-([1-9][0-9]*)-win{platform}", labels[0]) if len(labels) == 1 else None
        if label is None:
            raise ValueError("Windows lane label is invalid")
        executed_attempt = int(label[1])
        if executed_attempt > attempt or (executed_attempt < attempt and job["conclusion"] != "success"):
            raise ValueError("Only a successful earlier Windows lane may be reused")
        # Partial reruns copy successful jobs into the new attempt's job list.
        # Their evaluated routing label identifies the lease that actually ran,
        # even when the copied job's run_attempt metadata names the new attempt.
        expected.add(f"windows-whp/{run_id}/{executed_attempt}/win{platform}")
    return expected


def cleanup_finished(checks, app_id, expected):
    # A workflow's GITHUB_TOKEN cannot forge the separate App's check. Match
    # each lane's executed attempt, so old cleanup cannot satisfy a retried lane.
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
    jobs = attempt_jobs(lambda method, path: request(method, base + path, headers), run_id, attempt)
    expected = cleanup_expectations(jobs, run_id, attempt, revision)
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        checks = []
        for page in range(1, 11):
            batch = request("GET", base + f"/commits/{revision}/check-runs?filter=all&per_page=100&page={page}", headers)["check_runs"]
            checks.extend(batch)
            if len(batch) < 100:
                break
        if cleanup_finished(checks, app_id, expected):
            current = request("GET", base + f"/actions/runs/{run_id}", headers)
            if current["run_attempt"] != attempt or current["head_sha"] != revision:
                raise RuntimeError("Run identity changed while waiting for cleanup")
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
