"""Control-plane clients. These credentials never enter a worker artifact."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

from models import Lease, utc


class ApiError(Exception):
    def __init__(self, status):
        # URLs and response bodies may carry infrastructure details. Keep them
        # out of exceptions that an SDK or function host might log automatically.
        super().__init__(f"API status {status}")
        self.status = status


def request(method, url, headers, body=None, missing=False):
    data = None if body is None else json.dumps(body).encode()
    headers = {**headers, "Content-Type": "application/json"}
    try:
        # Never forward a control-plane Authorization header through a redirect.
        opener = urllib.request.build_opener(NoRedirect())
        with opener.open(urllib.request.Request(url, data, headers, method=method), timeout=15) as response:
            raw = response.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        if missing and error.code == 404:
            return None
        raise ApiError(error.code) from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, url):
        return None


def attempt_jobs(call, run_id, attempt):
    # Large job pages can return HTTP 502 for reruns with copied job histories.
    # Use GitHub's default page size while retaining a bounded, complete scan.
    jobs = []
    for page in range(1, 35):
        batch = call("GET", f"/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=30&page={page}")["jobs"]
        jobs.extend(batch)
        if len(batch) < 30:
            return jobs
    raise RuntimeError("Could not inspect every job in the attempt")


class Azure:
    def __init__(self, credential):
        self.credential = credential

    def call(self, method, path, body=None, missing=False, version=None):
        if not path.startswith("/subscriptions/"):
            raise ValueError("Azure resource path required")
        if version is None:
            # Managed disks have a separate API release train from VMs and
            # Run Commands, despite sharing the Microsoft.Compute provider.
            if "/microsoft.network/" in path.lower():
                version = "2024-10-01"
            elif "/microsoft.compute/disks/" in path.lower():
                version = "2025-01-02"
            else:
                version = "2025-04-01"
        query = "&" if "?" in path else "?"
        token = self.credential.get_token("https://management.azure.com/.default").token
        return request(method, "https://management.azure.com" + path + query + "api-version=" + version,
                       {"Authorization": "Bearer " + token}, body, missing)


class GitHub:
    def __init__(self, cfg, token_provider):
        self.cfg = cfg
        self.token_provider = token_provider

    def call(self, method, path, body=None, missing=False):
        return request(method, "https://api.github.com/repos/" + self.cfg.repository + path,
                       {"Authorization": "Bearer " + self.token_provider(), "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}, body, missing)

    def job(self, lease):
        return self.call("GET", f"/actions/jobs/{lease.job_id}", missing=True)

    def queued(self):
        policy = self.call("GET", "/actions/permissions/fork-pr-contributor-approval")["approval_policy"]
        # GitHub returns the workflow to queued when all remaining jobs await
        # runners. Poll both states, deduplicating transitions between requests.
        runs = {}
        for status in ("queued", "in_progress"):
            for page in range(1, 11):
                batch = self.call("GET", f"/actions/workflows/{self.cfg.workflow_id}/runs?status={status}&per_page=100&page={page}")["workflow_runs"]
                runs.update({run["id"]: run for run in batch})
                if len(batch) < 100:
                    break
            else:
                # Filtered workflow searches expose at most 1,000 results.
                # Refuse an incomplete scan instead of silently starving older
                # jobs; existing lease progress and cleanup run before discovery.
                raise RuntimeError("Could not inspect every workflow run")
        for run in sorted(runs.values(), key=lambda item: item["id"]):
            jobs = attempt_jobs(self.call, run["id"], run["run_attempt"])
            fork = (run.get("head_repository") or {}).get("full_name") != self.cfg.repository
            if fork and not any(
                job.get("name") == "Build Windows CLI (windows-x86_64)"
                and job.get("status") == "completed" and job.get("conclusion") == "success"
                and job.get("run_id") == run["id"] and job.get("head_sha") == run["head_sha"]
                and job.get("runner_id", 0) > 0 and job.get("labels") == ["windows-latest"]
                for job in jobs
            ):
                # An unapproved fork must not acquire a VM just because a job
                # appears queued. Its hosted prerequisite must have run first.
                # The attempt-specific endpoint also prevents borrowing evidence
                # from a different run or revision.
                continue
            for job in jobs:
                if job["status"] == "queued":
                    yield run, job, policy

    def create_check(self, lease):
        name = f"Windows {lease.platform[3:]} WHP infrastructure"
        existing = self.call("GET", f"/commits/{lease.revision}/check-runs?check_name=" + urllib.parse.quote(name) + "&per_page=100")
        for check in existing["check_runs"]:
            if check.get("external_id") == lease.external_id and str(check.get("app", {}).get("id")) == os.environ.get("GITHUB_APP_ID"):
                return check["id"]
        return self.call("POST", "/check-runs", {"name": name, "head_sha": lease.revision,
            "external_id": lease.external_id, "status": "in_progress", "started_at": utc(lease.created),
            "details_url": f"https://github.com/{self.cfg.repository}/actions/runs/{lease.run_id}/job/{lease.job_id}",
            "output": {"title": "Provisioning a disposable Windows runner", "summary": "A fresh VM is allocated for this job and deleted after it finishes."}})["id"]

    def complete_check(self, lease):
        self.call("PATCH", f"/check-runs/{lease.check_id}", {"status": "completed", "completed_at": utc(time.time()), "conclusion": lease.conclusion,
            "output": {"title": "Windows runner lifecycle finished", "summary": lease.reason}})

    def cancel(self, lease):
        try:
            self.call("POST", f"/actions/runs/{lease.run_id}/cancel")
        except ApiError as error:
            if error.status not in {404, 409}:  # Deleted or already completed/cancelled.
                raise

    def jit(self, lease):
        # JIT credentials can admit one job only. A reusable, hour-long runner
        # registration token is never copied onto an untrusted worker.
        return self.call("POST", "/actions/runners/generate-jitconfig", {"name": lease.name, "runner_group_id": self.cfg.runner_group_id,
            "labels": lease.labels, "work_folder": "_work"})

    def remove_runner(self, lease):
        # A successful JIT POST can lose its response before runner_id is saved.
        # The name is derived from the leased job ID, never a guest-supplied
        # prefix. Collect every exact match before deleting, so pagination cannot
        # skip registrations as the list shrinks.
        runner_ids = set()
        for page in range(1, 11):
            batch = self.call("GET", f"/actions/runners?per_page=100&page={page}")["runners"]
            runner_ids.update(runner["id"] for runner in batch if runner.get("name") == lease.name)
            if len(batch) < 100:
                break
        else:
            raise RuntimeError("Could not inspect every runner registration")
        if lease.runner_id:
            saved = self.call("GET", f"/actions/runners/{lease.runner_id}", missing=True)
            if saved is not None:
                if saved.get("name") != lease.name:
                    raise RuntimeError("Saved runner identity does not match its lease")
                runner_ids.add(lease.runner_id)
        for runner_id in runner_ids:
            self.call("DELETE", f"/actions/runners/{runner_id}", missing=True)
        # Keep the durable lease (and block a new JIT registration) until GitHub
        # confirms deletion, just as Azure resource cleanup requires absence.
        for runner_id in runner_ids:
            if self.call("GET", f"/actions/runners/{runner_id}", missing=True) is not None:
                raise RuntimeError("Runner registration deletion is pending")


class AppToken:
    def __init__(self):
        self.value = None
        self.expires = 0

    def __call__(self):
        if time.time() < self.expires:
            return self.value
        import jwt

        now = int(time.time())
        bearer = jwt.encode({"iat": now - 60, "exp": now + 540, "iss": os.environ["GITHUB_APP_ID"]},
                            os.environ["GITHUB_APP_PRIVATE_KEY"], algorithm="RS256")
        response = request("POST", "https://api.github.com/app/installations/" + os.environ["GITHUB_INSTALLATION_ID"] + "/access_tokens",
                           {"Authorization": "Bearer " + bearer, "Accept": "application/vnd.github+json"},
                           {"repositories": [os.environ["WINDOWS_CI_REPOSITORY"].split("/")[1]],
                            "permissions": {"administration": "write", "actions": "write", "checks": "write"}})
        self.value = response["token"]
        self.expires = time.time() + 3000
        return self.value


class BlobLeases:
    def __init__(self):
        from azure.storage.blob import BlobServiceClient
        from azure.core.exceptions import ResourceExistsError

        self.container = BlobServiceClient.from_connection_string(os.environ["AzureWebJobsStorage"]).get_container_client("windows-ci-leases")
        try:
            self.container.create_container()
        except ResourceExistsError:
            # Reuse the existing lease container on later initializations.
            # Only "already exists" is expected; other storage errors propagate.
            pass

    def list(self):
        return [Lease(**json.loads(self.container.download_blob(blob.name).readall())) for blob in self.container.list_blobs()]

    def save(self, lease):
        self.container.upload_blob(str(lease.job_id) + ".json", json.dumps(lease.to_dict()), overwrite=True)

    def delete(self, lease):
        self.container.delete_blob(str(lease.job_id) + ".json")
