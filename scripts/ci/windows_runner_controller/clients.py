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
        runs = self.call("GET", f"/actions/workflows/{self.cfg.workflow_id}/runs?status=in_progress&per_page=100")["workflow_runs"]
        for run in reversed(runs):
            for page in range(1, 11):
                jobs = self.call("GET", f'/actions/runs/{run["id"]}/attempts/{run["run_attempt"]}/jobs?per_page=100&page={page}')["jobs"]
                for job in jobs:
                    if job["status"] == "queued":
                        yield run, job, policy
                if len(jobs) < 100:
                    break

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
        if lease.runner_id:
            self.call("DELETE", f"/actions/runners/{lease.runner_id}", missing=True)


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
            pass

    def list(self):
        return [Lease(**json.loads(self.container.download_blob(blob.name).readall())) for blob in self.container.list_blobs()]

    def save(self, lease):
        self.container.upload_blob(str(lease.job_id) + ".json", json.dumps(lease.to_dict()), overwrite=True)

    def delete(self, lease):
        self.container.delete_blob(str(lease.job_id) + ".json")
