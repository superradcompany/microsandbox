"""One fresh VM per approved job, with cleanup independent of the job process."""

from __future__ import annotations

import base64
import logging
from pathlib import Path
import secrets
import time

from clients import ApiError
from models import OWNER_TAG, candidate, timestamp

FILES = Path(__file__).parent


def reap_expired_resources(cfg, azure, now):
    """Independent tag-based expiry, even if lease storage or GitHub is down."""
    resources = azure.call("GET", cfg.scope + "/resources", version="2021-04-01")["value"]
    suffixes = {"microsoft.compute/virtualmachines": "", "microsoft.compute/disks": "-os",
                "microsoft.network/networkinterfaces": "-nic", "microsoft.network/publicipaddresses": "-ip"}
    for resource in resources:
        tags = resource.get("tags") or {}
        kind = resource["type"].lower()
        if tags.get("managed-by") != OWNER_TAG or kind not in suffixes:
            continue
        try:
            job_id = int(tags["job-id"])
            expected = f"wci-{job_id}" + suffixes[kind]
            expected_id = cfg.scope + "/providers/" + resource["type"] + "/" + expected
            if job_id <= 0 or resource["name"] != expected or resource["id"].lower() != expected_id.lower():
                continue
            if timestamp(tags["expires-at"]) <= now:
                azure.call("DELETE", expected_id, missing=True)
        except (ApiError, KeyError, ValueError) as error:
            logging.warning("Expired-resource cleanup deferred (%s)", type(error).__name__)


class Controller:
    def __init__(self, cfg, azure, github, leases, clock=time.time):
        self.cfg, self.azure, self.github, self.leases, self.clock = cfg, azure, github, leases, clock

    def command(self, lease, name, script, protected=None):
        path = lease.resource_ids(self.cfg)[0] + "/runCommands/" + name
        command = self.azure.call("GET", path + "?$expand=instanceView", missing=True)
        if command is None:
            self.azure.call("PUT", path, {"location": self.cfg.location, "properties": {
                "source": {"script": script}, "asyncExecution": True, "timeoutInSeconds": 1200,
                "protectedParameters": [{"name": key, "value": value} for key, value in (protected or {}).items()],
            }})
            return False
        view = command.get("properties", {}).get("instanceView", {})
        if view.get("executionState") in {"Failed", "TimedOut", "Canceled"}:
            raise BootstrapFailure()
        if view.get("executionState") == "Succeeded":
            if view.get("exitCode", 1) != 0:
                raise BootstrapFailure()
            return True
        return False

    def delete_command(self, lease, name):
        path = lease.resource_ids(self.cfg)[0] + "/runCommands/" + name
        if self.azure.call("GET", path, missing=True) is None:
            return True
        self.azure.call("DELETE", path, missing=True)
        return False

    def create(self, lease):
        vm_id, disk_id, nic_id, ip_id = lease.resource_ids(self.cfg)
        ip = self.azure.call("GET", ip_id, missing=True)
        if ip is None:
            self.azure.call("PUT", ip_id, {"location": self.cfg.location, "tags": lease.tags, "sku": {"name": "Standard"},
                "properties": {"publicIPAllocationMethod": "Static", "publicIPAddressVersion": "IPv4"}})
            return False
        if ip["properties"].get("provisioningState") != "Succeeded":
            return False
        nic = self.azure.call("GET", nic_id, missing=True)
        if nic is None:
            self.azure.call("PUT", nic_id, {"location": self.cfg.location, "tags": lease.tags, "properties": {
                "ipConfigurations": [{"name": "primary", "properties": {"privateIPAllocationMethod": "Dynamic",
                    "subnet": {"id": self.cfg.subnet_id}, "publicIPAddress": {"id": ip_id}}}]}})
            return False
        if nic["properties"].get("provisioningState") != "Succeeded":
            return False
        vm = self.azure.call("GET", vm_id, missing=True)
        if vm is None:
            # Every lease gets a new disk from a pinned Marketplace or clean
            # builder image. Never attach or capture a previous job's disk.
            self.azure.call("PUT", vm_id, {"location": self.cfg.location, "tags": lease.tags, "properties": {
                "hardwareProfile": {"vmSize": "Standard_D4s_v5"},
                "osProfile": {"computerName": "whp-" + lease.platform, "adminUsername": "ciadmin",
                    "adminPassword": "Aa1!" + secrets.token_urlsafe(36),
                    "windowsConfiguration": {"provisionVMAgent": True, "enableAutomaticUpdates": True}},
                "storageProfile": {"imageReference": self.cfg.images[lease.platform], "osDisk": {
                    "name": lease.name + "-os", "createOption": "FromImage", "diskSizeGB": 256,
                    "caching": "ReadWrite", "managedDisk": {"storageAccountType": "StandardSSD_LRS"}, "deleteOption": "Delete"}},
                "securityProfile": {"securityType": "Standard"}, "licenseType": "Windows_Client",
                "networkProfile": {"networkInterfaces": [{"id": nic_id, "properties": {"primary": True, "deleteOption": "Delete"}}]},
            }})
            return False
        if vm["properties"].get("provisioningState") == "Failed":
            raise BootstrapFailure()
        if vm["properties"].get("provisioningState") != "Succeeded":
            return False
        if (vm.get("identity") or {}).get("type", "None") != "None":
            raise BootstrapFailure()
        disk = self.azure.call("GET", disk_id, missing=True)
        if disk and disk.get("tags") != lease.tags:
            self.azure.call("PATCH", disk_id, {"tags": lease.tags})
        return self.ready(lease)

    def ready(self, lease):
        view = self.azure.call("GET", lease.resource_ids(self.cfg)[0] + "/instanceView")
        return any(item.get("code") == "ProvisioningState/succeeded" for item in view.get("vmAgent", {}).get("statuses", []))

    def prepared_image(self, lease):
        # Read the VM's actual source, not today's config: an image rollout
        # must not skip bootstrap on a Marketplace VM already being created.
        vm = self.azure.call("GET", lease.resource_ids(self.cfg)[0])
        image = vm["properties"]["storageProfile"]["imageReference"]
        if "id" not in image:
            return False
        if not self.cfg.prepared_image({"id": image["id"]}):
            raise BootstrapFailure()
        return True

    def fail(self, lease, reason, conclusion="failure"):
        lease.phase, lease.conclusion, lease.reason = "cleanup", conclusion, reason
        self.leases.save(lease)

    def cleanup(self, lease):
        # Destruction comes first. GitHub downtime must not prevent resource
        # deletion after cancellation, timeout, a failed bootstrap, or a crash.
        remaining = False
        for resource in lease.resource_ids(self.cfg):
            try:
                if self.azure.call("GET", resource, missing=True) is not None:
                    self.azure.call("DELETE", resource, missing=True)
                    remaining = True
            except Exception as error:
                logging.warning("Resource deletion deferred (%s)", type(error).__name__)
                remaining = True
        # Cancelling a stranded queue must not depend on Azure deletion being
        # immediately available. Cleanup remains durable and is retried later.
        if lease.conclusion in {"failure", "timed_out"}:
            self.github.cancel(lease)
        if remaining:
            return
        self.github.remove_runner(lease)
        if lease.check_id:
            self.github.complete_check(lease)
        self.leases.delete(lease)

    def advance(self, lease):
        # Persist each completed transition before continuing. Pending Azure
        # work still yields immediately, but completed stages need no timer wait.
        for _ in range(12):
            previous = lease.phase
            if self.clock() >= lease.expires:
                self.fail(lease, "Windows runner expired during setup.", "timed_out")
                return
            self.advance_once(lease)
            if lease.phase == previous or lease.phase in {"running", "cleanup"}:
                return
        raise RuntimeError("Runner setup exceeded its transition bound")

    def advance_once(self, lease):
        if lease.phase == "create" and self.create(lease):
            lease.phase = "prepare" if self.prepared_image(lease) else "bootstrap"
        elif lease.phase == "bootstrap":
            if self.command(lease, "bootstrap", (FILES / "bootstrap.ps1").read_text(),
                            {"PublicKey": self.cfg.public_key, "SshSource": self.cfg.ssh_source}):
                lease.phase = "restart"
        elif lease.phase == "restart":
            self.azure.call("POST", lease.resource_ids(self.cfg)[0] + "/restart")
            lease.phase = "wait-reboot"
            lease.ready_after = self.clock() + 90
        elif lease.phase == "wait-reboot" and self.clock() >= lease.ready_after and self.ready(lease):
            lease.phase = "prepare"
        elif lease.phase == "prepare":
            files = {"Probe": base64.b64encode((FILES / "windows-whp-preflight.ps1").read_bytes()).decode(),
                     "Launcher": base64.b64encode((FILES / "RunnerLauncher.cs").read_bytes()).decode()}
            if self.prepared_image(lease):
                files.update({"ImagePlatform": lease.platform, "PublicKey": self.cfg.public_key,
                              "SshSource": self.cfg.ssh_source})
            if self.command(lease, "prepare", (FILES / "prepare.ps1").read_text(), files):
                lease.phase = "clear-bootstrap"
        elif lease.phase == "clear-bootstrap":
            if self.delete_command(lease, "bootstrap") and self.delete_command(lease, "prepare"):
                lease.phase = "jit"
        elif lease.phase == "jit":
            path = lease.resource_ids(self.cfg)[0] + "/runCommands/credentials"
            if self.azure.call("GET", path, missing=True) is not None:
                lease.phase = "jit-staged"
            else:
                # A crash after JIT creation but before staging loses the
                # single-use config. Remove that exact orphan and issue a new one.
                self.github.remove_runner(lease)
                result = self.github.jit(lease)
                lease.runner_id = result["runner"]["id"]
                self.leases.save(lease)
                self.command(lease, "credentials", (FILES / "stage-jit.ps1").read_text(), {"JitConfig": result["encoded_jit_config"]})
                lease.phase = "jit-staged"
        elif lease.phase == "jit-staged":
            if self.command(lease, "credentials", (FILES / "stage-jit.ps1").read_text()):
                lease.phase = "clear-credentials"
        elif lease.phase == "clear-credentials":
            if self.delete_command(lease, "credentials"):
                lease.phase = "start"
        elif lease.phase == "start":
            if self.command(lease, "start", "$ErrorActionPreference='Stop'; Start-Service WindowsCiRunner; Write-Output 'Runner started'"):
                lease.phase = "running"
        self.leases.save(lease)

    def tick(self):
        now = self.clock()
        leases = self.leases.list()
        # This pass has no dependency on GitHub or on a functioning runner.
        # An expired lease always enters cleanup, even if admission is disabled.
        for lease in leases:
            try:
                if now >= lease.expires and lease.phase != "cleanup":
                    self.fail(lease, "Windows runner expired. Its VM, disk, and networking resources were deleted.", "timed_out")
                if lease.phase == "cleanup":
                    self.cleanup(lease)
            except Exception as error:
                logging.warning("Runner cleanup deferred (%s)", type(error).__name__)
        leases = self.leases.list()
        for lease in leases:
            if lease.phase == "cleanup":
                continue
            try:
                job = self.github.job(lease)
                if job is None or job["status"] == "completed":
                    self.fail(lease, "Runner VM, disk, and networking resources were deleted after the job ended.", "success")
                    self.cleanup(lease)
                    continue
                if not lease.check_id:
                    lease.check_id = self.github.create_check(lease)
                    self.leases.save(lease)
                self.advance(lease)
            except BootstrapFailure:
                self.fail(lease, "Windows runner setup failed before tests could run. Its resources were deleted.")
            except Exception as error:
                logging.warning("Runner progress deferred (%s)", type(error).__name__)
        if not self.cfg.enabled:
            return
        leases = self.leases.list()
        seen = {lease.job_id for lease in leases}
        # Count orphaned cloud resources too: losing a lease record must not
        # let the next reconciliation exceed the fleet's global capacity.
        resources = self.azure.call("GET", self.cfg.scope + "/resources", version="2021-04-01")["value"]
        reservations = set(seen)
        for resource in resources:
            tags = resource.get("tags") or {}
            if tags.get("managed-by") == OWNER_TAG and tags.get("job-id", "").isdigit():
                reservations.add(int(tags["job-id"]))
        for run, job, policy in self.github.queued():
            lease = candidate(self.cfg, run, job, policy, now)
            if lease is None or lease.job_id in seen:
                continue
            # Queued workflow-job payloads expose started_at on API versions
            # without created_at. Prefer the job timestamp over upstream build
            # time; use the workflow age only when GitHub supplies neither.
            queued_at = job.get("created_at") or job.get("started_at") or run["created_at"]
            if now - timestamp(queued_at) >= self.cfg.queue_timeout:
                # A queued job has no running runner for GitHub's job timeout to
                # stop. Fail its infrastructure check and cancel this exact run.
                lease.check_id = self.github.create_check(lease)
                self.fail(lease, "Windows runner admission exceeded its deadline; no reusable worker was substituted.", "timed_out")
                self.cleanup(lease)
            elif len(reservations) < self.cfg.capacity:
                self.leases.save(lease)  # Durable ownership before creating anything.
                leases.append(lease)
                seen.add(lease.job_id)
                reservations.add(lease.job_id)


class BootstrapFailure(Exception):
    """A private bootstrap reported an explicit failure, not a transient API error."""
