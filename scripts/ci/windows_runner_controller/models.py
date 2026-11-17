"""Validated job identities and durable, credential-free runner leases."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import re

OWNER_TAG = "microsandbox-windows-ci"
PLATFORMS = {"win10": "10", "win11": "11"}


def timestamp(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def utc(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class Config:
    repository: str
    workflow_id: int
    subscription: str
    resource_group: str
    location: str
    subnet_id: str
    public_key: str
    ssh_source: str
    images: dict
    capacity: int = 2
    lifetime: int = 3600
    queue_timeout: int = 5400
    enabled: bool = False
    runner_group_id: int = 1

    def __post_init__(self):
        import ipaddress

        if not re.fullmatch(r"[\w.-]+/[\w.-]+", self.repository):
            raise ValueError("Invalid repository")
        if not re.fullmatch(r"[a-fA-F0-9-]{36}", self.subscription):
            raise ValueError("Invalid subscription")
        if not re.fullmatch(r"[\w.-]+", self.resource_group):
            raise ValueError("Invalid resource group")
        if not self.subnet_id.startswith(self.scope + "/providers/Microsoft.Network/"):
            raise ValueError("Workers must use the dedicated resource group's network")
        ssh_network = ipaddress.ip_network(self.ssh_source)
        if ssh_network.version != 4 or ssh_network.prefixlen != 32:
            raise ValueError("SSH must be limited to a single IPv4 address")
        if not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]*)?", self.public_key):
            raise ValueError("Expected one OpenSSH public key")
        if set(self.images) != set(PLATFORMS):
            raise ValueError("Both Windows images are required")
        if not 1 <= self.capacity <= 2 or not 300 <= self.lifetime <= 3600:
            raise ValueError("Fleet size or lifetime exceeds its safety limit")
        if not 300 <= self.queue_timeout <= 5400 or self.runner_group_id < 1:
            raise ValueError("Invalid admission deadline or runner group")
        for image in self.images.values():
            marketplace = set(image) == {"publisher", "offer", "sku", "version"} and image["version"] != "latest"
            if not marketplace and not self.prepared_image(image):
                raise ValueError("Use pinned Marketplace or dedicated gallery image versions, never an old job disk")

    def prepared_image(self, image):
        # Only immutable versions in the dedicated CI resource group are valid.
        # A disk, snapshot, external gallery, or mutable 'latest' reference must
        # never become a shortcut for reusing a previous job's machine state.
        pattern = re.escape(self.scope) + r"/providers/Microsoft\.Compute/galleries/[\w.-]+/images/[\w.-]+/versions/\d+\.\d+\.\d+"
        return set(image) == {"id"} and re.fullmatch(pattern, image["id"], re.IGNORECASE) is not None

    @property
    def scope(self):
        return f"/subscriptions/{self.subscription}/resourceGroups/{self.resource_group}"


@dataclass
class Lease:
    job_id: int
    run_id: int
    attempt: int
    platform: str
    revision: str
    created: float
    expires: float
    phase: str = "create"
    check_id: int = 0
    runner_id: int = 0
    ready_after: float = 0
    conclusion: str = "success"
    reason: str = "Fresh runner provisioned and resources deleted."

    def __post_init__(self):
        if min(self.job_id, self.run_id, self.attempt) <= 0 or self.platform not in PLATFORMS:
            raise ValueError("Invalid lease identity")
        if not re.fullmatch(r"[0-9a-f]{40}", self.revision):
            raise ValueError("Invalid revision")
        if not 0 < self.expires - self.created <= 3600:
            raise ValueError("Invalid lease expiry")

    @property
    def name(self):
        return f"wci-{self.job_id}"

    @property
    def labels(self):
        # GitHub matches subsets of labels. Omit generic platform/default labels
        # so a job requesting only a broad label cannot claim this runner.
        return [f"msb-whp-{self.run_id}-{self.attempt}-{self.platform}"]

    @property
    def external_id(self):
        return f"windows-whp/{self.run_id}/{self.attempt}/{self.platform}"

    @property
    def tags(self):
        return {"managed-by": OWNER_TAG, "expires-at": utc(self.expires), "job-id": str(self.job_id)}

    def resource_ids(self, cfg):
        # Only these four exact resources can be deleted for this lease. No IDs
        # supplied by a workflow, artifact, guest, or GitHub output are accepted.
        return [
            cfg.scope + "/providers/Microsoft.Compute/virtualMachines/" + self.name,
            cfg.scope + "/providers/Microsoft.Compute/disks/" + self.name + "-os",
            cfg.scope + "/providers/Microsoft.Network/networkInterfaces/" + self.name + "-nic",
            cfg.scope + "/providers/Microsoft.Network/publicIPAddresses/" + self.name + "-ip",
        ]

    def to_dict(self):
        return asdict(self)


def candidate(cfg, run, job, approval_policy, now):
    """Only admit an evaluated job from the expected, approved run attempt."""
    if run.get("workflow_id") != cfg.workflow_id or run.get("path") != ".github/workflows/check.yml":
        return None
    # A workflow can return to queued after its hosted builds finish, while
    # only self-hosted jobs remain. Do not require a runner to exist already.
    if run.get("status") not in {"queued", "in_progress"} or run.get("conclusion") is not None:
        return None
    if run.get("event") not in {"push", "pull_request", "workflow_dispatch"}:
        return None
    if job.get("status") != "queued" or job.get("run_id") != run["id"]:
        return None
    # Keep GitHub's approval policy mandatory for forks. Discovery additionally
    # requires a completed hosted prerequisite in this attempt's job list;
    # workflow queue state alone is not evidence that approval was granted.
    fork = (run.get("head_repository") or {}).get("full_name") != cfg.repository
    if fork and (run.get("event") != "pull_request" or approval_policy != "all_external_contributors"):
        return None
    for platform in PLATFORMS:
        lease = Lease(job["id"], run["id"], run["run_attempt"], platform, run["head_sha"], now, now + cfg.lifetime)
        if job.get("name") == f"Windows WHP ({PLATFORMS[platform]})" and set(job.get("labels", [])) == set(lease.labels):
            return lease
    return None
