"""Explicit local storage inspection without catalog migration or repair."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Literal

from microsandbox import _microsandbox as native
from microsandbox.setup import RuntimeConfig, _config_json

StorageDiagnosticStatus = Literal[
    "ready", "eligible", "maintenance_required", "recovery_required", "in_progress", "unavailable"
]


@dataclass(frozen=True)
class StorageCandidate:
    """A role-bound selected disk view; this is not an authorization token."""

    id: str
    disk_id: str
    layers: int
    virtual_size: int
    estimated_bytes: int


@dataclass(frozen=True)
class StorageInspection:
    """The common engine's provisional candidate inspection."""

    status: str
    reasons: list[str]
    candidates: list[StorageCandidate]
    estimated_bytes: int
    preview_available: bool = False


@dataclass(frozen=True)
class StorageSandboxDiagnosis:
    """One selected sandbox, including failures that leave other results available."""

    name: str
    status: StorageDiagnosticStatus
    running: bool
    protection_registered: bool
    reason: str | None
    inspection: StorageInspection | None
    guest_mounts: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class StorageDiagnosis:
    """Storage readiness; all source selection is revalidated before migration."""

    home: str
    sandboxes: list[StorageSandboxDiagnosis]
    required_runtime_capability: str


async def diagnose_storage(
    names: list[str] | None = None,
    *,
    all_sandboxes: bool = False,
    config: RuntimeConfig | None = None,
) -> StorageDiagnosis:
    """Inspect named sandboxes or explicitly all; never start, stop, repair or migrate.

    SQLite may maintain read-lock WAL sidecars. Catalog data, permissions and disks
    remain unchanged; running-sandbox results are provisional.
    """
    if all_sandboxes == (names is not None):
        raise ValueError("select names or all_sandboxes=True, exclusively")
    if names is not None and not names:
        raise ValueError("select at least one sandbox name")
    call = getattr(native, "diagnose_storage", None)
    if call is None:
        raise RuntimeError(
            "storage diagnostics require an updated microsandbox native SDK; upgrade or rebuild it"
        )
    selection = "all" if all_sandboxes else {"named": names}
    result = json.loads(await call(_config_json(config), json.dumps(selection)))
    entries = []
    for entry in result["sandboxes"]:
        inspection = entry["inspection"]
        if inspection is not None:
            inspection["candidates"] = [
                StorageCandidate(**item) for item in inspection["candidates"]
            ]
            entry["inspection"] = StorageInspection(**inspection)
        entries.append(StorageSandboxDiagnosis(**entry))
    result["sandboxes"] = entries
    return StorageDiagnosis(**result)
