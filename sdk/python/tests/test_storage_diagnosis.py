"""Read-only diagnosis wrapper contracts without a VM or catalog initialization."""

import json
from unittest.mock import AsyncMock

import pytest

from microsandbox import RuntimeConfig, diagnose_storage
from microsandbox import _microsandbox as native


async def test_scope_partial_results_and_exact_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "home": "/selected",
        "required_runtime_capability": "protected_guest_state",
        "sandboxes": [
            {
                "name": "app",
                "status": "eligible",
                "running": True,
                "protection_registered": True,
                "reason": None,
                "guest_mounts": {"owned-data": "/data"},
                "inspection": {
                    "preview_available": True,
                    "status": "eligible",
                    "reasons": [],
                    "estimated_bytes": 2**64 - 1,
                    "candidates": [
                        {
                            "id": "view-1",
                            "disk_id": "root",
                            "layers": 2,
                            "virtual_size": 2**64 - 1,
                            "estimated_bytes": 0,
                        }
                    ],
                },
            },
            {
                "name": "missing",
                "status": "unavailable",
                "running": False,
                "protection_registered": False,
                "reason": "not_found",
                "inspection": None,
            },
        ],
    }
    call = AsyncMock(return_value=json.dumps(payload))
    monkeypatch.setattr(native, "diagnose_storage", call, raising=False)
    report = await diagnose_storage(["app", "missing"], config=RuntimeConfig(home="/selected"))
    config, selection = call.call_args.args
    assert json.loads(config)["home"] == "/selected"
    assert json.loads(selection) == {"named": ["app", "missing"]}
    assert report.sandboxes[0].inspection.candidates[0].virtual_size == 2**64 - 1
    assert report.sandboxes[0].inspection.preview_available
    assert report.sandboxes[0].guest_mounts == {"owned-data": "/data"}
    assert report.sandboxes[1].guest_mounts == {}
    assert report.sandboxes[0].running
    assert report.sandboxes[1].reason == "not_found"
    await diagnose_storage(all_sandboxes=True)
    assert json.loads(call.call_args.args[1]) == "all"


async def test_explicit_scope_and_missing_native_export(monkeypatch: pytest.MonkeyPatch) -> None:
    call = AsyncMock()
    monkeypatch.setattr(native, "diagnose_storage", call, raising=False)
    for names, all_sandboxes in [(None, False), ([], False), (["app"], True)]:
        with pytest.raises(ValueError, match="select"):
            await diagnose_storage(names, all_sandboxes=all_sandboxes)
    call.assert_not_called()
    monkeypatch.delattr(native, "diagnose_storage")
    with pytest.raises(RuntimeError, match="upgrade or rebuild"):
        await diagnose_storage(["app"])


async def test_native_cloud_selection_never_falls_back_to_local(tmp_path, monkeypatch):
    from microsandbox import BackendKind, backend_scope

    home = tmp_path / "absent-home"
    monkeypatch.setenv("MSB_CONFIG_PATH", str(tmp_path / "absent-config.json"))
    with (
        backend_scope(BackendKind.CLOUD, url="http://127.0.0.1:9", api_key="unused"),
        pytest.raises(Exception, match="local-only"),
    ):
        await diagnose_storage(["app"], config=RuntimeConfig(home=str(home)))
    assert not home.exists()


async def test_native_recovery_requires_acknowledgement_before_backend_access():
    from microsandbox import InvalidConfigError, Sandbox

    with pytest.raises(InvalidConfigError, match="acknowledg"):
        await Sandbox.recover_storage("app", selections={"root": "untrusted-candidate"})
