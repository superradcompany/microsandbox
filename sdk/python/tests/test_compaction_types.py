"""The nested compaction result remains a typed dictionary, not a native-only class."""

from microsandbox.types import DiskCompactionDiskResult, DiskCompactionResult


def test_compaction_results_include_per_disk_metrics():
    disk: DiskCompactionDiskResult = {
        "guest_path": "/data",
        "input_layers": 1,
        "selected_layers": 0,
        "output_layers": 1,
        "materialized_bytes": 0,
        "total_us": 0,
    }
    result: DiskCompactionResult = {
        "dry_run": True,
        "input_layers": 1,
        "selected_layers": 0,
        "output_layers": 1,
        "materialized_bytes": 0,
        "total_us": 0,
        "pause_us": 0,
        "disks": [disk],
    }
    assert result["disks"][0]["guest_path"] == "/data"
    assert result["disks"][0]["selected_layers"] == 0
