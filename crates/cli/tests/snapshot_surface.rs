//! Snapshot command compatibility and group filtering through the CLI, without starting a VM.

use std::{collections::BTreeMap, path::Path, process::Output, time::Duration};

use microsandbox_image::snapshot::{
    DESCRIPTOR_FILENAME, DiskLayer, DiskLayerId, FileSnapshotState, ImageRef, LayerFileKind,
    LayerPayload, Manifest, SCHEMA, SnapshotCapture, SnapshotConsistency, SnapshotFormat,
    SnapshotId, SnapshotRootDisk, SnapshotScope, SnapshotState,
};
use tokio::{process::Command, time::timeout};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn cli_output(home: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_msb"));
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("MSB_") {
            command.env_remove(key);
        }
    }
    let output = timeout(
        Duration::from_secs(30),
        command
            .env("MSB_HOME", home)
            .env("MSB_BACKEND", "local")
            .env("NO_COLOR", "1")
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("snapshot command must finish without a VM")
    .expect("spawn built CLI");
    output
}

async fn cli(home: &Path, args: &[&str]) -> Output {
    let output = cli_output(home, args).await;
    assert!(
        output.status.success(),
        "{args:?}: stdout={}; stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    output
}

fn write_snapshot(directory: &Path) -> SnapshotId {
    // A complete metadata/payload fixture, not a bootable guest filesystem.
    let snapshot_id = SnapshotId::new(format!("snap_{:032x}", 1)).unwrap();
    let layer_id = DiskLayerId::new(format!("layer_{:032x}", 1)).unwrap();
    let state = FileSnapshotState {
        disk_format: SnapshotFormat::Raw,
        filesystem: "ext4".into(),
        virtual_size: 4,
        head: layer_id.clone(),
        layers: vec![DiskLayer {
            layer_id,
            format: SnapshotFormat::Raw,
            virtual_size: 4,
            backing: None,
            payload: LayerPayload {
                file_kind: LayerFileKind::Regular,
                integrity: None,
            },
        }],
    };
    let payload = directory.join(state.layer_path(&state.layers[0]));
    let manifest = Manifest {
        schema: SCHEMA.into(),
        snapshot_id: snapshot_id.clone(),
        scope: SnapshotScope::Disk,
        state: SnapshotState::File(state),
        capture: SnapshotCapture {
            created_at: "2026-09-19T00:00:00Z".into(),
            source_lineage: Some("source".into()),
            source_checkpoint: None,
            consistency: SnapshotConsistency::CrashConsistent,
        },
        image: ImageRef {
            reference: "docker.io/library/alpine:latest".into(),
            manifest_digest: format!("sha256:{}", "a".repeat(64)),
        },
        root_disk: SnapshotRootDisk::Managed,
        parent: None,
        requires: Vec::new(),
        extensions: BTreeMap::new(),
    };
    std::fs::create_dir_all(payload.parent().unwrap()).unwrap();
    std::fs::write(payload, [42u8; 4]).unwrap();
    std::fs::write(
        directory.join(DESCRIPTOR_FILENAME),
        manifest.to_canonical_bytes().unwrap(),
    )
    .unwrap();
    snapshot_id
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn archive_aliases_round_trip_and_group_selection_applies_to_every_output() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let source_group = home.join("snapshots/seed");
    let source = source_group.join(format!("snap_{:032x}", 1));
    let id = write_snapshot(&source);
    std::fs::write(
        source_group.join("group.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema": "microsandbox.snapshot-group/1", "head": id.as_str()
        }))
        .unwrap(),
    )
    .unwrap();

    for (export, import, group) in [("export", "import", "app"), ("save", "load", "app-extra")] {
        let archive = root.path().join(format!("{group}.msb"));
        let archive = archive.to_str().unwrap();
        let mut args = vec!["snap", export, "seed"];
        if export == "export" {
            args.push("--output");
        }
        args.extend([archive, "--plain-tar"]);
        let output = cli(&home, &args).await;
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), archive);
        cli(&home, &["snapshot", import, group, "--file", archive]).await;
    }

    let all = cli(&home, &["snap", "ls", "--format", "json"]).await;
    let all: Vec<serde_json::Value> = serde_json::from_slice(&all.stdout).unwrap();
    assert_eq!(all.len(), 3);
    assert!(
        all.iter()
            .any(|row| row["name"] == "seed" && row["count"] == 1)
    );

    let filtered = cli(&home, &["snap", "ls", "app", "--format", "json"]).await;
    let filtered: Vec<serde_json::Value> = serde_json::from_slice(&filtered.stdout).unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0]["group"], "app");
    assert_eq!(filtered[0]["snapshot_id"], id.as_str());
    let digest = filtered[0]["digest"].as_str().unwrap();

    let quiet = cli(&home, &["snaps", "app", "--quiet"]).await;
    assert_eq!(String::from_utf8_lossy(&quiet.stdout).trim(), id.as_str());

    let table = cli(&home, &["snapshot", "list", "app"]).await;
    let table = String::from_utf8_lossy(&table.stdout);
    let member = filtered[0]["name"].as_str().unwrap_or(id.as_str());
    assert!(table.contains(&format!("app:{member}")), "{table}");
    assert!(!table.contains("app-extra:"));

    let missing = cli_output(&home, &["snapshots", "missing", "--format", "json"]).await;
    assert!(
        !missing.status.success(),
        "a missing group must not appear empty"
    );

    // The imported selector can be exported again through the new form.
    let archive = root.path().join("roundtrip.msb");
    let archive = archive.to_str().unwrap();
    cli(
        &home,
        &[
            "snap",
            "export",
            "app",
            "--checkpoint",
            id.as_str(),
            "-o",
            archive,
        ],
    )
    .await;
    cli(&home, &["snap", "import", "received", "--file", archive]).await;
    let restored = cli(&home, &["snap", "ls", "received", "--format", "json"]).await;
    let restored: Vec<serde_json::Value> = serde_json::from_slice(&restored.stdout).unwrap();
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0]["snapshot_id"], id.as_str());
    assert_eq!(restored[0]["digest"], digest);
}

#[tokio::test]
async fn help_and_shell_completions_expose_canonical_management_controls() {
    let home = tempfile::tempdir().unwrap();
    for command in [
        "create",
        "checkpoint",
        "list",
        "inspect",
        "verify",
        "modify",
        "remove",
        "export",
        "import",
        "restore",
    ] {
        let help = cli(home.path(), &["snap", command, "--help"]).await;
        assert!(String::from_utf8_lossy(&help.stdout).contains("Usage:"));
    }
    for shell in ["bash", "elvish", "fish", "powershell", "zsh"] {
        let completion = cli(home.path(), &["completion", shell]).await;
        let script = String::from_utf8_lossy(&completion.stdout);
        for selector in ["checkpoint", "clear-head", "set-head", "compatibility"] {
            assert!(script.contains(selector), "{shell} lacks {selector}");
        }
    }
}
