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

async fn cli(home: &Path, args: &[&str]) -> Output {
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
async fn archive_aliases_round_trip_and_group_filter_applies_to_every_output() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let source = root.path().join("source");
    let id = write_snapshot(&source);
    let source = source.to_str().unwrap();

    for (export, import, group) in [("export", "import", "app"), ("save", "load", "app-extra")] {
        let archive = root.path().join(format!("{group}.msb"));
        let archive = archive.to_str().unwrap();
        let mut args = vec!["snap", export, source];
        if export == "export" {
            args.push("--output");
        }
        args.extend([archive, "--plain-tar"]);
        let output = cli(&home, &args).await;
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), archive);
        cli(&home, &["snapshot", import, archive, "--group", group]).await;
    }

    let all = cli(&home, &["snap", "ls", "--format", "json"]).await;
    let all: Vec<serde_json::Value> = serde_json::from_slice(&all.stdout).unwrap();
    assert_eq!(all.len(), 2);

    let filtered = cli(&home, &["snap", "ls", "--group", "app", "--format", "json"]).await;
    let filtered: Vec<serde_json::Value> = serde_json::from_slice(&filtered.stdout).unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0]["group"], "app");
    assert_eq!(filtered[0]["snapshot_id"], id.as_str());
    let digest = filtered[0]["digest"].as_str().unwrap();

    let quiet = cli(&home, &["snaps", "--group", "app", "--quiet"]).await;
    assert_eq!(String::from_utf8_lossy(&quiet.stdout).trim(), digest);

    let table = cli(&home, &["snapshot", "list", "--group", "app"]).await;
    let table = String::from_utf8_lossy(&table.stdout);
    let member = filtered[0]["name"].as_str().unwrap_or(id.as_str());
    assert!(table.contains(&format!("app:{member}")), "{table}");
    assert!(!table.contains("app-extra:"));

    let missing = cli(
        &home,
        &["snapshots", "--group", "missing", "--format", "json"],
    )
    .await;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&missing.stdout).unwrap(),
        serde_json::json!([])
    );

    // The imported selector can be exported again through the new form.
    let selector = format!("app:{id}");
    let archive = root.path().join("roundtrip.msb");
    let archive = archive.to_str().unwrap();
    cli(&home, &["snap", "export", &selector, "-o", archive]).await;
    cli(&home, &["snap", "import", archive, "--group", "received"]).await;
    let restored = cli(
        &home,
        &["snap", "ls", "--group", "received", "--format", "json"],
    )
    .await;
    let restored: Vec<serde_json::Value> = serde_json::from_slice(&restored.stdout).unwrap();
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0]["snapshot_id"], id.as_str());
    assert_eq!(restored[0]["digest"], digest);
}
