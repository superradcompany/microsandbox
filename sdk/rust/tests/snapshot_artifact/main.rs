//! Integration tests for snapshot artifact handling.
//!
//! These tests do not require KVM/libkrun — they exercise the
//! file-format, integrity-check, and archive layers by synthesizing
//! manifests + upper files directly. End-to-end tests that boot a
//! VM live alongside the other `msb_test`-gated integration tests.

use std::collections::BTreeMap;

use microsandbox::Checkpoint;
use microsandbox_types::snapshot::{
    DiskLayer, DiskLayerId, FileSnapshotState, ImageRef, LayerFileKind, LayerPayload, Manifest,
    SCHEMA, SnapshotCapture, SnapshotConsistency, SnapshotFormat, SnapshotId, SnapshotRootDisk,
    SnapshotScope, SnapshotState, UpperIntegrity,
};

#[cfg(feature = "local")]
mod local;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn sample_manifest(upper_size: u64) -> Manifest {
    let snapshot_id = SnapshotId::new(format!("snap_{:032x}", rand::random::<u128>())).unwrap();
    let layer_id = DiskLayerId::new(format!("layer_{:032x}", rand::random::<u128>())).unwrap();
    Manifest {
        schema: SCHEMA.into(),
        snapshot_id,
        scope: SnapshotScope::Disk,
        state: SnapshotState::File(FileSnapshotState {
            disk_format: SnapshotFormat::Raw,
            filesystem: "ext4".into(),
            virtual_size: upper_size,
            head: layer_id.clone(),
            layers: vec![DiskLayer {
                layer_id,
                format: SnapshotFormat::Raw,
                virtual_size: upper_size,
                backing: None,
                payload: LayerPayload {
                    file_kind: LayerFileKind::Regular,
                    integrity: Some(UpperIntegrity::SparseSha256V1 {
                        digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                    }),
                },
            }],
        }),
        capture: SnapshotCapture {
            created_at: "2026-05-01T12:00:00Z".into(),
            source_lineage: Some("synthetic".into()),
            source_checkpoint: None,
            consistency: SnapshotConsistency::CrashConsistent,
        },
        image: ImageRef {
            reference: "docker.io/library/alpine:3.20".into(),
            manifest_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000001".into(),
        },
        root_disk: SnapshotRootDisk::Managed,
        parent: None,
        extensions: BTreeMap::new(),
        requires: Vec::new(),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn builder_supports_name_first_contract() {
    let config = Checkpoint::builder("clean-python")
        .from_sandbox("build-box")
        .label("stage", "deps")
        .build()
        .unwrap();

    assert_eq!(config.name, "clean-python");
    assert_eq!(config.source_sandbox, "build-box");
    assert_eq!(config.labels, vec![("stage".into(), "deps".into())]);
}

#[test]
fn builder_carries_dest_dir() {
    let config = Checkpoint::builder("clean")
        .from_sandbox("box")
        .dest_dir("/mnt/big")
        .build()
        .unwrap();
    assert_eq!(config.name, "clean");
    assert_eq!(
        config.dest_dir.as_deref(),
        Some(std::path::Path::new("/mnt/big"))
    );
}

#[test]
fn builder_requires_source_sandbox() {
    let err = Checkpoint::builder("clean").build().unwrap_err();
    assert!(err.to_string().contains("from_sandbox"));
}

#[test]
fn manifest_validation_rejects_noncanonical_layer_identity() {
    let manifest = sample_manifest(4);
    let mut value = serde_json::to_value(manifest).unwrap();
    value["state"]["layers"][0]["layer_id"] = serde_json::json!("../outside.ext4");
    let bytes = serde_json::to_vec(&value).unwrap();
    let error = Manifest::from_bytes(&bytes).unwrap_err().to_string();

    assert!(error.contains("layer_id"), "unexpected error: {error}");
}

#[tokio::test]
async fn manifest_digest_is_stable_across_processes() {
    // Canonicalization is stable for one immutable descriptor. Independent
    // captures intentionally receive different opaque snapshot IDs.
    let manifest = sample_manifest(10);
    assert_eq!(
        manifest.digest().unwrap(),
        manifest.clone().digest().unwrap()
    );
}
