//! Tests for the cloud wire contract.

use super::*;
use crate::domain::{
    DEFAULT_SANDBOX_CPUS, DEFAULT_SANDBOX_MEMORY_MIB, OciRootfsSource, RootDisk, RootfsSource,
    SecretInjection, SecretsConfig,
};
use crate::snapshot::Manifest as SnapshotManifest;

fn spec(name: &str) -> CloudSandboxSpec {
    CloudSandboxSpec {
        name: name.into(),
        ..Default::default()
    }
}

fn image_request(name: &str) -> CloudCreateSandboxRequest {
    CloudCreateSandboxRequest::Oci {
        sandbox: spec(name),
        reference: "python:3.12".into(),
        resources: CloudSandboxResources::default(),
        patches: Vec::new(),
        pull_policy: CloudPullPolicy::default(),
    }
}

fn restore_request(name: &str) -> CloudCreateSandboxRequest {
    CloudCreateSandboxRequest::DiskSnapshot {
        sandbox: spec(name),
        disk_snapshot_ref: CloudSnapshotLocation::Managed {
            id: "00000000-0000-0000-0000-000000000003".into(),
        },
        resources: CloudSandboxComputeResources::default(),
        pull_policy: CloudPullPolicy::default(),
    }
}

#[test]
fn create_request_serializes_flat_tagged_spec() {
    let req = image_request("agent-1");
    let json = serde_json::to_value(&req).unwrap();
    // The source is explicit while the spec remains flat (SDK parity).
    assert_eq!(json["source"], "oci");
    assert_eq!(json["name"], "agent-1");
    assert_eq!(json["reference"], "python:3.12");
    assert!(json.get("image").is_none());
    assert!(json.get("deployment_profile").is_none());

    let back: CloudCreateSandboxRequest = serde_json::from_value(json).unwrap();
    assert_eq!(back.sandbox_spec().name, "agent-1");
}

#[test]
fn cloud_network_rejects_rate_limit_configuration() {
    let error = serde_json::from_value::<CloudNetworkSpec>(serde_json::json!({
        "rate_limiter": {
            "egress": {
                "bandwidth": {"size": 1024, "refill_time_ms": 1000}
            }
        }
    }))
    .unwrap_err();

    assert!(error.to_string().contains("unknown field `rate_limiter`"));
}

#[test]
fn cloud_rootfs_source_uses_internal_tagging() {
    let json = serde_json::to_value(CloudRootfsSource::Oci {
        reference: "python:3.12".into(),
    })
    .unwrap();
    assert_eq!(
        json,
        serde_json::json!({"type": "oci", "reference": "python:3.12"})
    );

    let bind = serde_json::to_value(CloudRootfsSource::Bind {
        path: "/host".into(),
    })
    .unwrap();
    assert_eq!(bind, serde_json::json!({"type": "bind", "path": "/host"}));

    let back: CloudRootfsSource = serde_json::from_value(json).unwrap();
    assert!(matches!(back, CloudRootfsSource::Oci { reference } if reference == "python:3.12"));
}

#[test]
fn cloud_secret_twins_use_internal_tagging() {
    // Scalar domain variants normalize to a uniform `{ "type", value }` union.
    assert_eq!(
        serde_json::to_value(CloudHostPattern::Exact {
            value: "api.example.com".into(),
        })
        .unwrap(),
        serde_json::json!({"type": "exact", "value": "api.example.com"})
    );
    assert_eq!(
        serde_json::to_value(CloudSecretSource::Env {
            var: "OPENAI".into()
        })
        .unwrap(),
        serde_json::json!({"type": "env", "var": "OPENAI"})
    );
    assert_eq!(
        serde_json::to_value(CloudViolationAction::Passthrough {
            hosts: vec![CloudHostPattern::Any],
        })
        .unwrap(),
        serde_json::json!({"type": "passthrough", "hosts": [{"type": "any"}]})
    );
}

#[test]
fn cloud_secrets_config_round_trips_through_domain() {
    let cloud = CloudSecretsConfig {
        entries: vec![CloudSecretEntry {
            env_var: "OPENAI_API_KEY".into(),
            value: "sk-x".into(),
            source: Some(CloudSecretSource::Env {
                var: "OPENAI".into(),
            }),
            placeholder: "$MSB_OPENAI".into(),
            allowed_hosts: vec![CloudHostPattern::Exact {
                value: "api.openai.com".into(),
            }],
            injection: SecretInjection::default(),
            on_violation: Some(CloudViolationAction::BlockAndTerminate),
            require_tls_identity: true,
        }],
        on_violation: CloudViolationAction::BlockAndLog,
    };

    let back: CloudSecretsConfig = SecretsConfig::from(cloud.clone()).into();
    assert_eq!(back.entries.len(), 1);
    assert_eq!(back.entries[0].value, "sk-x");
    assert_eq!(back.entries[0].allowed_hosts.len(), 1);
    assert!(matches!(
        back.entries[0].on_violation,
        Some(CloudViolationAction::BlockAndTerminate)
    ));
}

#[test]
fn create_request_converts_disk_size_to_oci_rootfs() {
    let mut req = image_request("agent-1");
    assert!(req.set_oci_disk_size_mib(8192));

    let domain = SandboxSpec::try_from(req).unwrap();

    assert_eq!(domain.resources.cpus, DEFAULT_SANDBOX_CPUS);
    assert_eq!(domain.resources.memory_mib, DEFAULT_SANDBOX_MEMORY_MIB);
    assert_eq!(domain.resources.thp, TransparentHugePagePolicy::Madvise);
    match domain.image {
        RootfsSource::Oci(oci) => {
            assert_eq!(oci.reference, "python:3.12");
            assert_eq!(oci.root_disk, Some(RootDisk::managed(8192)));
        }
        other => panic!("expected OCI rootfs, got {other:?}"),
    }
}

#[test]
fn cloud_resources_do_not_carry_host_runtime_policy() {
    let mut domain = SandboxSpec::try_from(image_request("agent-1")).unwrap();
    domain.resources.cpu_placement = CpuPlacement::Spread;
    domain.resources.placement_profile = Some("locality".into());
    domain.resources.thp = TransparentHugePagePolicy::Always;

    let cloud = CloudCreateSandboxRequest::from(domain);
    let wire = serde_json::to_value(&cloud).unwrap();
    let resources = &wire["resources"];
    assert!(resources.get("cpu_placement").is_none());
    assert!(resources.get("placement_profile").is_none());
    assert!(resources.get("thp").is_none());

    let round_trip = SandboxSpec::try_from(cloud).unwrap();
    assert_eq!(round_trip.resources.cpu_placement, CpuPlacement::Inherit);
    assert!(round_trip.resources.placement_profile.is_none());
    assert_eq!(round_trip.resources.thp, TransparentHugePagePolicy::Madvise);
}

#[test]
fn legacy_request_rejects_disk_size_for_non_oci_rootfs() {
    let request = serde_json::from_value::<CloudCreateSandboxRequest>(serde_json::json!({
        "name": "agent-1",
        "image": {"type": "bind", "path": "/tmp/rootfs"},
        "resources": {
            "vcpus": 1,
            "memory_mib": 512,
            "disk_size_mib": 8192,
        },
    }));

    assert!(request.unwrap_err().to_string().contains("disk_size_mib"));
}

#[test]
fn domain_spec_converts_oci_size_to_cloud_resources() {
    let domain = SandboxSpec {
        name: "agent-1".into(),
        image: RootfsSource::Oci(OciRootfsSource {
            reference: "python:3.12".into(),
            root_disk: Some(RootDisk::managed(8192)),
        }),
        deployment_profile: DeploymentProfile::MultiTenant,
        ..Default::default()
    };

    let req = CloudCreateSandboxRequest::from(domain);

    // The hosting platform, not a tenant create request, selects the
    // effective deployment profile.
    assert!(
        serde_json::to_value(&req)
            .unwrap()
            .get("deployment_profile")
            .is_none()
    );

    assert_eq!(req.oci_disk_size_mib(), Some(Some(8192)));
    assert_eq!(req.oci_reference(), Some("python:3.12"));
}

#[test]
fn create_request_minimal_defaults() {
    // Only the spec's name + image are set; everything else defaults.
    let req = image_request("agent-1");
    let json = serde_json::to_value(&req).unwrap();
    let back: CloudCreateSandboxRequest = serde_json::from_value(json).unwrap();
    assert_eq!(back.sandbox_spec().name, "agent-1");
}

#[test]
fn sandbox_response_accepts_curated_optional_spec() {
    let sb = CloudCreateSandboxResponse {
        id: "00000000-0000-0000-0000-000000000002".into(),
        org_id: "00000000-0000-0000-0000-000000000001".into(),
        name: "agent-1".into(),
        slug: "brave-otter".into(),
        status: CloudSandboxStatus::Created,
        status_reason: None,
        spec: Some(serde_json::json!({
            "image": "python:3.12",
            "resources": { "vcpus": 2, "memory_mib": 1024 },
        })),
        ephemeral: true,
        created_at: "2026-05-17T12:00:00Z".parse().unwrap(),
        started_at: None,
        stopped_at: None,
        last_failure_message: None,
    };
    let json = serde_json::to_value(&sb).unwrap();
    assert_eq!(json["slug"], "brave-otter");
    assert_eq!(json["name"], "agent-1");

    let back: CloudCreateSandboxResponse = serde_json::from_value(json).unwrap();
    assert_eq!(back.slug, "brave-otter");
    assert_eq!(back.status, CloudSandboxStatus::Created);
    assert_eq!(back.spec.as_ref().unwrap()["image"], "python:3.12");
    assert!(back.started_at.is_none());
}

#[test]
fn sandbox_response_accepts_omitted_spec() {
    let json = serde_json::json!({
        "id": "00000000-0000-0000-0000-000000000002",
        "org_id": "00000000-0000-0000-0000-000000000001",
        "name": "agent-1",
        "slug": "brave-otter",
        "status": "running",
        "ephemeral": false,
        "created_at": "2026-05-17T12:00:00Z",
        "started_at": "2026-05-17T12:00:01Z",
        "stopped_at": null,
        "last_failure_message": null
    });

    let response: CloudCreateSandboxResponse = serde_json::from_value(json).unwrap();

    assert!(response.spec.is_none());
    assert_eq!(response.status, CloudSandboxStatus::Running);
}

#[test]
fn snapshot_location_uses_internal_tagging() {
    assert_eq!(
        serde_json::to_value(CloudSnapshotLocation::Managed {
            id: "snap-00000000-0000-0000-0000-000000000003".into(),
        })
        .unwrap(),
        serde_json::json!({
            "type": "managed",
            "id": "snap-00000000-0000-0000-0000-000000000003",
        })
    );
    assert_eq!(
        serde_json::to_value(CloudSnapshotLocation::HostVolume {
            path: "/mnt/snapshots/post-setup".into(),
        })
        .unwrap(),
        serde_json::json!({"type": "host_volume", "path": "/mnt/snapshots/post-setup"})
    );
}

#[test]
fn create_request_requires_exactly_one_rootfs_origin() {
    let neither = serde_json::from_value::<CloudCreateSandboxRequest>(serde_json::json!({
        "name": "agent-1",
    }));
    assert!(neither.is_err());

    let both = serde_json::from_value::<CloudCreateSandboxRequest>(serde_json::json!({
        "name": "agent-1",
        "image": {"type": "oci", "reference": "python:3.12"},
        "disk_snapshot_ref": {
            "type": "managed",
            "id": "00000000-0000-0000-0000-000000000003",
        },
    }));
    assert!(both.is_err());
}

#[test]
fn create_request_deserializes_managed_snapshot_restore() {
    let req: CloudCreateSandboxRequest = serde_json::from_value(serde_json::json!({
        "source": "disk_snapshot",
        "name": "agent-1",
        "disk_snapshot_ref": {
            "type": "managed",
            "id": "00000000-0000-0000-0000-000000000003",
        },
    }))
    .unwrap();

    assert_eq!(
        req.disk_snapshot_ref(),
        Some(&CloudSnapshotLocation::Managed {
            id: "00000000-0000-0000-0000-000000000003".into(),
        })
    );
}

#[test]
fn create_request_accepts_legacy_untagged_sources() {
    let image: CloudCreateSandboxRequest = serde_json::from_value(serde_json::json!({
        "name": "image",
        "image": {"type": "oci", "reference": "python:3.12"},
    }))
    .unwrap();
    assert!(matches!(image, CloudCreateSandboxRequest::Oci { .. }));

    let restore: CloudCreateSandboxRequest = serde_json::from_value(serde_json::json!({
        "name": "restore",
        "disk_snapshot_ref": {
            "type": "managed",
            "id": "00000000-0000-0000-0000-000000000003",
        },
    }))
    .unwrap();
    assert!(matches!(
        restore,
        CloudCreateSandboxRequest::DiskSnapshot { .. }
    ));
}

#[test]
fn create_request_rejects_invalid_tagged_sources() {
    for body in [
        serde_json::json!({
            "source": "image",
            "name": "missing-image",
        }),
        serde_json::json!({
            "source": "disk_snapshot",
            "name": "wrong-field",
            "image": {"type": "oci", "reference": "python:3.12"},
        }),
        serde_json::json!({
            "source": "future_source",
            "name": "unknown",
            "image": {"type": "oci", "reference": "python:3.12"},
        }),
    ] {
        assert!(serde_json::from_value::<CloudCreateSandboxRequest>(body).is_err());
    }
}

#[test]
fn create_request_wire_body_with_image_and_snapshot_fails_validation() {
    let req = serde_json::from_value::<CloudCreateSandboxRequest>(serde_json::json!({
        "name": "agent-1",
        "image": {"type": "oci", "reference": "python:3.12"},
        "disk_snapshot_ref": {
            "type": "managed",
            "id": "00000000-0000-0000-0000-000000000003",
        },
    }));

    assert!(req.is_err());
}

#[test]
fn create_request_rejects_disk_size_for_snapshot_restore() {
    let restore = serde_json::from_value::<CloudCreateSandboxRequest>(serde_json::json!({
        "name": "agent-1",
        "disk_snapshot_ref": {
            "type": "managed",
            "id": "00000000-0000-0000-0000-000000000003",
        },
        "resources": {
            "vcpus": 2,
            "memory_mib": 1024,
            "disk_size_mib": 8192,
        },
    }));

    assert!(restore.is_err());
}

#[test]
fn unresolved_snapshot_reference_conversion_errors() {
    let err = SandboxSpec::try_from(restore_request("agent-1")).unwrap_err();

    assert!(err.to_string().contains("disk_snapshot_ref"));
}

#[test]
fn domain_spec_converts_to_oci_without_snapshot() {
    let cloud = CloudCreateSandboxRequest::from(SandboxSpec {
        name: "agent-1".into(),
        ..Default::default()
    });

    assert!(matches!(cloud, CloudCreateSandboxRequest::Oci { .. }));
    let json = serde_json::to_value(&cloud).unwrap();
    assert_eq!(json["source"], "oci");
    assert!(json.get("image").is_none());
    assert!(json.get("disk_snapshot_ref").is_none());
}

fn sample_snapshot_manifest() -> SnapshotManifest {
    use crate::snapshot::{
        FileSnapshotState, ImageRef, SCHEMA_VERSION, SNAPSHOT_ARTIFACT_KIND, SnapshotFormat,
        SnapshotScope, SnapshotState, UpperIntegrity, UpperLayer,
    };

    SnapshotManifest {
        schema: SCHEMA_VERSION,
        artifact: SNAPSHOT_ARTIFACT_KIND.into(),
        scope: SnapshotScope::Disk,
        created_at: "2026-05-01T12:00:00Z".into(),
        parent: None,
        image: ImageRef {
            reference: "docker.io/library/python:3.12".into(),
            manifest_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        },
        source_sandbox: Some("agent-1".into()),
        state: SnapshotState::File(FileSnapshotState {
            format: SnapshotFormat::Raw,
            fstype: "ext4".into(),
            upper: UpperLayer {
                file: "upper.ext4".into(),
                size_bytes: 4_294_967_296,
                integrity: Some(UpperIntegrity::SparseSha256V1 {
                    digest:
                        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                            .into(),
                }),
            },
        }),
        labels: BTreeMap::new(),
        extensions: BTreeMap::new(),
        requires: Vec::new(),
    }
}

#[test]
fn cloud_snapshot_serializes_approved_shape_and_round_trips() {
    let manifest = sample_snapshot_manifest();
    let digest = manifest.digest().unwrap();
    let snapshot = CloudSnapshot::Disk {
        snapshot: CloudSnapshotDetails {
            name: "post-setup".into(),
            location: CloudSnapshotLocation::Managed {
                id: "snap-00000000-0000-0000-0000-000000000003".into(),
            },
            source_sandbox_id: Some("00000000-0000-0000-0000-000000000002".into()),
            digest: digest.clone(),
            size_bytes: 4_294_967_296,
            manifest,
            labels: BTreeMap::from([("owner".into(), "alice".into())]),
            created_at: "2026-05-17T12:00:00Z".parse().unwrap(),
        },
    };

    let json = serde_json::to_value(&snapshot).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "kind": "disk",
            "name": "post-setup",
            "location": {
                "type": "managed",
                "id": "snap-00000000-0000-0000-0000-000000000003",
            },
            "source_sandbox_id": "00000000-0000-0000-0000-000000000002",
            "digest": digest,
            "size_bytes": 4_294_967_296_u64,
            "manifest": {
                "schema": 1,
                "artifact": "snapshot",
                "scope": "disk",
                "created_at": "2026-05-01T12:00:00Z",
                "parent": null,
                "image": {
                    "ref": "docker.io/library/python:3.12",
                    "manifest_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                },
                "source_sandbox": "agent-1",
                "state": {
                    "kind": "file",
                    "format": "raw",
                    "fstype": "ext4",
                    "upper": {
                        "file": "upper.ext4",
                        "size_bytes": 4_294_967_296_u64,
                        "integrity": {
                            "algorithm": "msb-sparse-sha256-v1",
                            "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        },
                    },
                },
                "labels": {},
                "extensions": {},
                "requires": [],
            },
            "labels": {"owner": "alice"},
            "created_at": "2026-05-17T12:00:00Z",
        })
    );

    let back: CloudSnapshot = serde_json::from_value(json).unwrap();
    assert_eq!(back.kind(), CloudSnapshotKind::Disk);
    assert_eq!(back.details().digest, snapshot.details().digest);
    assert_eq!(back.details().manifest, snapshot.details().manifest);
    assert_eq!(back.details().location, snapshot.details().location);

    let checkpoint = CloudSnapshot::Checkpoint {
        snapshot: back.into_details(),
    };
    let checkpoint_json = serde_json::to_value(checkpoint).unwrap();
    assert_eq!(checkpoint_json["kind"], "checkpoint");
}

#[test]
fn snapshot_operation_serializes_approved_shape() {
    let operation = CloudSnapshotOperation {
        id: "op-00000000-0000-0000-0000-000000000004".into(),
        kind: CloudSnapshotKind::Disk,
        status: CloudSnapshotOperationStatus::Failed,
        result: None,
        error: Some(CloudErrorDetails {
            code: Some("snapshot_failed".into()),
            message: Some("sandbox stopped during capture".into()),
        }),
        created_at: "2026-05-17T12:00:00Z".parse().unwrap(),
        updated_at: "2026-05-17T12:00:05Z".parse().unwrap(),
        completed_at: Some("2026-05-17T12:00:05Z".parse().unwrap()),
    };

    let json = serde_json::to_value(&operation).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "id": "op-00000000-0000-0000-0000-000000000004",
            "kind": "disk",
            "status": "failed",
            "result": null,
            "error": {
                "code": "snapshot_failed",
                "message": "sandbox stopped during capture",
            },
            "created_at": "2026-05-17T12:00:00Z",
            "updated_at": "2026-05-17T12:00:05Z",
            "completed_at": "2026-05-17T12:00:05Z",
        })
    );

    let back: CloudSnapshotOperation = serde_json::from_value(json).unwrap();
    assert_eq!(back.status, CloudSnapshotOperationStatus::Failed);
    assert!(back.result.is_none());
    assert_eq!(back.error.unwrap().code.as_deref(), Some("snapshot_failed"));
    assert!(back.completed_at.is_some());
}

#[test]
fn snapshot_operation_status_serializes_snake_case() {
    use CloudSnapshotOperationStatus::*;

    for (status, expected) in [
        (Queued, "queued"),
        (InProgress, "in_progress"),
        (Succeeded, "succeeded"),
        (Failed, "failed"),
    ] {
        assert_eq!(
            serde_json::to_value(status).unwrap(),
            serde_json::json!(expected)
        );
    }
}

#[test]
fn in_flight_snapshot_operation_defaults_result_fields() {
    let operation: CloudSnapshotOperation = serde_json::from_value(serde_json::json!({
        "id": "op-00000000-0000-0000-0000-000000000004",
        "kind": "checkpoint",
        "status": "in_progress",
        "created_at": "2026-05-17T12:00:00Z",
        "updated_at": "2026-05-17T12:00:01Z",
    }))
    .unwrap();

    assert_eq!(operation.kind, CloudSnapshotKind::Checkpoint);
    assert_eq!(operation.status, CloudSnapshotOperationStatus::InProgress);
    assert!(operation.result.is_none());
    assert!(operation.error.is_none());
    assert!(operation.completed_at.is_none());
}

#[test]
fn create_snapshot_request_serializes_approved_shape() {
    let request = CloudCreateSnapshotRequest::Disk {
        snapshot: CloudSnapshotSpec {
            source_sandbox_id: "00000000-0000-0000-0000-000000000002".into(),
            name: "post-setup".into(),
            dest_dir: Some("/mnt/snapshots".into()),
            labels: BTreeMap::from([("owner".into(), "alice".into())]),
            force: true,
            record_integrity: true,
        },
    };

    assert_eq!(
        serde_json::to_value(&request).unwrap(),
        serde_json::json!({
            "kind": "disk",
            "source_sandbox_id": "00000000-0000-0000-0000-000000000002",
            "name": "post-setup",
            "dest_dir": "/mnt/snapshots",
            "labels": {"owner": "alice"},
            "force": true,
            "record_integrity": true,
        })
    );
}

#[test]
fn create_snapshot_request_requires_source_and_name_and_defaults_the_rest() {
    let request: CloudCreateSnapshotRequest = serde_json::from_value(serde_json::json!({
        "kind": "checkpoint",
        "source_sandbox_id": "00000000-0000-0000-0000-000000000002",
        "name": "post-setup",
    }))
    .unwrap();

    assert_eq!(request.kind(), CloudSnapshotKind::Checkpoint);
    let request = request.snapshot_spec();
    assert_eq!(
        request.source_sandbox_id,
        "00000000-0000-0000-0000-000000000002"
    );
    assert_eq!(request.name, "post-setup");
    assert!(request.dest_dir.is_none());
    assert!(request.labels.is_empty());
    assert!(!request.force);
    assert!(!request.record_integrity);

    // Defaulted fields stay off the wire entirely.
    assert_eq!(
        serde_json::to_value(CloudCreateSnapshotRequest::Checkpoint {
            snapshot: request.clone(),
        })
        .unwrap(),
        serde_json::json!({
            "kind": "checkpoint",
            "source_sandbox_id": "00000000-0000-0000-0000-000000000002",
            "name": "post-setup",
        })
    );

    let missing_source = serde_json::from_value::<CloudCreateSnapshotRequest>(serde_json::json!({
        "kind": "disk",
        "name": "post-setup",
    }));
    assert!(missing_source.is_err());

    let missing_name = serde_json::from_value::<CloudCreateSnapshotRequest>(serde_json::json!({
        "kind": "disk",
        "source_sandbox_id": "00000000-0000-0000-0000-000000000002",
    }));
    assert!(missing_name.is_err());

    let missing_kind = serde_json::from_value::<CloudCreateSnapshotRequest>(serde_json::json!({
        "source_sandbox_id": "00000000-0000-0000-0000-000000000002",
        "name": "post-setup",
    }));
    assert!(missing_kind.is_err());

    let legacy_source = serde_json::from_value::<CloudCreateSnapshotRequest>(serde_json::json!({
        "kind": "disk",
        "source_sandbox": "00000000-0000-0000-0000-000000000002",
        "name": "post-setup",
    }));
    assert!(legacy_source.is_err());
}
