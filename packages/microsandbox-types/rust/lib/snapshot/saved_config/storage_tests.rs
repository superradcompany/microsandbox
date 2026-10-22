//! Portable resource identities, secret/path exclusion and authoritative owned-backing checks.

use super::*;
use crate::snapshot::{
    OwnedDirectoryPayload, OwnedMountSnapshot, OwnedVolumeCapture, OwnedVolumeData,
};
use crate::{
    DiskImageFormat, HostPermissions, MountOptions, NamedVolumeCreate, NamedVolumeMode,
    OwnedVolumeStorage, StatVirtualization, VolumeKind, VolumeMount, VsockRouteSpec,
    VsockSocketType, owned_volume_mount_id,
};
use serde_json::{Value, json};
use std::path::PathBuf;

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn canonical_guest_identity_and_parent_first_order_are_required_without_repair() {
    for path in [
        "/",
        "relative",
        "C:\\host",
        "/a/../b",
        "/a/./b",
        "/a//b",
        "/a/",
        "/a,option",
        "/a;b",
        "/a:b",
        "/SENTINEL\0",
    ] {
        let mut mount = tmpfs("/valid");
        mount["guest"] = json!(path);
        let error = reject(&json!({"mounts":saved(json!([mount]))}), "SCFG_");
        assert!(!error.contains("SENTINEL"));
    }
    parse(&json!({"mounts":saved(json!([tmpfs("/a"),tmpfs("/z"),tmpfs("/a/b")]))}));
    reject(
        &json!({"mounts":saved(json!([tmpfs("/a/b"),tmpfs("/a")]))}),
        "parent-before-child",
    );
    reject(
        &json!({"mounts":saved(json!([tmpfs("/a"),tmpfs("/a")]))}),
        "duplicate guest",
    );
}

#[test]
fn owned_mount_id_hash_collision_cannot_alias_two_guest_mounts_to_one_backing() {
    // Real collision in the released 32-bit identity suffix, with the same slug.
    let paths = ["/shared-path/11188", "/shared-path/92829"];
    assert_eq!(
        owned_volume_mount_id(paths[0]),
        owned_volume_mount_id(paths[1])
    );
    let mounts: Vec<_> = paths
        .iter()
        .map(|p| json!({"kind":"owned","guest":p,"mount_id":owned_volume_mount_id(p)}))
        .collect();
    reject(
        &json!({"mounts":saved(json!(mounts))}),
        "duplicate owned mount identity",
    );
}

#[test]
fn all_mount_variants_reject_injected_host_paths_operational_consent_and_extra_options() {
    for mut mount in [
        bind("/bind", "data"),
        named("/named", "volume"),
        disk("/disk", "block"),
        tmpfs("/tmp"),
        owned("/owned"),
    ] {
        let base = mount.clone();
        for field in [
            "host",
            "host_path",
            "name",
            "create",
            "safe_to_apply",
            "allow_missing",
            "source_credentials",
        ] {
            mount = base.clone();
            mount[field] = json!("SENTINEL_PRIVATE");
            assert!(
                !reject(&json!({"mounts":saved(json!([mount]))}), "SCFG_SCHEMA")
                    .contains("SENTINEL")
            );
        }
        if base.get("options").is_some() {
            mount = base.clone();
            mount["options"]["host_credentials"] = json!("SENTINEL");
            reject(&json!({"mounts":saved(json!([mount]))}), "SCFG_SCHEMA");
        }
    }
    reject(&json!({"mounts":null}), "SCFG_SCHEMA");
    reject(&json!({"vsock":null}), "SCFG_SCHEMA");
    let mut route = route(8080, "stream", "ipc");
    route["host_socket"] = json!("/SENTINEL/socket");
    reject(&json!({"vsock":saved(json!([route]))}), "SCFG_SCHEMA");
}

#[test]
fn directory_owner_and_literal_metadata_constraints_match_existing_mount_rules() {
    let mut mount = bind("/data", "data");
    mount["options"]["override_uid"] = json!(0);
    reject(
        &json!({"mounts":saved(json!([mount.clone()]))}),
        "uid and gid must be paired",
    );
    mount["options"]["override_gid"] = json!(0);
    parse(&json!({"mounts":saved(json!([mount.clone()]))}));
    mount["stat_virtualization"] = json!("off");
    reject(
        &json!({"mounts":saved(json!([mount.clone()]))}),
        "literal host metadata conflicts",
    );
    mount["options"] = options();
    mount["host_permissions"] = json!("mirror");
    reject(
        &json!({"mounts":saved(json!([mount.clone()]))}),
        "literal host metadata conflicts",
    );
    mount["stat_virtualization"] = json!("strict");
    mount["follow_root_symlinks"] = json!(true);
    let input = json!({"mounts":saved(json!([mount]))});
    assert_eq!(serde_json::to_value(parse(&input)).unwrap(), input);
    // Preserving a relaxation is not approval to apply it on the destination.
}

#[test]
fn block_and_tmpfs_mounts_cannot_apply_filesystem_overlay_ownership() {
    for mut mount in [
        disk("/disk", "block"),
        tmpfs("/tmp"),
        named("/named", "volume"),
    ] {
        if mount["kind"] == "named" {
            mount["storage"] = json!({"kind":"disk","capacity_mib":64});
        }
        mount["options"]["override_uid"] = json!(1);
        mount["options"]["override_gid"] = json!(1);
        reject(
            &json!({"mounts":saved(json!([mount]))}),
            "ownership overrides require",
        );
    }
    for (field, value) in [
        ("stat_virtualization", "relaxed"),
        ("host_permissions", "mirror"),
    ] {
        let mut mount = named("/disk", "volume");
        mount["storage"] = json!({"kind":"disk","capacity_mib":64});
        mount[field] = json!(value);
        reject(
            &json!({"mounts":saved(json!([mount]))}),
            "disk storage cannot apply directory",
        );
    }
}

#[test]
fn disk_capacity_fstype_and_optional_limits_are_not_silently_defaulted() {
    let mut mount = named("/disk", "volume");
    mount["storage"] = json!({"kind":"disk","capacity_mib":0});
    reject(
        &json!({"mounts":saved(json!([mount]))}),
        "capacity must be positive",
    );
    for fstype in ["", "ext4,ro", "ext4;ro", "ext4:ro", "ext4=ro", "SENTINEL\n"] {
        let mut mount = disk("/disk", "block");
        mount["fstype"] = json!(fstype);
        assert!(
            !reject(
                &json!({"mounts":saved(json!([mount]))}),
                "invalid guest filesystem"
            )
            .contains("SENTINEL")
        );
    }
    let mut mount = bind("/data", "data");
    mount["quota_mib"] = json!(0);
    let mut temp = tmpfs("/tmp");
    temp["size_mib"] = json!(0);
    let input = json!({"mounts":saved(json!([mount,temp]))});
    assert_eq!(serde_json::to_value(parse(&input)).unwrap(), input);
    for (mut mount, field) in [
        (bind("/data", "data"), "quota_mib"),
        (disk("/disk", "block"), "fstype"),
        (tmpfs("/tmp"), "size_mib"),
    ] {
        mount[field] = Value::Null;
        reject(&json!({"mounts":saved(json!([mount]))}), "SCFG_SCHEMA");
    }
}

#[test]
fn vsock_uses_existing_port_bounds_clock_reservation_and_transport_identity() {
    for (port, transport) in [(0, "stream"), (u32::MAX, "stream"), (123, "dgram")] {
        reject(
            &json!({"vsock":saved(json!([route(port,transport,"ipc")]))}),
            "invalid or reserved vsock port",
        );
    }
    let valid = json!({"vsock":saved(json!([route(123,"stream","clock.stream"),route(8080,"stream","stream"),route(8080,"dgram","dgram"),route(u32::MAX-1,"stream","upper")]))});
    parse(&valid);
    reject(
        &json!({"vsock":saved(json!([route(8080,"stream","first"),route(8080,"stream","second")]))}),
        "duplicate socket type and port",
    );
}

#[test]
fn mount_and_ipc_binding_kinds_are_derived_and_cross_checked_against_other_consumers() {
    let mut doc = super::document_tests::document();
    let mut file = bind("/file", "file");
    file["root_kind"] = json!("file");
    let mut named_disk = named("/named-disk", "named-disk");
    named_disk["storage"] = json!({"kind":"disk","capacity_mib":64});
    doc["active"]["storage"] = json!({"mounts":saved(json!([bind("/bind","directory"),disk("/disk","disk"),file,named("/named","named-dir"),named_disk,tmpfs("/tmp")])),"vsock":saved(json!([route(8080,"stream","stream"),route(8080,"dgram","dgram")]))});
    doc["bindings"] = json!({"directory":"filesystem_directory","disk":"disk_image","file":"filesystem_file","named-dir":"named_directory","named-disk":"named_disk","stream":"stream_socket","dgram":"datagram_socket"});
    let config = parse_doc(&doc);
    let uses = config.active_binding_uses().unwrap();
    assert_eq!(uses.len(), 7);
    assert!(
        uses["directory"]
            .consumers
            .contains(&SavedBindingConsumer::Mount)
    );
    assert!(
        uses["stream"]
            .consumers
            .contains(&SavedBindingConsumer::Vsock)
    );
    doc["active"]["runtime"]["cmd"] = saved(json!([{"kind":"binding","id":"directory"}]));
    assert!(doc_error(&doc).contains("incompatible destination kinds"));
}

#[test]
fn shared_mount_binding_is_valid_but_pending_routes_never_become_active() {
    let mut doc = super::document_tests::document();
    doc["active"]["storage"] =
        json!({"mounts":saved(json!([bind("/a","shared"),bind("/b","shared")]))});
    doc["pending"] = json!({"storage":{"vsock":saved(json!([route(8080,"stream","future")]))}});
    doc["bindings"] = json!({"shared":"filesystem_directory","future":"stream_socket"});
    let uses = parse_doc(&doc).active_binding_uses().unwrap();
    assert_eq!(uses.len(), 1);
    assert!(uses.contains_key("shared"));
    doc["bindings"].as_object_mut().unwrap().remove("future");
    assert!(doc_error(&doc).contains("not declared"));
}

#[test]
fn owned_references_must_match_the_complete_authoritative_inventory() {
    let mut manifest = super::document_tests::descriptor();
    manifest
        .set_owned_volumes(vec![owned_capture("/owned")])
        .unwrap();
    let original = manifest.to_canonical_bytes().unwrap();
    let valid = parse(&json!({"mounts":saved(json!([owned("/owned")]))}));
    valid.validate_owned_projection(&manifest).unwrap();
    assert_eq!(manifest.to_canonical_bytes().unwrap(), original);
    for mounts in [
        json!([]),
        json!([owned("/different")]),
        json!([bind("/owned", "external")]),
        json!([owned("/extra"), owned("/owned")]),
    ] {
        let config = parse(&json!({"mounts":saved(mounts)}));
        assert!(
            config
                .validate_owned_projection(&manifest)
                .unwrap_err()
                .to_string()
                .contains("disagree with authoritative")
        );
    }
    valid
        .validate_owned_projection(&super::document_tests::descriptor())
        .unwrap_err();
    // Unknown legacy details cannot remove authoritative existing owned storage.
    parse(&json!({"mounts":{"state":"unknown","reason":"not_recorded"}}))
        .validate_owned_projection(&manifest)
        .unwrap();
}

#[test]
fn pending_owned_declaration_does_not_claim_backing_or_active_demand() {
    let mut inventory = saved(json!([requested_owned("/future")]));
    inventory["origin"] = json!("configured");
    let storage = json!({"mounts":inventory});
    let parsed = parse(&storage);
    assert!(parsed.binding_uses().unwrap().is_empty());
    assert!(
        parsed
            .validate_active()
            .unwrap_err()
            .to_string()
            .contains("pending storage")
    );
    assert!(
        parsed
            .validate_owned_projection(&super::document_tests::descriptor())
            .is_err()
    );
    let mut doc = super::document_tests::document();
    doc["pending"] = json!({"storage":storage});
    let document = parse_doc(&doc);
    document
        .validate_legacy_projections(&super::document_tests::descriptor())
        .unwrap();
    assert!(
        !serde_json::to_string(&document.pending)
            .unwrap()
            .contains("mount_id")
    );
    doc["active"]["storage"] = doc["pending"]["storage"].clone();
    assert!(doc_error(&doc).contains("pending storage"));
}

#[test]
fn pending_owned_declaration_rejects_false_observation_and_invalid_policies() {
    let mut inventory = saved(json!([requested_owned("/future")]));
    reject(&json!({"mounts":inventory}), "configured origin");
    inventory["origin"] = json!("configured");
    let base = json!({"mounts":inventory});
    for (field, value) in [
        ("host", json!("PRIVATE_PATH")),
        ("mount_id", json!("PRIVATE_ID")),
        ("storage", json!({"kind":"disk","capacity_mib":0})),
        ("guest", json!("/not/../canonical")),
    ] {
        let mut invalid = base.clone();
        invalid["mounts"]["value"][0][field] = value;
        let error = reject(&invalid, "SCFG_");
        assert!(!error.contains("PRIVATE_"));
    }
    let mut invalid = base.clone();
    invalid["mounts"]["value"][0]["options"]["override_uid"] = json!(1000);
    reject(&invalid, "paired");
    let mut disk = base;
    disk["mounts"]["value"][0]["storage"] = json!({"kind":"disk","capacity_mib":64});
    parse(&disk);
    disk["mounts"]["value"][0]["host_permissions"] = json!("mirror");
    reject(&disk, "disk storage");
}

#[test]
fn document_projection_checks_do_not_allow_external_replacement_of_owned_backing() {
    let mut manifest = super::document_tests::descriptor();
    manifest
        .set_owned_volumes(vec![owned_capture("/owned")])
        .unwrap();
    let mut doc = super::document_tests::document();
    doc["active"]["storage"] = json!({"mounts":saved(json!([bind("/owned","external")]))});
    doc["bindings"] = json!({"external":"filesystem_directory"});
    assert!(
        parse_doc(&doc)
            .validate_legacy_projections(&manifest)
            .unwrap_err()
            .to_string()
            .contains("owned references disagree")
    );
}

#[test]
fn malformed_authoritative_owned_options_fail_without_echoing_source_values() {
    let mut manifest = super::document_tests::descriptor();
    let mut volume = owned_capture("/owned");
    volume.mount.options.override_uid = Some(0);
    manifest.set_owned_volumes(vec![volume]).unwrap();
    let config = parse(&json!({"mounts":saved(json!([owned("/owned")]))}));
    assert!(config.validate_owned_projection(&manifest).is_err());
    manifest.extensions.insert(
        crate::snapshot::OWNED_VOLUMES_EXTENSION.into(),
        json!({"SENTINEL":"PRIVATE"}),
    );
    assert!(
        !config
            .validate_owned_projection(&manifest)
            .unwrap_err()
            .to_string()
            .contains("SENTINEL")
    );
}

#[test]
fn projection_excludes_source_paths_socket_names_and_transient_named_creation() {
    let source = VolumeMount::Bind {
        host: PathBuf::from("/SENTINEL_PRIVATE/nonexistent"),
        guest: "/bind".into(),
        options: MountOptions::default(),
        stat_virtualization: StatVirtualization::Strict,
        host_permissions: HostPermissions::Private,
        follow_root_symlinks: false,
        quota_mib: Some(0),
    };
    let projected = SavedMount::from_source(
        &source,
        Some(SavedExternalMountCapture::Bind {
            binding: reference("filesystem"),
            root_kind: SavedBindRootKind::File,
        }),
    )
    .unwrap();
    let json = serde_json::to_value(projected).unwrap();
    assert_eq!(json["root_kind"], "file");
    assert!(!json.to_string().contains("SENTINEL"));
    assert!(SavedMount::from_source(&source, None).is_err());
    let source = VolumeMount::Named {
        name: "SENTINEL_VOLUME".into(),
        guest: "/named".into(),
        create: Some(NamedVolumeCreate {
            mode: NamedVolumeMode::EnsureExists,
            name: "SENTINEL_CREATE".into(),
            kind: VolumeKind::Disk,
            quota_mib: None,
            capacity_mib: Some(64),
            labels: vec![("SENTINEL_LABEL".into(), "PRIVATE".into())],
        }),
        options: MountOptions::default(),
        stat_virtualization: StatVirtualization::Strict,
        host_permissions: HostPermissions::Private,
        follow_root_symlinks: false,
    };
    let projected = SavedMount::from_source(
        &source,
        Some(SavedExternalMountCapture::Named {
            binding: reference("volume"),
            storage: SavedNamedStorage::Directory { quota_mib: Some(7) },
        }),
    )
    .unwrap();
    let json = serde_json::to_value(projected).unwrap();
    assert_eq!(json["storage"], json!({"kind":"directory","quota_mib":7}));
    assert!(!json.to_string().contains("SENTINEL"));
    assert!(json.get("create").is_none());
    let route = VsockRouteSpec {
        host_socket: PathBuf::from("/SENTINEL_SOCKET/never-read"),
        port: 8080,
        socket_type: VsockSocketType::Stream,
    };
    let json =
        serde_json::to_value(SavedVsockRoute::from_source(&route, reference("ipc")).unwrap())
            .unwrap();
    assert!(!json.to_string().contains("SENTINEL"));
    assert_eq!(json["port"], 8080);
}

#[test]
fn disk_owned_and_tmpfs_projection_preserves_semantics_without_host_backing_copy() {
    let disk_source = VolumeMount::DiskImage {
        host: PathBuf::from("/SENTINEL_DISK"),
        guest: "/disk".into(),
        format: DiskImageFormat::Vmdk,
        fstype: Some("ext4".into()),
        options: MountOptions {
            readonly: true,
            ..Default::default()
        },
    };
    let json = serde_json::to_value(
        SavedMount::from_source(
            &disk_source,
            Some(SavedExternalMountCapture::DiskImage {
                binding: reference("disk"),
            }),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(json["format"], "Vmdk");
    assert_eq!(json["options"]["readonly"], true);
    assert!(!json.to_string().contains("SENTINEL"));
    assert!(
        SavedMount::from_source(
            &disk_source,
            Some(SavedExternalMountCapture::Bind {
                binding: reference("wrong"),
                root_kind: SavedBindRootKind::File
            })
        )
        .is_err()
    );
    let source = VolumeMount::Tmpfs {
        guest: "/tmp".into(),
        size_mib: Some(32),
        options: MountOptions::default(),
    };
    let json = serde_json::to_value(SavedMount::from_source(&source, None).unwrap()).unwrap();
    assert_eq!(json["size_mib"], 32);
    let source = owned_capture("/owned").mount.to_mount();
    let json = serde_json::to_value(SavedMount::from_source(&source, None).unwrap()).unwrap();
    assert_eq!(json, owned("/owned"));
    assert!(
        SavedMount::from_source(
            &source,
            Some(SavedExternalMountCapture::DiskImage {
                binding: reference("wrong")
            })
        )
        .is_err()
    );
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

// Pending declarations use the same bounded guest policy, but never a payload identifier.
fn requested_owned(guest: &str) -> Value {
    json!({"kind":"requested_owned", "guest":guest,
        "storage":{"kind":"directory","quota_mib":0}, "options":options(),
        "stat_virtualization":"strict", "host_permissions":"private"})
}

fn options() -> Value {
    json!({"readonly":false,"noexec":false,"nosuid":false,"nodev":false})
}
fn saved(value: Value) -> Value {
    json!({"state":"value","origin":"observed","value":value})
}
fn reference(id: &str) -> SavedBindingReference {
    SavedBindingReference { id: id.into() }
}
fn bind(guest: &str, id: &str) -> Value {
    json!({"kind":"bind","guest":guest,"root_kind":"directory","binding":{"id":id},"options":options(),"stat_virtualization":"strict","host_permissions":"private","follow_root_symlinks":false})
}
fn named(guest: &str, id: &str) -> Value {
    json!({"kind":"named","guest":guest,"binding":{"id":id},"storage":{"kind":"directory"},"options":options(),"stat_virtualization":"strict","host_permissions":"private","follow_root_symlinks":false})
}
fn disk(guest: &str, id: &str) -> Value {
    json!({"kind":"disk_image","guest":guest,"binding":{"id":id},"format":"Raw","options":options()})
}
fn tmpfs(guest: &str) -> Value {
    json!({"kind":"tmpfs","guest":guest,"options":options()})
}
fn owned(guest: &str) -> Value {
    json!({"kind":"owned","guest":guest,"mount_id":owned_volume_mount_id(guest)})
}
fn route(port: u32, transport: &str, id: &str) -> Value {
    json!({"port":port,"socket_type":transport,"binding":{"id":id}})
}
fn parse(value: &Value) -> SavedStorageConfig {
    SavedStorageConfig::from_bytes(&serde_json::to_vec(value).unwrap()).unwrap()
}
fn reject(value: &Value, expected: &str) -> String {
    let error = SavedStorageConfig::from_bytes(&serde_json::to_vec(value).unwrap())
        .unwrap_err()
        .to_string();
    assert!(error.contains(expected), "expected {expected}; got {error}");
    error
}
fn parse_doc(value: &Value) -> SavedSandboxConfig {
    SavedSandboxConfig::from_bytes(&serde_json::to_vec(value).unwrap()).unwrap()
}
fn doc_error(value: &Value) -> String {
    SavedSandboxConfig::from_bytes(&serde_json::to_vec(value).unwrap())
        .err()
        .unwrap()
        .to_string()
}
fn owned_capture(guest: &str) -> OwnedVolumeCapture {
    OwnedVolumeCapture {
        mount_id: owned_volume_mount_id(guest),
        mount: OwnedMountSnapshot {
            guest: guest.into(),
            storage: OwnedVolumeStorage::Directory { quota_mib: None },
            options: MountOptions::default(),
            stat_virtualization: StatVirtualization::Strict,
            host_permissions: HostPermissions::Private,
        },
        data: OwnedVolumeData::Directory {
            descriptor: OwnedDirectoryPayload {
                digest: "a".repeat(64),
                bytes: 1,
            },
            files: vec![],
        },
    }
}
