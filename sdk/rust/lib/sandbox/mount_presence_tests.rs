//! Newly declared ownership defaults are evidence; historical omissions are not.

use microsandbox_types::snapshot::saved_config::{SavedMount, SavedValue};
use microsandbox_types::{MountOptions, SandboxSpecPatch, VolumeMount};
use serde_json::{Value, json};

use super::{SandboxBuilder, SandboxConfig, SandboxConfigPatch};
use crate::snapshot::saved_config::{RuntimeCaptureSource, StorageCaptureBindings};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn config() -> SandboxConfig {
    SandboxBuilder::new("mount-presence")
        .image("alpine")
        .volume("/data/", |mount| mount.tmpfs().size(16))
        .finish(None, None)
        .unwrap()
}

fn raw(config: &SandboxConfig) -> Value {
    serde_json::to_value(config.clone_for_persistence()).unwrap()
}

fn known(record: &Value) -> bool {
    RuntimeCaptureSource::from_recorded(record, None, None)
        .unwrap()
        .project_pending_storage(StorageCaptureBindings::default())
        .unwrap()
        .mounts
        .unwrap()
        .value()
        .is_some()
}

fn old_config() -> SandboxConfig {
    let mut record = raw(&config());
    // Preserve the earlier THP/network hint to model producers predating only mount evidence.
    record["field_presence"]
        .as_object_mut()
        .unwrap()
        .remove("default_mount_ownership");
    serde_json::from_value(record).unwrap()
}

fn tmpfs(guest: &str) -> VolumeMount {
    VolumeMount::Tmpfs {
        guest: guest.into(),
        size_mib: Some(16),
        options: MountOptions::default(),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn default_mount_ownership_survives_canonicalization_and_reconstruction() {
    let record = raw(&config());
    assert_eq!(record["mounts"][0]["guest"], "/data");
    assert!(record.pointer("/mounts/0/options/override_uid").is_none());
    assert!(record.pointer("/mounts/0/options/override_gid").is_none());
    assert_eq!(
        record["field_presence"]["default_mount_ownership"],
        json!([{"kind":"tmpfs","guest":"/data"}])
    );
    assert!(known(&record));
    let decoded: SandboxConfig = serde_json::from_value(record).unwrap();
    let rebuilt = SandboxBuilder::from(decoded).finish(None, None).unwrap();
    assert!(known(&raw(&rebuilt)));
}

#[test]
fn historical_mount_omission_stays_unknown_after_rebuild_and_patch_reconstruction() {
    let old = old_config();
    assert!(!known(&raw(&old)));
    let rebuilt = SandboxBuilder::from(old.clone())
        .overlay(SandboxConfigPatch::from_present_fields(old))
        .finish(None, None)
        .unwrap();
    assert!(!known(&raw(&rebuilt)));
}

#[test]
fn historical_mount_replacement_cannot_inherit_evidence_from_the_previous_list() {
    let rebuilt = SandboxBuilder::from(config())
        .overlay(SandboxConfigPatch::from_present_fields(old_config()))
        .finish(None, None)
        .unwrap();
    assert!(!known(&raw(&rebuilt)));
    // A genuinely known replacement still carries its own evidence.
    let rebuilt = SandboxBuilder::from(old_config())
        .overlay(SandboxConfigPatch::from_present_fields(config()))
        .finish(None, None)
        .unwrap();
    assert!(known(&raw(&rebuilt)));
}

#[test]
fn explicit_mount_append_does_not_certify_reconstructed_siblings() {
    for rebuilt in [
        SandboxBuilder::from(old_config()).volume("/new/", |mount| mount.tmpfs().size(16)),
        SandboxBuilder::from(old_config()).add_volume_mount(tmpfs("/new/")),
    ] {
        let rebuilt = rebuilt.finish(None, None).unwrap();
        let record = raw(&rebuilt);
        assert_eq!(
            record["field_presence"]["default_mount_ownership"],
            json!([{"kind":"tmpfs","guest":"/new"}])
        );
        assert!(!known(&record));
    }
    let replacement =
        SandboxConfigPatch::new().spec(SandboxSpecPatch::new().mounts(vec![tmpfs("/new/")]));
    let rebuilt = SandboxBuilder::from(old_config())
        .overlay(replacement)
        .finish(None, None)
        .unwrap();
    assert!(known(&raw(&rebuilt)));
}

#[test]
fn missing_options_parent_cannot_revive_evidence_after_reserialization() {
    let mut record = raw(&config());
    record["mounts"][0]
        .as_object_mut()
        .unwrap()
        .remove("options");
    assert!(!known(&record));
    let decoded: SandboxConfig = serde_json::from_value(record).unwrap();
    let rebuilt = SandboxBuilder::from(decoded).finish(None, None).unwrap();
    assert!(!known(&raw(&rebuilt)));
    let mut record = raw(&config());
    record.as_object_mut().unwrap().remove("mounts");
    let decoded: SandboxConfig = serde_json::from_value(record).unwrap();
    assert!(
        raw(&decoded)["field_presence"]
            .get("default_mount_ownership")
            .is_none()
    );
}

#[test]
fn missing_policy_field_cannot_gain_known_defaults_through_reserialization() {
    for field in ["readonly", "noexec", "nosuid", "nodev"] {
        let mut record = raw(&config());
        record["mounts"][0]["options"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(!known(&record), "{field}");
        let decoded: SandboxConfig = serde_json::from_value(record).unwrap();
        let rebuilt = SandboxBuilder::from(decoded).finish(None, None).unwrap();
        assert!(!known(&raw(&rebuilt)), "{field}");
    }
}

#[test]
fn changed_guest_kind_or_override_cannot_borrow_old_default_evidence() {
    for change in ["guest", "kind", "override"] {
        let mut record = raw(&config());
        match change {
            "guest" => record["mounts"][0]["guest"] = json!("/other"),
            "kind" => {
                record["mounts"][0]["type"] = json!("Owned");
                record["mounts"][0]["storage"] = json!({"kind":"directory","quota_mib":null});
            }
            _ => {
                record["mounts"][0]["options"]["override_uid"] = json!(1000);
                record["mounts"][0]["options"]["override_gid"] = json!(1000);
            }
        }
        let mut decoded: SandboxConfig = serde_json::from_value(record).unwrap();
        assert!(
            !decoded
                .field_presence
                .as_ref()
                .unwrap()
                .knows_default_mount_ownership(&decoded.spec.mounts[0]),
            "{change}"
        );
        // Even if an older writer later removes those overrides, the retired marker stays gone.
        decoded.spec.mounts[0] = tmpfs("/data");
        assert!(!known(&raw(&decoded)), "{change}");
    }
}

#[test]
fn mount_hint_contains_only_guest_identity_and_covers_owned_and_external_variants() {
    // Disk mounts validate host existence independently of the private evidence contract.
    let disk = tempfile::Builder::new()
        .prefix("PRIVATE_DISK")
        .tempfile()
        .unwrap();
    let config = SandboxBuilder::new("mount-presence")
        .image("alpine")
        .volume("/owned", |mount| mount.owned())
        .volume("/bind", |mount| mount.bind("/PRIVATE_HOST"))
        .volume("/named", |mount| mount.named("PRIVATE_VOLUME"))
        .volume("/disk", |mount| mount.disk(disk.path()))
        .finish(None, None)
        .unwrap();
    let record = raw(&config);
    let hint = &record["field_presence"]["default_mount_ownership"];
    assert_eq!(hint.as_array().unwrap().len(), 4);
    assert!(!hint.to_string().contains("PRIVATE_"));
    for entry in hint.as_array().unwrap() {
        assert_eq!(entry.as_object().unwrap().len(), 2);
        assert!(entry.get("guest").is_some() && entry.get("kind").is_some());
    }
    let only_owned = SandboxBuilder::new("owned-presence")
        .image("alpine")
        .volume("/owned", |mount| mount.owned())
        .finish(None, None)
        .unwrap();
    let record = raw(&only_owned);
    let pending = RuntimeCaptureSource::from_recorded(&record, None, None)
        .unwrap()
        .project_pending_storage(StorageCaptureBindings::default())
        .unwrap();
    assert!(
        matches!(pending.mounts, Some(SavedValue::Value { value, .. }) if matches!(value[0], SavedMount::RequestedOwned { .. }))
    );
}

#[test]
fn future_or_invalid_mount_hint_is_unknown_without_breaking_config_decode() {
    for hint in [
        json!([{"kind":"future","guest":"/data"}]),
        json!("wrong-shape"),
        json!([{"kind":"tmpfs","guest":"/data","host":"PRIVATE"}]),
    ] {
        let mut record = raw(&config());
        record["field_presence"]["default_mount_ownership"] = hint;
        let decoded: SandboxConfig = serde_json::from_value(record.clone()).unwrap();
        // Invalid positive mount hints cannot be revived by a rewrite; unrelated
        // negative network evidence may still be retained.
        assert!(!known(&record));
        assert!(!known(&raw(&decoded)));
    }
}
