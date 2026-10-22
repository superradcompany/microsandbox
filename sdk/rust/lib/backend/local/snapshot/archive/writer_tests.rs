//! Exercise writer dialects through real archives, rather than only key-renaming helpers.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use super::tests::{grouped_archive_manifest, write_grouped_archive_fixture};
use super::*;
use crate::ArchiveCompatibility;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn members(path: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut archive = tar::Archive::new(std::fs::File::open(path).unwrap());
    archive
        .entries()
        .unwrap()
        .map(|entry| {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().into_owned();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            (path, bytes)
        })
        .collect()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn archive_targets_preserve_names_and_descriptor_identity_through_import_export() {
    let temp = tempfile::tempdir().unwrap();
    let local = crate::test_support::local_backend_builder(temp.path().join("home"))
        .build()
        .await
        .unwrap();
    let mut manifest = grouped_archive_manifest(817, None);
    manifest.extensions.insert(
        "org.microsandbox.capture-labels".into(),
        serde_json::json!({"old":"label"}),
    );
    let source = temp.path().join("artifact");
    write_grouped_archive_fixture(&source, &manifest);
    std::fs::write(
        source.join("group-member.json"),
        br#"{"schema":"microsandbox.snapshot-group-member/1","name":"ready"}"#,
    )
    .unwrap();
    let descriptor = std::fs::read(source.join(DESCRIPTOR_FILENAME)).unwrap();
    let descriptor_path = format!("snapshots/{}/snapshot.json", manifest.snapshot_id);
    for (target, name, key) in [
        (
            ArchiveCompatibility::Current,
            "canonical",
            "microsandbox.member-names",
        ),
        (
            ArchiveCompatibility::V0_7_8,
            "historical",
            "msb-snapshot-member-names",
        ),
    ] {
        let output = temp.path().join(format!("{name}.tar"));
        save_snapshot(
            &local,
            source.to_str().unwrap(),
            &output,
            SaveOpts::default().plain_tar().compatibility(target),
        )
        .await
        .unwrap();
        let entries = members(&output);
        assert_eq!(entries[&descriptor_path], descriptor);
        let inventory: ArchiveInventory = serde_json::from_slice(&entries["archive.json"]).unwrap();
        assert_eq!(inventory.extensions.len(), 1);
        assert_eq!(
            inventory.extensions[key][manifest.snapshot_id.as_str()],
            "ready"
        );
        assert_eq!(
            inventory.members[0].descriptor_digest,
            manifest.digest().unwrap()
        );
        assert_eq!(
            inventory.requires.iter().any(|required| required == key),
            target == ArchiveCompatibility::Current
        );
        // Canonical naming is deliberately must-understand so old readers cannot silently
        // discard a name. Explicit historical output retains the released optional binding.
        let loaded = load_snapshot(&local, &output, Some(&temp.path().join(name)))
            .await
            .unwrap();
        assert_eq!(
            super::super::group::member_name(loaded.path())
                .unwrap()
                .as_deref(),
            Some("ready")
        );
        assert_eq!(
            std::fs::read(loaded.path().join(DESCRIPTOR_FILENAME)).unwrap(),
            descriptor
        );
        let again = temp.path().join(format!("{name}-fresh-export.tar"));
        save_snapshot(
            &local,
            loaded.path().to_str().unwrap(),
            &again,
            SaveOpts::default().plain_tar(),
        )
        .await
        .unwrap();
        let repacked = members(&again);
        let fresh: ArchiveInventory = serde_json::from_slice(&repacked["archive.json"]).unwrap();
        assert!(fresh.extensions.contains_key("microsandbox.member-names"));
        assert!(!fresh.extensions.contains_key("msb-snapshot-member-names"));
        assert_eq!(repacked[&descriptor_path], descriptor);
    }
    assert_eq!(
        std::fs::read(source.join(DESCRIPTOR_FILENAME)).unwrap(),
        descriptor
    );
}

#[tokio::test]
async fn historical_archive_refuses_unrepresentable_clock_before_touching_output() {
    let temp = tempfile::tempdir().unwrap();
    let local = crate::test_support::local_backend_builder(temp.path().join("home"))
        .build()
        .await
        .unwrap();
    let mut manifest = grouped_archive_manifest(818, None);
    manifest
        .set_guest_clock(microsandbox_types::GuestClockPolicy::Off)
        .unwrap();
    let source = temp.path().join("artifact");
    write_grouped_archive_fixture(&source, &manifest);
    let output = temp.path().join("existing.msb");
    std::fs::write(&output, b"keep existing archive").unwrap();
    let error = save_snapshot(
        &local,
        source.to_str().unwrap(),
        &output,
        SaveOpts::default().compatibility(ArchiveCompatibility::V0_7_8),
    )
    .await
    .unwrap_err();
    assert!(
        error.to_string().contains("archive target 0.7.8"),
        "{error}"
    );
    assert_eq!(std::fs::read(&output).unwrap(), b"keep existing archive");
    assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 3);
}

#[test]
fn archive_dependency_dialect_keeps_the_exact_required_payload_binding() {
    for (target, expected) in [
        (ArchiveCompatibility::Current, "microsandbox.dependencies"),
        (ArchiveCompatibility::V0_7_8, "msb-snapshot-dependencies-v1"),
    ] {
        let payload = serde_json::json!({"disks": [], "memory": [], "owned": []});
        let mut inventory: ArchiveInventory = serde_json::from_value(serde_json::json!({
            "schema": "microsandbox.snapshot-archive/1", "head": "snap_00000000000000000000000000000331",
            "completeness": "dependent", "members": [], "entries": [],
            "limits": {"entry_count":0,"encoded_bytes":0,"apparent_bytes":0},
            "extensions": {"msb-snapshot-dependencies-v1":payload},
            "requires": ["msb-snapshot-dependencies-v1"],
        })).unwrap();
        extensions::write_dialect(&mut inventory, target).unwrap();
        assert_eq!(inventory.requires, vec![expected.to_string()]);
        assert_eq!(inventory.extensions.len(), 1);
        assert_eq!(inventory.extensions[expected], payload);
    }
}

#[tokio::test]
#[ignore = "requires MSB_ARCHIVE_LEGACY_CLI pointing to a released 0.7.8 binary"]
async fn released_reader_accepts_historical_target_and_refuses_canonical_names() {
    let executable =
        std::env::var_os("MSB_ARCHIVE_LEGACY_CLI").expect("set MSB_ARCHIVE_LEGACY_CLI");
    let temp = tempfile::tempdir().unwrap();
    let local = crate::test_support::local_backend_builder(temp.path().join("source-home"))
        .build()
        .await
        .unwrap();
    let manifest = grouped_archive_manifest(819, None);
    let source = temp.path().join("artifact");
    write_grouped_archive_fixture(&source, &manifest);
    std::fs::write(
        source.join("group-member.json"),
        br#"{"schema":"microsandbox.snapshot-group-member/1","name":"ready"}"#,
    )
    .unwrap();
    for (target, group) in [
        (ArchiveCompatibility::Current, "canonical"),
        (ArchiveCompatibility::V0_7_8, "historical"),
    ] {
        let output = temp.path().join(format!("{group}.msb"));
        save_snapshot(
            &local,
            source.to_str().unwrap(),
            &output,
            SaveOpts::default().compatibility(target),
        )
        .await
        .unwrap();
        let home = temp.path().join(format!("recipient-{group}"));
        let result = std::process::Command::new(&executable)
            .env("MSB_HOME", &home)
            .env("MSB_CONFIG_PATH", home.join("missing.json"))
            .args(["snap", "load"])
            .arg(&output)
            .args(["--group", group])
            .output()
            .unwrap();
        let diagnostic = String::from_utf8_lossy(&result.stderr);
        if target == ArchiveCompatibility::Current {
            assert!(
                !result.status.success(),
                "released reader silently accepted unknown names"
            );
            assert!(
                diagnostic.contains("microsandbox.member-names"),
                "{diagnostic}"
            );
        } else {
            assert!(result.status.success(), "{diagnostic}");
            assert_eq!(
                super::super::group::member_name(
                    &home
                        .join("snapshots")
                        .join(group)
                        .join(manifest.snapshot_id.as_str())
                )
                .unwrap()
                .as_deref(),
                Some("ready")
            );
        }
    }
}
