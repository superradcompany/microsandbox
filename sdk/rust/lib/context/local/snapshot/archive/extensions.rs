//! Interpret archive extension aliases without rewriting identity-bearing input metadata.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The archive layer has its own capabilities, separate from descriptor extensions.
#[derive(Clone, Copy)]
pub(super) enum Extension {
    MemberNames,
    Dependencies,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Extension {
    pub(super) fn canonical(self) -> &'static str {
        match self {
            Self::MemberNames => "microsandbox.member-names",
            Self::Dependencies => "microsandbox.dependencies",
        }
    }

    pub(super) fn historical(self) -> &'static str {
        match self {
            Self::MemberNames => "msb-snapshot-member-names",
            Self::Dependencies => "msb-snapshot-dependencies-v1",
        }
    }

    pub(super) fn recognizes(self, key: &str) -> bool {
        key == self.canonical() || key == self.historical()
    }

    /// Resolve aliases in memory. Keeping the map intact preserves its original wire dialect.
    pub(super) fn resolve<'a>(
        self,
        extensions: &'a BTreeMap<String, Value>,
        requires: &[String],
    ) -> MicrosandboxResult<Option<&'a Value>> {
        // Aliases cannot repair an invalid wire binding: the exact required spelling must
        // have a payload, even if the other spelling carries equivalent data.
        for key in requires.iter().filter(|key| self.recognizes(key)) {
            if !extensions.contains_key(key) {
                return Err(MicrosandboxError::SnapshotIntegrity(format!(
                    "required archive extension '{key}' has no matching payload"
                )));
            }
        }
        let canonical = extensions.get(self.canonical());
        let historical = extensions.get(self.historical());
        if let (Some(current), Some(previous)) = (canonical, historical)
            && current != previous
        {
            return Err(MicrosandboxError::SnapshotIntegrity(format!(
                "conflicting archive extension aliases '{}' and '{}'",
                self.canonical(),
                self.historical()
            )));
        }
        Ok(canonical.or(historical))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Check every packaged descriptor before opening an output file. The frozen list is the
/// v0.7.8 reader's contract, not the current reader's expanding capability set.
pub(super) fn validate_export(
    snapshots: &[super::Snapshot],
    target: crate::ArchiveCompatibility,
) -> MicrosandboxResult<()> {
    if target == crate::ArchiveCompatibility::Current {
        return Ok(());
    }
    for snapshot in snapshots {
        let manifest = snapshot.manifest();
        for requirement in &manifest.requires {
            if ![
                "microsandbox.guest-clock",
                "microsandbox.restore-defaults",
                "microsandbox.owned-volumes",
            ]
            .contains(&requirement.as_str())
            {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "checkpoint {} requires '{requirement}', which archive target 0.7.8 cannot preserve",
                    snapshot.id()
                )));
            }
        }
        // Its descriptor decoder knows the clock policy, but its archive admission rejects
        // the lifted non-default clock requirement. Do not export an archive it must refuse.
        if !manifest.guest_clock()?.is_sync() {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "checkpoint {} uses a non-default guest clock unsupported by archive target 0.7.8",
                snapshot.id()
            )));
        }
    }
    Ok(())
}

/// Only fresh inventories pass here. Readers retain input spelling; import never invokes this
/// function to normalize existing metadata. Checkpoint descriptors are not part of the rewrite.
pub(super) fn write_dialect(
    inventory: &mut super::ArchiveInventory,
    target: crate::ArchiveCompatibility,
) -> MicrosandboxResult<()> {
    for extension in [Extension::MemberNames, Extension::Dependencies] {
        let Some(payload) = extension
            .resolve(&inventory.extensions, &inventory.requires)?
            .cloned()
        else {
            continue;
        };
        let required = inventory
            .requires
            .iter()
            .any(|key| extension.recognizes(key));
        inventory.extensions.remove(extension.canonical());
        inventory.extensions.remove(extension.historical());
        inventory.requires.retain(|key| !extension.recognizes(key));
        let key = match target {
            crate::ArchiveCompatibility::Current => extension.canonical(),
            crate::ArchiveCompatibility::V0_7_8 => extension.historical(),
        };
        inventory.extensions.insert(key.into(), payload);
        // A released reader would silently discard canonical member names if optional.
        // Require recognition for new inventories; historical names retain their old contract.
        if required || target == crate::ArchiveCompatibility::Current {
            inventory.requires.push(key.into());
        }
    }
    inventory.requires.sort();
    if target == crate::ArchiveCompatibility::V0_7_8 {
        for requirement in &inventory.requires {
            if ![
                super::ARCHIVE_MEMBER_TRANSPORT_ALGORITHM,
                Extension::Dependencies.historical(),
            ]
            .contains(&requirement.as_str())
            {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "archive target 0.7.8 cannot preserve required capability '{requirement}'"
                )));
            }
        }
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn aliases_preserve_input_and_resolve_equal_payloads() {
        for extension in [Extension::MemberNames, Extension::Dependencies] {
            let payload = json!({"example": [1, 2]});
            for keys in [
                vec![extension.historical()],
                vec![extension.canonical()],
                vec![extension.historical(), extension.canonical()],
            ] {
                let extensions: BTreeMap<_, _> = keys
                    .iter()
                    .map(|key| ((*key).to_string(), payload.clone()))
                    .collect();
                let requires = keys
                    .iter()
                    .map(|key| (*key).to_string())
                    .collect::<Vec<_>>();
                let original = serde_json::to_vec(&extensions).unwrap();
                assert_eq!(
                    extension.resolve(&extensions, &requires).unwrap(),
                    Some(&payload)
                );
                assert_eq!(serde_json::to_vec(&extensions).unwrap(), original);
            }
        }
    }

    #[test]
    fn required_alias_cannot_borrow_another_keys_payload() {
        for extension in [Extension::MemberNames, Extension::Dependencies] {
            for (present, missing) in [
                (extension.historical(), extension.canonical()),
                (extension.canonical(), extension.historical()),
            ] {
                let extensions = BTreeMap::from([(present.to_string(), json!({}))]);
                let error = extension
                    .resolve(&extensions, &[missing.to_string()])
                    .unwrap_err();
                assert!(error.to_string().contains(missing));
                assert!(error.to_string().contains("no matching payload"));
            }
        }
    }

    #[test]
    fn conflicting_aliases_refuse_even_when_optional() {
        for extension in [Extension::MemberNames, Extension::Dependencies] {
            let extensions = BTreeMap::from([
                (extension.canonical().to_string(), json!({"value": 1})),
                (extension.historical().to_string(), json!({"value": 2})),
            ]);
            assert!(
                extension
                    .resolve(&extensions, &[])
                    .unwrap_err()
                    .to_string()
                    .contains("conflicting")
            );
        }
    }
}
