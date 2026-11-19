//! Host-private observations of registered backing at the paused capture boundary.

use std::collections::BTreeMap;

#[cfg(all(feature = "runner", unix))]
use std::collections::BTreeSet;
#[cfg(feature = "runner")]
use std::fs::File;

#[cfg(all(feature = "runner", unix))]
use microsandbox_filesystem::{CapturedRuntimeScripts, RuntimeScriptLimits};
use serde::{Deserialize, Serialize};
#[cfg(feature = "runner")]
use serde_json::Value;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Closed, value-free reasons why actual backing cannot be used as capture evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScriptBackingUnknown {
    /// No confirmed source registration inventory was available.
    SourceUnavailable,
    /// This runtime could not retain an observation handle for its actual mounted backend.
    BackendUnavailable,
    /// Registered files could not be observed safely within the supported representation/bounds.
    Unreadable,
    /// Backing changed between observation and checkpoint publication.
    Changed,
}

/// Guest metadata for a pinned backing directory, separate from host access permissions.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedScriptDirectory {
    /// Guest-visible owner.
    pub uid: u32,
    /// Guest-visible group.
    pub gid: u32,
    /// Ordinary guest permission bits.
    pub mode: u16,
}

/// Exact observed bytes and guest metadata, never the declared desired script text.
/// Deliberately has no Debug implementation: body and names require capture-time exclusions.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedScriptBacking {
    /// UTF-8 content from the mounted backing file, without normalization or wrapping.
    pub content: String,
    /// Guest-visible owner, not source-host ownership.
    pub uid: u32,
    /// Guest-visible group, not source-host ownership.
    pub gid: u32,
    /// Ordinary guest permission bits, including zero.
    pub mode: u16,
}

/// Host-private evidence, not an archive payload or full-state resource admission result.
#[derive(Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScriptBackingEvidence {
    /// Missing evidence stays unknown; desired configuration must not fill this gap.
    Unknown {
        /// Safe diagnostic classification without names, paths or contents.
        reason: ScriptBackingUnknown,
    },
    /// Each registered file was observed and revalidated while the VM remained paused.
    Observed {
        /// Metadata of the mounted runtime root, not its source-host pathname.
        runtime_directory: CapturedScriptDirectory,
        /// Metadata of the registered-script directory below that root.
        scripts_directory: CapturedScriptDirectory,
        /// Exact registration inventory, including a known-empty inventory.
        files: BTreeMap<String, CapturedScriptBacking>,
    },
}

#[cfg(feature = "runner")]
pub(super) enum ScriptBackingObservation {
    Unknown(ScriptBackingUnknown),
    #[cfg(unix)]
    Observed(Box<CapturedRuntimeScripts>),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "runner")]
impl ScriptBackingObservation {
    pub(super) fn observe(root: Option<&File>, source: Option<&Value>) -> Self {
        let Some(registrations) = source
            .and_then(|source| source.get("runtime"))
            .and_then(|runtime| runtime.get("scripts"))
            .and_then(Value::as_object)
        else {
            return Self::Unknown(ScriptBackingUnknown::SourceUnavailable);
        };
        // Use keys only. A declaration's body can differ from the backing used by the VM.
        // Reject malformed private input without formatting its values into an error.
        if registrations.len() > 256 || registrations.values().any(|value| !value.is_string()) {
            return Self::Unknown(ScriptBackingUnknown::SourceUnavailable);
        }
        let Some(root) = root else {
            return Self::Unknown(ScriptBackingUnknown::BackendUnavailable);
        };
        #[cfg(unix)]
        {
            let names = registrations.keys().cloned().collect::<BTreeSet<_>>();
            match CapturedRuntimeScripts::capture(
                root,
                &names,
                RuntimeScriptLimits {
                    max_entries: 256,
                    max_script_bytes: 64 * 1024,
                    max_total_bytes: 256 * 1024,
                },
            ) {
                Ok(observed) => Self::Observed(Box::new(observed)),
                Err(_) => Self::Unknown(ScriptBackingUnknown::Unreadable),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = root;
            Self::Unknown(ScriptBackingUnknown::BackendUnavailable)
        }
    }

    pub(super) fn finish(self) -> ScriptBackingEvidence {
        match self {
            Self::Unknown(reason) => ScriptBackingEvidence::Unknown { reason },
            #[cfg(unix)]
            Self::Observed(observed) => {
                // This runs before the private receipt and immutable checkpoint are published.
                // Unknown preserves legacy capture; a saved-config consumer must demand evidence.
                if observed.revalidate().is_err() {
                    return ScriptBackingEvidence::Unknown {
                        reason: ScriptBackingUnknown::Changed,
                    };
                }
                let files = observed
                    .observations()
                    .map(|(name, content, metadata)| {
                        (
                            name.to_owned(),
                            CapturedScriptBacking {
                                content: content.to_owned(),
                                uid: metadata.uid,
                                gid: metadata.gid,
                                mode: metadata.mode,
                            },
                        )
                    })
                    .collect();
                let (runtime, scripts) = observed.directory_metadata();
                ScriptBackingEvidence::Observed {
                    runtime_directory: CapturedScriptDirectory {
                        uid: runtime.uid,
                        gid: runtime.gid,
                        mode: runtime.mode,
                    },
                    scripts_directory: CapturedScriptDirectory {
                        uid: scripts.uid,
                        gid: scripts.gid,
                        mode: scripts.mode,
                    },
                    files,
                }
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, feature = "runner", unix))]
mod tests {
    use std::{fs, os::unix::fs::symlink};

    use microsandbox_filesystem::{PassthroughConfig, PassthroughFs};
    use serde_json::json;

    use super::*;

    fn fixture() -> (tempfile::TempDir, File) {
        let home = tempfile::tempdir().unwrap();
        fs::create_dir(home.path().join("scripts")).unwrap();
        let backend = PassthroughFs::new(PassthroughConfig {
            root_dir: home.path().to_owned(),
            inject_init: false,
            ..Default::default()
        })
        .unwrap();
        let pinned = backend.pin_runtime_script_root().unwrap();
        (home, pinned)
    }

    fn source() -> Value {
        json!({"runtime": {"scripts": {"task": "declared bytes must not be used"}}})
    }

    #[test]
    fn actual_bytes_and_guest_permissions_survive_after_source_deletion() {
        let (home, root) = fixture();
        let file = home.path().join("scripts/task");
        fs::write(&file, "guest changed λ\r\n").unwrap();
        PassthroughFs::set_runtime_backing_permissions(&File::open(file).unwrap(), 42, 43, 0o640)
            .unwrap();
        fs::write(
            home.path().join("scripts/unregistered"),
            "PRIVATE_UNREGISTERED",
        )
        .unwrap();
        PassthroughFs::set_runtime_backing_permissions(
            &File::open(home.path().join("scripts")).unwrap(),
            44,
            45,
            0o710,
        )
        .unwrap();
        let evidence = ScriptBackingObservation::observe(Some(&root), Some(&source())).finish();
        let ScriptBackingEvidence::Observed {
            files,
            scripts_directory,
            ..
        } = &evidence
        else {
            panic!("not observed")
        };
        assert_eq!(
            (
                scripts_directory.uid,
                scripts_directory.gid,
                scripts_directory.mode
            ),
            (44, 45, 0o710)
        );
        assert_eq!(files.len(), 1);
        let actual = &files["task"];
        assert_eq!(actual.content, "guest changed λ\r\n");
        assert_eq!((actual.uid, actual.gid, actual.mode), (42, 43, 0o640));
        let bytes = serde_json::to_vec(&evidence).unwrap();
        drop(home);
        let decoded: ScriptBackingEvidence = serde_json::from_slice(&bytes).unwrap();
        let ScriptBackingEvidence::Observed { files, .. } = decoded else {
            panic!("lost evidence")
        };
        assert_eq!(files["task"].content, actual.content);
        assert!(
            !String::from_utf8(bytes)
                .unwrap()
                .contains("PRIVATE_UNREGISTERED")
        );
    }

    #[test]
    fn changed_backing_becomes_unknown_without_disclosing_either_version() {
        let (home, root) = fixture();
        let file = home.path().join("scripts/task");
        fs::write(&file, "PRIVATE_BEFORE").unwrap();
        let observed = ScriptBackingObservation::observe(Some(&root), Some(&source()));
        fs::write(file, "PRIVATE_AFTER").unwrap();
        let evidence = observed.finish();
        assert!(matches!(
            evidence,
            ScriptBackingEvidence::Unknown {
                reason: ScriptBackingUnknown::Changed
            }
        ));
        assert!(
            !serde_json::to_string(&evidence)
                .unwrap()
                .contains("PRIVATE")
        );
    }

    #[test]
    fn linked_backing_is_unknown_without_changing_capture_result_contract() {
        for link_after_observation in [false, true] {
            let (home, root) = fixture();
            let file = home.path().join("scripts/task");
            fs::write(&file, "PRIVATE_BODY").unwrap();
            let alias = home.path().join("PRIVATE_ALIAS");
            if !link_after_observation {
                fs::hard_link(&file, &alias).unwrap();
            }
            let observed = ScriptBackingObservation::observe(Some(&root), Some(&source()));
            if link_after_observation {
                fs::hard_link(&file, &alias).unwrap();
            }
            // Only the optional backing evidence becomes unavailable. Its existing
            // representation contains neither script contents nor the alias pathname.
            let evidence = observed.finish();
            let expected = if link_after_observation {
                ScriptBackingUnknown::Changed
            } else {
                ScriptBackingUnknown::Unreadable
            };
            assert!(
                matches!(evidence, ScriptBackingEvidence::Unknown { reason } if reason == expected)
            );
            let encoded = serde_json::to_string(&evidence).unwrap();
            assert!(!encoded.contains("PRIVATE") && !encoded.contains("declared"));
        }
    }

    #[test]
    fn symlink_and_missing_backing_do_not_read_or_reuse_declared_content() {
        let (home, root) = fixture();
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::write(outside.path(), "PRIVATE_OUTSIDE").unwrap();
        for linked in [false, true] {
            if linked {
                symlink(outside.path(), home.path().join("scripts/task")).unwrap();
            }
            let evidence = ScriptBackingObservation::observe(Some(&root), Some(&source())).finish();
            assert!(matches!(
                evidence,
                ScriptBackingEvidence::Unknown {
                    reason: ScriptBackingUnknown::Unreadable
                }
            ));
            let serialized = serde_json::to_string(&evidence).unwrap();
            assert!(!serialized.contains("PRIVATE"));
            assert!(!serialized.contains("declared"));
        }
    }

    #[test]
    fn source_absence_is_distinct_from_known_empty_and_backend_unavailability() {
        let (_home, root) = fixture();
        assert!(matches!(
            ScriptBackingObservation::observe(Some(&root), None).finish(),
            ScriptBackingEvidence::Unknown {
                reason: ScriptBackingUnknown::SourceUnavailable
            }
        ));
        assert!(matches!(
            ScriptBackingObservation::observe(None, Some(&source())).finish(),
            ScriptBackingEvidence::Unknown {
                reason: ScriptBackingUnknown::BackendUnavailable
            }
        ));
        let empty = json!({"runtime": {"scripts": {}}});
        let ScriptBackingEvidence::Observed { files, .. } =
            ScriptBackingObservation::observe(Some(&root), Some(&empty)).finish()
        else {
            panic!("empty inventory unknown")
        };
        assert!(files.is_empty());
    }

    #[test]
    fn observation_uses_mounted_inode_after_pathname_replacement() {
        let (home, root) = fixture();
        fs::write(home.path().join("scripts/task"), "mounted").unwrap();
        let parent = tempfile::tempdir().unwrap();
        fs::rename(home.path(), parent.path().join("mounted")).unwrap();
        fs::create_dir_all(home.path().join("scripts")).unwrap();
        fs::write(home.path().join("scripts/task"), "replacement").unwrap();
        let ScriptBackingEvidence::Observed { files, .. } =
            ScriptBackingObservation::observe(Some(&root), Some(&source())).finish()
        else {
            panic!("mounted inode unavailable")
        };
        assert_eq!(files["task"].content, "mounted");
    }
}
