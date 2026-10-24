//! Save the caller's explicit settings separately from the final sandbox configuration.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{SandboxConfig, SandboxConfigPatch};
use crate::MicrosandboxResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Saved caller overrides and the configuration they were recorded with.
#[derive(Serialize, Deserialize)]
struct StoredCallerConfigOverrides<P = SandboxConfigPatch> {
    /// SHA-256 of the exact resolved config JSON saved beside these overrides.
    /// A mismatch means the config changed without updating the overrides, so we ignore them.
    config_digest: [u8; 32],

    /// The caller's explicit settings, before defaults and managed policy were applied.
    caller_config_overrides: P,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SandboxConfig {
    pub(crate) fn caller_config_overrides_json(
        &self,
        resolved_json: &str,
    ) -> MicrosandboxResult<Option<String>> {
        self.caller_config_overrides
            .as_ref()
            .map(|caller_config_overrides| {
                Ok(serde_json::to_string(&StoredCallerConfigOverrides {
                    config_digest: Sha256::digest(resolved_json.as_bytes()).into(),
                    caller_config_overrides: (**caller_config_overrides).clone(),
                })?)
            })
            .transpose()
    }

    pub(crate) fn from_stored(
        resolved_json: &str,
        caller_config_overrides_json: Option<&str>,
    ) -> MicrosandboxResult<Self> {
        let mut config: Self = serde_json::from_str(resolved_json)?;
        if let Some(json) = caller_config_overrides_json {
            // Check the envelope before interpreting the patch: an older writer
            // may have invalidated overrides whose shape we no longer support.
            let caller_config_overrides: StoredCallerConfigOverrides<serde_json::Value> =
                serde_json::from_str(json)?;

            if caller_config_overrides.config_digest.as_slice()
                == Sha256::digest(resolved_json.as_bytes()).as_slice()
            {
                config.caller_config_overrides = Some(Box::new(serde_json::from_value(
                    caller_config_overrides.caller_config_overrides,
                )?));
            }
        }
        Ok(config)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use microsandbox_types::SandboxSpecPatch;

    #[test]
    fn stale_digest_ignores_an_incompatible_patch_but_matching_digest_rejects_it() {
        let config = SandboxConfig {
            caller_config_overrides: Some(Box::new(SandboxConfigPatch::new())),
            ..Default::default()
        };
        let resolved = serde_json::to_string(&config).unwrap();
        let stored = config
            .caller_config_overrides_json(&resolved)
            .unwrap()
            .unwrap();
        let mut stored: serde_json::Value = serde_json::from_str(&stored).unwrap();
        stored["caller_config_overrides"] = serde_json::json!("unsupported patch shape");
        let stored = stored.to_string();
        assert!(SandboxConfig::from_stored(&resolved, Some(&stored)).is_err());

        let mut changed: serde_json::Value = serde_json::from_str(&resolved).unwrap();
        changed["name"] = "edited-by-older-writer".into();
        let loaded = SandboxConfig::from_stored(&changed.to_string(), Some(&stored)).unwrap();
        assert!(loaded.caller_config_overrides.is_none());
        assert_eq!(loaded.spec.name, "edited-by-older-writer");
    }

    #[test]
    fn durable_caller_config_overrides_preserve_clears_and_omit_operation_state() {
        let mut caller_config_overrides = SandboxConfigPatch::new();
        caller_config_overrides.spec.runtime.workdir = Some(None);
        caller_config_overrides.spec.runtime.cmd = Some(Vec::new());
        caller_config_overrides.spec.security_profile =
            Some(microsandbox_types::SecurityProfile::Default);
        caller_config_overrides.spec.replace_env_mut(Vec::new());
        caller_config_overrides.replace_existing = Some(true);
        caller_config_overrides.snapshot_archive_source = Some("/private/input.msb".into());
        caller_config_overrides.registry_auth =
            Some(Some(microsandbox_types::RegistryAuth::Basic {
                username: "private-user".into(),
                password: "private-password".into(),
            }));
        let config = SandboxConfig {
            caller_config_overrides: Some(Box::new(caller_config_overrides)),
            ..Default::default()
        };

        let resolved = serde_json::to_string(&config).unwrap();
        let stored = config
            .caller_config_overrides_json(&resolved)
            .unwrap()
            .unwrap();
        assert!(!stored.contains("private-password"));
        assert!(!stored.contains("private-user"));
        assert!(!stored.contains("input.msb"));
        assert!(!stored.contains("replace_existing"));
        assert!(!resolved.contains("caller_config_overrides"));

        let restored = SandboxConfig::from_stored(&resolved, Some(&stored)).unwrap();
        let caller_config_overrides = restored.caller_config_overrides.unwrap();
        assert_eq!(caller_config_overrides.spec.runtime.workdir, Some(None));
        assert_eq!(caller_config_overrides.spec.runtime.cmd, Some(Vec::new()));
        assert!(caller_config_overrides.spec.init.is_none());
        assert_eq!(
            caller_config_overrides.spec.security_profile,
            Some(microsandbox_types::SecurityProfile::Default)
        );
        let mut target = SandboxConfig::default();
        target.spec.env.push(microsandbox_types::EnvVar {
            key: "INHERITED".into(),
            value: "value".into(),
        });
        caller_config_overrides.apply_to(&mut target);
        assert!(target.spec.env.is_empty());
    }

    #[test]
    fn legacy_or_older_writer_edits_do_not_invent_intent() {
        let config = SandboxConfig {
            caller_config_overrides: Some(Box::new(
                SandboxConfigPatch::new().spec(
                    SandboxSpecPatch::new()
                        .security_profile(microsandbox_types::SecurityProfile::Restricted),
                ),
            )),
            ..Default::default()
        };
        let resolved = serde_json::to_string(&config).unwrap();
        let stored = config
            .caller_config_overrides_json(&resolved)
            .unwrap()
            .unwrap();
        let mut edited: serde_json::Value = serde_json::from_str(&resolved).unwrap();
        edited["name"] = "changed-by-old-writer".into();
        let edited = serde_json::to_string(&edited).unwrap();

        for caller_config_overrides in [None, Some(stored.as_str())] {
            let rebuilt = SandboxConfig::from_stored(&edited, caller_config_overrides).unwrap();
            assert_eq!(rebuilt.spec.name, "changed-by-old-writer");
            assert!(rebuilt.caller_config_overrides.is_none());
        }
    }
}
