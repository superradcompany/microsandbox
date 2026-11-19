//! Host-private environment origins. These are evidence for sanitization, never portable values.

use std::{collections::BTreeMap, fmt};

use microsandbox_types::{EnvVar, HandoffInit};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EnvironmentOrigin {
    Literal,
    Host,
    Unknown,
}

/// A digest binds origin to a value without making another copy of its private contents.
/// It is not authorization or a credential and must not be emitted into an archive.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnvironmentEntry {
    digest: [u8; 32],
    origin: EnvironmentOrigin,
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnvironmentProvenance {
    pub(crate) env: BTreeMap<String, EnvironmentEntry>,
    pub(crate) init_env: BTreeMap<String, EnvironmentEntry>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl EnvironmentEntry {
    pub(crate) fn new(value: &str, origin: EnvironmentOrigin) -> Self {
        Self {
            digest: Sha256::digest(value.as_bytes()).into(),
            origin,
        }
    }

    fn matches(&self, value: &str) -> bool {
        self.digest == <[u8; 32]>::from(Sha256::digest(value.as_bytes()))
    }
}

impl EnvironmentProvenance {
    pub(crate) fn declare_env(&mut self, key: &str, value: &str, origin: EnvironmentOrigin) {
        self.env
            .insert(key.into(), EnvironmentEntry::new(value, origin));
    }

    /// A retained patch carries evidence, not a fresh declaration. Never relabel a known host
    /// value or missing retained origin as a literal simply because a patch was reconstructed.
    pub(crate) fn declare_env_input(&mut self, key: &str, value: &str, supplied: Option<&Self>) {
        let origin = match supplied {
            None => EnvironmentOrigin::Literal,
            Some(supplied) => supplied
                .env
                .get(key)
                .filter(|entry| entry.matches(value))
                .map_or(EnvironmentOrigin::Unknown, |entry| entry.origin),
        };
        self.declare_env(key, value, origin);
    }

    pub(crate) fn declare_init_input(&mut self, init: &HandoffInit, supplied: Option<&Self>) {
        self.init_env = init
            .env
            .iter()
            .map(|(key, value)| {
                let origin = match supplied {
                    None => EnvironmentOrigin::Literal,
                    Some(supplied) => supplied
                        .init_env
                        .get(key)
                        .filter(|entry| entry.matches(value))
                        .map_or(EnvironmentOrigin::Unknown, |entry| entry.origin),
                };
                (key.clone(), EnvironmentEntry::new(value, origin))
            })
            .collect();
    }

    pub(crate) fn declare_init(&mut self, init: Option<&HandoffInit>) {
        self.init_env = init
            .into_iter()
            .flat_map(|init| &init.env)
            .map(|(key, value)| {
                (
                    key.clone(),
                    EnvironmentEntry::new(value, EnvironmentOrigin::Literal),
                )
            })
            .collect();
    }

    /// Last declaration wins, matching environment delivery. A changed value never borrows
    /// stale evidence. Reconstruction may retain known entries but cannot infer missing ones.
    pub(crate) fn resolve(&mut self, env: &[EnvVar], init: Option<&HandoffInit>, unknown: bool) {
        self.env = resolve_map(
            env.iter().map(|v| (v.key.as_str(), v.value.as_str())),
            &self.env,
            None,
            unknown,
        );
        self.init_env = resolve_map(
            init.into_iter()
                .flat_map(|i| i.env.iter())
                .map(|(k, v)| (k.as_str(), v.as_str())),
            &self.init_env,
            Some(&self.env),
            unknown,
        );
    }

    /// Used after direct config edits and at capture: pruning differs from fresh construction.
    /// Even an unchanged-looking newly added key has no evidence until explicitly declared.
    pub(crate) fn retain_matching(&mut self, env: &[EnvVar], init: Option<&HandoffInit>) {
        let values: BTreeMap<_, _> = env
            .iter()
            .map(|v| (v.key.as_str(), v.value.as_str()))
            .collect();
        self.env.retain(|key, entry| {
            values
                .get(key.as_str())
                .is_some_and(|value| entry.matches(value))
        });
        let values: BTreeMap<_, _> = init
            .into_iter()
            .flat_map(|i| &i.env)
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        self.init_env.retain(|key, entry| {
            values
                .get(key.as_str())
                .is_some_and(|value| entry.matches(value))
        });
    }

    /// Portable projection may copy only a positively classified, unchanged literal.
    /// Missing, host-derived and invalidated entries all require a binding or exclusion.
    pub(crate) fn is_literal(&self, key: &str, value: &str, init: bool) -> bool {
        let entries = if init { &self.init_env } else { &self.env };
        entries
            .get(key)
            .is_some_and(|entry| entry.origin == EnvironmentOrigin::Literal && entry.matches(value))
    }

    pub(crate) fn matches(&self, env: &[EnvVar], init: Option<&HandoffInit>) -> bool {
        let mut retained = self.clone();
        retained.retain_matching(env, init);
        &retained == self
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for EnvironmentProvenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvironmentProvenance")
            .finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn resolve_map<'a>(
    values: impl Iterator<Item = (&'a str, &'a str)>,
    entries: &BTreeMap<String, EnvironmentEntry>,
    inherited: Option<&BTreeMap<String, EnvironmentEntry>>,
    unknown: bool,
) -> BTreeMap<String, EnvironmentEntry> {
    // Collapse before checking evidence so duplicate keys cannot inherit an earlier value's origin.
    let values: BTreeMap<_, _> = values.collect();
    values
        .into_iter()
        .filter_map(|(key, value)| {
            match entries
                .get(key)
                .or_else(|| inherited.and_then(|map| map.get(key)))
            {
                Some(entry) if entry.matches(value) => Some((key.into(), entry.clone())),
                // Keep negative evidence across layering and auto-init inheritance. Dropping
                // it would let a later fresh-resolution pass mistake this value for a literal.
                Some(_) => Some((
                    key.into(),
                    EnvironmentEntry::new(value, EnvironmentOrigin::Unknown),
                )),
                None if !unknown => Some((
                    key.into(),
                    EnvironmentEntry::new(value, EnvironmentOrigin::Literal),
                )),
                None => None,
            }
        })
        .collect()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, feature = "local"))]
mod tests {
    use microsandbox_image::ImageConfig;
    use microsandbox_types::SandboxSpecPatch;

    use super::*;
    use crate::sandbox::SandboxBuilder;
    use crate::{SandboxConfig, SandboxConfigPatch};

    fn finish(builder: SandboxBuilder) -> SandboxConfig {
        builder.finish(None, None).unwrap()
    }

    fn origin(config: &SandboxConfig, key: &str, init: bool) -> Option<EnvironmentOrigin> {
        let evidence = config.environment_provenance.as_ref()?;
        let map = if init {
            &evidence.init_env
        } else {
            &evidence.env
        };
        map.get(key).map(|entry| entry.origin)
    }

    #[test]
    fn explicit_and_host_values_keep_order_and_last_declaration_origin() {
        let config = finish(
            SandboxBuilder::new("env-origin")
                .image("alpine")
                .env("KEY", "literal")
                .host_env("KEY".into(), "private-value".into())
                .host_env("EMPTY".into(), "".into()),
        );
        assert_eq!(config.spec.env.len(), 3);
        assert!(origin(&config, "KEY", false) == Some(EnvironmentOrigin::Host));
        assert!(origin(&config, "EMPTY", false) == Some(EnvironmentOrigin::Host));
        let serialized = serde_json::to_string(&config.environment_provenance).unwrap();
        assert!(!serialized.contains("private-value"));
        assert!(!format!("{:?}", config.environment_provenance).contains("KEY"));
        let config = finish(SandboxBuilder::from(config).env("KEY", "private-value"));
        assert!(origin(&config, "KEY", false) == Some(EnvironmentOrigin::Literal));
    }

    #[test]
    fn sparse_override_and_replace_preserve_only_effective_origins() {
        let config =
            finish(
                SandboxBuilder::new("env-origin")
                    .image("alpine")
                    .host_env("KEY".into(), "private-value".into())
                    .host_env("KEEP".into(), "retained".into())
                    .overlay(SandboxConfigPatch::new().spec(
                        SandboxSpecPatch::new().env(vec![EnvVar::new("KEY", "private-value")]),
                    )),
            );
        assert!(origin(&config, "KEY", false) == Some(EnvironmentOrigin::Literal));
        assert!(origin(&config, "KEEP", false) == Some(EnvironmentOrigin::Host));
        let replaced =
            finish(SandboxBuilder::from(config).overlay(
                SandboxConfigPatch::new().spec(SandboxSpecPatch::new().replace_env(vec![])),
            ));
        assert!(replaced.spec.env.is_empty());
        assert!(replaced.environment_provenance.unwrap().env.is_empty());
    }

    #[test]
    fn older_records_stay_unknown_until_each_key_is_declared() {
        let known = finish(
            SandboxBuilder::new("env-origin")
                .image("alpine")
                .env("OLD", "value"),
        );
        let mut raw = serde_json::to_value(known).unwrap();
        raw.as_object_mut()
            .unwrap()
            .remove("environment_provenance");
        let historical: SandboxConfig = serde_json::from_value(raw).unwrap();
        let rebuilt = finish(SandboxBuilder::from(historical).env("NEW", "value"));
        assert!(origin(&rebuilt, "OLD", false).is_none());
        assert!(origin(&rebuilt, "NEW", false) == Some(EnvironmentOrigin::Literal));
        let raw = serde_json::to_value(&rebuilt).unwrap();
        assert!(raw.get("environment_provenance_unknown").is_none());
        let twice = finish(SandboxBuilder::from(
            serde_json::from_value::<SandboxConfig>(raw).unwrap(),
        ));
        assert!(origin(&twice, "OLD", false).is_none());
    }

    #[test]
    fn persisted_hints_survive_round_trip_but_not_changed_values() {
        let known = finish(
            SandboxBuilder::new("env-origin")
                .image("alpine")
                .host_env("KEY".into(), "private-value".into()),
        );
        let mut decoded: SandboxConfig =
            serde_json::from_value(serde_json::to_value(known.clone_for_persistence()).unwrap())
                .unwrap();
        assert!(origin(&decoded, "KEY", false) == Some(EnvironmentOrigin::Host));
        decoded.spec.env[0].value = "edited".into();
        assert!(
            !decoded
                .environment_provenance
                .as_ref()
                .unwrap()
                .matches(&decoded.spec.env, None)
        );
        assert!(origin(&decoded.clone_for_persistence(), "KEY", false).is_none());
        let rebuilt = finish(SandboxBuilder::from(decoded));
        assert!(origin(&rebuilt, "KEY", false).is_none());
    }

    #[test]
    fn auto_init_inherits_host_origin_and_respects_init_override() {
        let image = ImageConfig {
            entrypoint: Some(vec!["/init".into()]),
            env: vec!["IMAGE=literal".into()],
            ..Default::default()
        };
        for override_host in [true, false] {
            let config = SandboxBuilder::new("env-init")
                .image("alpine")
                .host_env("INHERIT".into(), "host-value".into())
                .host_env("OVERRIDE".into(), "same-value".into())
                .init_with("auto", |i| {
                    if override_host {
                        i.host_env("OVERRIDE".into(), "same-value".into())
                    } else {
                        i.env("OVERRIDE", "same-value")
                    }
                })
                .finish(None, Some(SandboxConfigPatch::from_image(&image)))
                .unwrap();
            assert!(origin(&config, "INHERIT", true) == Some(EnvironmentOrigin::Host));
            assert!(origin(&config, "IMAGE", true) == Some(EnvironmentOrigin::Literal));
            assert!(
                origin(&config, "OVERRIDE", true)
                    == Some(if override_host {
                        EnvironmentOrigin::Host
                    } else {
                        EnvironmentOrigin::Literal
                    })
            );
            assert!(
                config
                    .environment_provenance
                    .as_ref()
                    .unwrap()
                    .matches(&config.spec.env, config.spec.init.as_ref())
            );
        }
    }

    #[test]
    fn replacing_init_removes_old_host_origins() {
        let config = finish(
            SandboxBuilder::new("env-init")
                .image("alpine")
                .init_with("/init", |i| i.host_env("PRIVATE".into(), "host".into()))
                .init_with("/sbin/init", |i| i.env("NEW", "declared")),
        );
        assert!(origin(&config, "PRIVATE", true).is_none());
        assert!(origin(&config, "NEW", true) == Some(EnvironmentOrigin::Literal));
    }

    #[test]
    fn explicit_spec_declares_environment_without_inheriting_unknown_guard() {
        let config = finish(
            SandboxBuilder::new("env-spec")
                .image("alpine")
                .env("NEW", "literal"),
        );
        let declared = finish(
            SandboxBuilder::from_spec_json(&serde_json::to_string(&config.spec).unwrap()).unwrap(),
        );
        assert!(origin(&declared, "NEW", false) == Some(EnvironmentOrigin::Literal));
    }

    #[test]
    fn malformed_origins_are_rejected_without_accepting_missing_maps() {
        for raw in [
            "{}",
            r#"{"env":{}}"#,
            r#"{"env":{},"init_env":{},"extra":true}"#,
        ] {
            assert!(serde_json::from_str::<EnvironmentProvenance>(raw).is_err());
        }
    }
    #[test]
    fn retained_sparse_patch_does_not_turn_host_or_missing_origins_into_literals() {
        let mut config = finish(
            SandboxBuilder::new("retained-env")
                .image("alpine")
                .host_env("HOST".into(), "private".into())
                .init_with("/init", |i| {
                    i.host_env("INIT_HOST".into(), "private".into())
                }),
        );
        config.spec.env.push(EnvVar::new("UNKNOWN", "untracked"));
        let rebuilt = finish(
            SandboxBuilder::new("destination")
                .overlay(SandboxConfigPatch::from_present_fields(config)),
        );
        assert!(origin(&rebuilt, "HOST", false) == Some(EnvironmentOrigin::Host));
        assert!(origin(&rebuilt, "INIT_HOST", true) == Some(EnvironmentOrigin::Host));
        assert!(origin(&rebuilt, "UNKNOWN", false) == Some(EnvironmentOrigin::Unknown));
    }

    #[test]
    fn legacy_sparse_overlay_keeps_missing_workload_and_init_origins_unknown() {
        let original = finish(
            SandboxBuilder::new("legacy-source")
                .image("alpine")
                .host_env("HOST".into(), "PRIVATE_WORKLOAD".into())
                .init_with("/init", |init| {
                    init.host_env("INIT_HOST".into(), "PRIVATE_INIT".into())
                }),
        );
        let expected_env = original.spec.env.clone();
        let expected_init = original.spec.init.clone();
        let mut raw = serde_json::to_value(original).unwrap();
        raw.as_object_mut()
            .unwrap()
            .remove("environment_provenance");
        for _ in 0..2 {
            let legacy: SandboxConfig = serde_json::from_value(raw).unwrap();
            let rebuilt = finish(
                SandboxBuilder::new("destination")
                    // Existing literal evidence for the same value must not certify a
                    // historical replacement whose origin was never recorded.
                    .env("HOST", "PRIVATE_WORKLOAD")
                    .overlay(SandboxConfigPatch::from_present_fields(legacy)),
            );
            assert_eq!(rebuilt.spec.env, expected_env);
            assert_eq!(
                serde_json::to_value(&rebuilt.spec.init).unwrap(),
                serde_json::to_value(&expected_init).unwrap()
            );
            assert!(origin(&rebuilt, "HOST", false) == Some(EnvironmentOrigin::Unknown));
            assert!(origin(&rebuilt, "INIT_HOST", true) == Some(EnvironmentOrigin::Unknown));
            assert!(
                !rebuilt.environment_provenance.as_ref().unwrap().is_literal(
                    "HOST",
                    "PRIVATE_WORKLOAD",
                    false
                )
            );
            raw = serde_json::to_value(rebuilt.clone_for_persistence()).unwrap();
        }
        let retained: SandboxConfig = serde_json::from_value(raw).unwrap();
        let explicit = finish(
            SandboxBuilder::new("destination")
                .overlay(SandboxConfigPatch::from_present_fields(retained))
                .env("HOST", "PRIVATE_WORKLOAD")
                .init_with("/init", |init| init.env("INIT_HOST", "PRIVATE_INIT")),
        );
        assert!(origin(&explicit, "HOST", false) == Some(EnvironmentOrigin::Literal));
        assert!(origin(&explicit, "INIT_HOST", true) == Some(EnvironmentOrigin::Literal));
    }

    #[test]
    fn mismatched_origin_stays_unknown_across_resolution_and_init_inheritance() {
        let mut evidence = EnvironmentProvenance::default();
        evidence.declare_env("KEY", "original-private-value", EnvironmentOrigin::Host);
        let env = vec![EnvVar::new("KEY", "changed-private-value")];
        let init = HandoffInit {
            cmd: "/init".into(),
            args: vec![],
            env: vec![("KEY".into(), "changed-private-value".into())],
        };
        for _ in 0..2 {
            evidence.resolve(&env, Some(&init), false);
            assert!(
                evidence
                    .env
                    .get("KEY")
                    .is_some_and(|entry| entry.origin == EnvironmentOrigin::Unknown)
            );
            assert!(
                evidence
                    .init_env
                    .get("KEY")
                    .is_some_and(|entry| entry.origin == EnvironmentOrigin::Unknown)
            );
            evidence = serde_json::from_value(serde_json::to_value(evidence).unwrap()).unwrap();
        }
        assert!(evidence.matches(&env, Some(&init)));
        // A new explicit declaration, rather than another resolution pass, can establish intent.
        evidence.declare_env("KEY", "changed-private-value", EnvironmentOrigin::Literal);
        evidence.resolve(&env, Some(&init), false);
        assert!(evidence.env["KEY"].origin == EnvironmentOrigin::Literal);
        assert!(evidence.init_env["KEY"].origin == EnvironmentOrigin::Unknown);
    }

    #[test]
    fn repeated_layering_never_reclassifies_changed_retained_input_as_literal() {
        let mut source = finish(
            SandboxBuilder::new("changed-env")
                .image("alpine")
                .host_env("KEY".into(), "original-private-value".into()),
        );
        source.spec.env[0].value = "changed-private-value".into();
        // Deferred preparation can layer a concrete config more than once. Losing an invalid
        // hint on its first pass must not make the next pass treat the value as new input.
        for _ in 0..2 {
            let mut resolved = SandboxConfig::default();
            resolved
                .apply_layers(None, SandboxConfigPatch::from_present_fields(source), None)
                .unwrap();
            assert!(origin(&resolved, "KEY", false) == Some(EnvironmentOrigin::Unknown));
            source = serde_json::from_value(serde_json::to_value(resolved).unwrap()).unwrap();
        }
    }
}
