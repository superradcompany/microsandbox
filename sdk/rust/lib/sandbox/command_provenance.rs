//! Host-private command intent. Portable capture must still apply its exclusion controls.

use std::fmt;

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Distinguish reusable CMD from a one-shot detached invocation without changing legacy restart
/// behavior. Matching is evidence of input intent, not proof of a running process or guest state.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommandProvenance {
    /// Exact runtime CMD this record describes; None and an explicit empty vector differ.
    #[serde(deserialize_with = "Option::deserialize")]
    pub(crate) configured: Option<Vec<String>>,
    /// CMD before the invocation overlay, after image and destination configuration layering.
    #[serde(deserialize_with = "Option::deserialize")]
    pub(crate) defaults: Option<Vec<String>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CommandProvenance {
    pub(crate) fn new(configured: Option<Vec<String>>, defaults: Option<Vec<String>>) -> Self {
        Self {
            configured,
            defaults,
        }
    }

    /// Direct config edits and old writers must not borrow evidence for a different command.
    pub(crate) fn matches(&self, configured: &Option<Vec<String>>) -> bool {
        &self.configured == configured
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for CommandProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandProvenance")
            .finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, feature = "local"))]
mod tests {
    use microsandbox_image::ImageConfig;
    use microsandbox_types::{SandboxRuntimeOptionsPatch, SandboxSpecPatch};

    use super::*;
    use crate::sandbox::{RootfsSource, SandboxBuilder};
    use crate::{SandboxConfig, SandboxConfigPatch};

    fn build(background: Option<Vec<&str>>, image_cmd: Option<Vec<&str>>) -> SandboxConfig {
        let image = ImageConfig {
            cmd: image_cmd.map(|args| args.into_iter().map(String::from).collect()),
            ..Default::default()
        };
        let builder = SandboxBuilder::new("command-origin").image("alpine");
        let builder = match background {
            Some(args) => builder.background_command(args),
            None => builder,
        };
        builder
            .finish(None, Some(SandboxConfigPatch::from_image(&image)))
            .unwrap()
    }

    #[test]
    fn detached_invocation_retains_image_defaults_without_changing_persisted_cmd() {
        let config = build(
            Some(vec!["one-shot", "private-arg"]),
            Some(vec!["image-default"]),
        );
        let expected = CommandProvenance::new(
            Some(vec!["one-shot".into(), "private-arg".into()]),
            Some(vec!["image-default".into()]),
        );
        assert_eq!(config.command_provenance, Some(expected.clone()));
        let persisted = config.clone_for_persistence();
        assert_eq!(persisted.spec.runtime.cmd, expected.configured);
        assert_eq!(persisted.command_provenance, Some(expected));
        assert!(!format!("{:?}", persisted.command_provenance).contains("private-arg"));
    }

    #[test]
    fn foreground_invocation_does_not_replace_default_cmd() {
        let image = ImageConfig {
            cmd: Some(vec!["image".into()]),
            ..Default::default()
        };
        let config = SandboxBuilder::new("foreground-origin")
            .image("alpine")
            .foreground_command(["one-shot"])
            .finish(None, Some(SandboxConfigPatch::from_image(&image)))
            .unwrap();
        assert_eq!(
            config.command_provenance,
            Some(CommandProvenance::new(
                Some(vec!["image".into()]),
                Some(vec!["image".into()]),
            ))
        );
    }

    #[test]
    fn absent_empty_and_inherited_cmd_remain_distinct() {
        for image_cmd in [None, Some(vec![]), Some(vec!["image"])] {
            let config = build(Some(vec!["invocation"]), image_cmd.clone());
            assert_eq!(
                config.command_provenance.unwrap().defaults,
                image_cmd.map(|args| args.into_iter().map(String::from).collect())
            );
        }
        let no_override = build(Some(vec![]), Some(vec!["image"]));
        let origin = no_override.command_provenance.unwrap();
        assert_eq!(origin.configured, origin.defaults);
        assert_eq!(origin.defaults, Some(vec!["image".into()]));
    }

    #[test]
    fn persistence_and_reconstruction_keep_original_defaults() {
        let config = build(Some(vec!["first-invocation"]), Some(vec!["image"]));
        let json = serde_json::to_value(config.clone_for_persistence()).unwrap();
        let decoded: SandboxConfig = serde_json::from_value(json).unwrap();
        let rebuilt = SandboxBuilder::from(decoded.clone())
            .finish(None, None)
            .unwrap();
        assert_eq!(rebuilt.command_provenance, config.command_provenance);
        let second = SandboxBuilder::from(decoded)
            .background_command(["second-invocation"])
            .finish(None, None)
            .unwrap();
        assert_eq!(
            second.command_provenance.unwrap().defaults,
            Some(vec!["image".into()])
        );
    }

    #[test]
    fn retained_overlay_preserves_missing_command_intent() {
        let original = build(Some(vec!["private-invocation"]), Some(vec!["reusable"]));
        for recorded in [false, true] {
            let mut raw = serde_json::to_value(original.clone_for_persistence()).unwrap();
            if !recorded {
                raw.as_object_mut().unwrap().remove("command_provenance");
            }
            for _ in 0..2 {
                let retained: SandboxConfig = serde_json::from_value(raw).unwrap();
                let rebuilt = SandboxBuilder::new("replacement")
                    .cmd(["private-invocation"])
                    .overlay(SandboxConfigPatch::from_present_fields(retained))
                    .finish(None, None)
                    .unwrap();
                assert_eq!(rebuilt.spec.runtime.cmd, original.spec.runtime.cmd);
                assert_eq!(
                    rebuilt.command_provenance,
                    recorded.then(|| original.command_provenance.clone().unwrap())
                );
                raw = serde_json::to_value(rebuilt.clone_for_persistence()).unwrap();
            }
        }
    }

    #[test]
    fn explicit_same_value_cmd_replaces_invocation_origin() {
        let config = build(Some(vec!["one-shot"]), Some(vec!["image"]));
        for builder in [
            SandboxBuilder::from(config.clone()).cmd(["one-shot"]),
            SandboxBuilder::from(config).overlay(
                SandboxConfigPatch::new().spec(
                    SandboxSpecPatch::new()
                        .runtime(SandboxRuntimeOptionsPatch::new().cmd(vec!["one-shot".into()])),
                ),
            ),
        ] {
            let config = builder.finish(None, None).unwrap();
            let origin = config.command_provenance.unwrap();
            assert_eq!(origin.configured, origin.defaults);
            assert_eq!(origin.defaults, Some(vec!["one-shot".into()]));
        }
    }

    #[test]
    fn older_records_and_direct_edits_do_not_invent_evidence_on_restart() {
        let config = build(Some(vec!["one-shot"]), Some(vec!["image"]));
        let mut json = serde_json::to_value(config.clone_for_persistence()).unwrap();
        json.as_object_mut().unwrap().remove("command_provenance");
        let older: SandboxConfig = serde_json::from_value(json).unwrap();
        assert!(older.clone_for_persistence().command_provenance.is_none());
        for builder in [
            SandboxBuilder::from(older.clone()),
            SandboxBuilder::from(older.clone()).background_command(["new-invocation"]),
        ] {
            assert!(
                builder
                    .finish(None, None)
                    .unwrap()
                    .command_provenance
                    .is_none()
            );
        }
        let declared = SandboxBuilder::from(older)
            .cmd(["new-default"])
            .finish(None, None)
            .unwrap();
        assert_eq!(
            declared.command_provenance.unwrap().defaults,
            Some(vec!["new-default".into()])
        );
        let mut edited = config;
        edited.spec.runtime.cmd = Some(vec!["new".into()]);
        assert!(edited.clone_for_persistence().command_provenance.is_none());
        let rebuilt = SandboxBuilder::from(edited)
            .background_command(["another-invocation"])
            .finish(None, None)
            .unwrap();
        assert!(rebuilt.command_provenance.is_none());
        // The unknown marker is builder-local, not another persisted contract.
        assert!(
            serde_json::to_value(&rebuilt)
                .unwrap()
                .get("command_provenance_unknown")
                .is_none()
        );
    }

    #[test]
    fn image_init_routing_retains_cmd_evidence_after_consuming_launch_intent() {
        let image = ImageConfig {
            entrypoint: Some(vec!["/init".into(), "wrapper".into()]),
            cmd: Some(vec!["image".into()]),
            ..Default::default()
        };
        let config = SandboxBuilder::new("init-command-origin")
            .image("alpine")
            .init("auto")
            .background_command(["one-shot"])
            .finish(None, Some(SandboxConfigPatch::from_image(&image)))
            .unwrap();
        assert!(config.init_owns_boot_workload());
        assert_eq!(
            config
                .clone_for_persistence()
                .command_provenance
                .unwrap()
                .defaults,
            Some(vec!["image".into()])
        );
    }
    #[test]
    fn explicit_cmd_after_detached_selection_is_a_new_default() {
        let image = ImageConfig {
            cmd: Some(vec!["image".into()]),
            ..Default::default()
        };
        for builder in
            [
                SandboxBuilder::new("explicit-command")
                    .image("alpine")
                    .background_command(["one-shot"])
                    .cmd(["declared"]),
                SandboxBuilder::new("explicit-command")
                    .image("alpine")
                    .background_command(["one-shot"])
                    .overlay(SandboxConfigPatch::new().spec(
                        SandboxSpecPatch::new().runtime(
                            SandboxRuntimeOptionsPatch::new().cmd(vec!["declared".into()]),
                        ),
                    )),
            ]
        {
            let config = builder
                .finish(None, Some(SandboxConfigPatch::from_image(&image)))
                .unwrap();
            let origin = config.command_provenance.unwrap();
            assert_eq!(origin.defaults, Some(vec!["declared".into()]));
            assert_eq!(origin.configured, origin.defaults);
        }
    }

    #[test]
    fn provenance_requires_both_fields_even_when_the_value_is_null() {
        for json in ["{}", r#"{"configured":null}"#, r#"{"defaults":null}"#] {
            assert!(serde_json::from_str::<CommandProvenance>(json).is_err());
        }
        assert_eq!(
            serde_json::from_str::<CommandProvenance>(r#"{"configured":null,"defaults":null}"#)
                .unwrap(),
            CommandProvenance::new(None, None)
        );
    }
    #[test]
    fn explicit_spec_is_a_declaration_not_a_historical_reconstruction() {
        let mut config = SandboxConfig::default();
        config.spec.name = "declared-command".into();
        config.spec.image = RootfsSource::oci("alpine");
        config.spec.runtime.cmd = Some(vec!["declared".into()]);
        let json = serde_json::to_string(&config.spec).unwrap();
        let declared = SandboxBuilder::from_spec_json(&json)
            .unwrap()
            .finish(None, None)
            .unwrap();
        assert_eq!(
            declared.command_provenance.unwrap().defaults,
            Some(vec!["declared".into()])
        );
    }
}
