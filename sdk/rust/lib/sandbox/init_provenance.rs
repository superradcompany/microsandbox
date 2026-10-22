//! Local input provenance, separate from guest-confirmed boot selection.

use microsandbox_protocol::HANDOFF_INIT_AUTO;
use serde::{Deserialize, Serialize};

use super::HandoffInit;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Positive evidence from configuration resolution; absence in older records is unknown.
/// The configured spelling binds the intent to the configuration that actually reached launch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum InitProvenance {
    Builtin {},
    Auto { configured: String },
    Path { configured: String },
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl InitProvenance {
    pub(crate) fn from_init(init: Option<&HandoffInit>) -> Self {
        match init {
            None => Self::Builtin {},
            Some(init) if init.cmd == HANDOFF_INIT_AUTO => Self::Auto {
                configured: init.cmd.clone(),
            },
            Some(init) => Self::Path {
                configured: init.cmd.clone(),
            },
        }
    }

    /// A public config can be edited directly. Never borrow provenance from a different init.
    pub(crate) fn matches(&self, init: Option<&HandoffInit>) -> bool {
        match (self, init) {
            (Self::Builtin {}, None) => true,
            (Self::Auto { configured }, Some(init)) => configured == &init.cmd,
            (Self::Path { configured }, Some(init)) => {
                configured != HANDOFF_INIT_AUTO && configured == &init.cmd
            }
            _ => false,
        }
    }
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

    fn auto_from_image() -> SandboxConfig {
        let image = ImageConfig {
            entrypoint: Some(vec!["/init".into()]),
            ..Default::default()
        };
        SandboxBuilder::new("provenance")
            .image("alpine")
            .init("auto")
            .finish(None, Some(SandboxConfigPatch::from_image(&image)))
            .unwrap()
    }

    #[test]
    fn image_auto_intent_survives_persistence_and_builder_reconstruction() {
        let config = auto_from_image();
        assert_eq!(config.spec.init.as_ref().unwrap().cmd, "/init");
        let expected = Some(InitProvenance::Auto {
            configured: "/init".into(),
        });
        assert_eq!(config.init_provenance, expected);
        let json = serde_json::to_value(config.clone_for_persistence()).unwrap();
        assert_eq!(
            json["init_provenance"],
            serde_json::json!({"kind":"auto","configured":"/init"})
        );
        let loaded: SandboxConfig = serde_json::from_value(json).unwrap();
        assert_eq!(loaded.init_provenance, expected);
        let rebuilt = SandboxBuilder::from(loaded).finish(None, None).unwrap();
        assert_eq!(rebuilt.spec.init.as_ref().unwrap().cmd, "/init");
        assert_eq!(rebuilt.init_provenance, expected);
    }

    #[test]
    fn retained_overlay_and_reconstruction_preserve_init_intent_or_its_absence() {
        let original = auto_from_image();
        for recorded in [false, true] {
            let mut raw = serde_json::to_value(original.clone_for_persistence()).unwrap();
            if !recorded {
                raw.as_object_mut().unwrap().remove("init_provenance");
            }
            for overlay in [false, true] {
                let retained: SandboxConfig = serde_json::from_value(raw.clone()).unwrap();
                let builder = if overlay {
                    SandboxBuilder::new("replacement")
                        // Equal paths do not establish that the old producer selected a path.
                        .init("/init")
                        .overlay(SandboxConfigPatch::from_present_fields(retained))
                } else {
                    SandboxBuilder::from(retained)
                };
                let rebuilt = builder.finish(None, None).unwrap();
                assert_eq!(
                    serde_json::to_value(&rebuilt.spec.init).unwrap(),
                    serde_json::to_value(&original.spec.init).unwrap()
                );
                assert_eq!(
                    rebuilt.init_provenance,
                    recorded.then(|| original.init_provenance.clone().unwrap())
                );
                raw = serde_json::to_value(rebuilt.clone_for_persistence()).unwrap();
                assert!(raw.get("init_provenance_unknown").is_none());
            }
        }
    }

    #[test]
    fn explicit_init_declaration_can_replace_missing_historical_intent() {
        let mut raw = serde_json::to_value(auto_from_image()).unwrap();
        raw.as_object_mut().unwrap().remove("init_provenance");
        let retained: SandboxConfig = serde_json::from_value(raw).unwrap();
        let explicit = HandoffInit {
            cmd: "/init".into(),
            args: vec![],
            env: vec![],
        };
        for builder in [
            SandboxBuilder::from(retained.clone()).init("/init"),
            SandboxBuilder::from(retained.clone()).init_with("/init", |init| init),
            SandboxBuilder::from(retained.clone())
                .overlay(SandboxConfigPatch::new().spec(SandboxSpecPatch::new().init(explicit))),
            SandboxBuilder::from_spec_json(&serde_json::to_string(&retained.spec).unwrap())
                .unwrap(),
        ] {
            let config = builder.finish(None, None).unwrap();
            assert_eq!(
                config.init_provenance,
                Some(InitProvenance::Path {
                    configured: "/init".into()
                })
            );
        }
    }

    #[test]
    fn explicit_same_path_override_replaces_inherited_auto_intent() {
        let explicit = HandoffInit {
            cmd: "/init".into(),
            args: vec![],
            env: vec![],
        };
        let builders = [
            SandboxBuilder::from(auto_from_image()).init("/init"),
            SandboxBuilder::from(auto_from_image()).init_with("/init", |init| init),
            SandboxBuilder::from(auto_from_image())
                .overlay(SandboxConfigPatch::new().spec(SandboxSpecPatch::new().init(explicit))),
        ];
        for builder in builders {
            let config = builder.finish(None, None).unwrap();
            assert_eq!(
                config.init_provenance,
                Some(InitProvenance::Path {
                    configured: "/init".into()
                })
            );
        }
    }

    #[test]
    fn guest_auto_and_builtin_are_recorded_only_by_fresh_resolution() {
        for choice in [None, Some("auto"), Some("/sbin/init")] {
            let builder = SandboxBuilder::new("fresh").image("alpine");
            let builder = match choice {
                Some(choice) => builder.init(choice),
                None => builder,
            };
            let config = builder.finish(None, None).unwrap();
            assert_eq!(
                config.init_provenance,
                Some(InitProvenance::from_init(config.spec.init.as_ref()))
            );

            // An older reader can drop the additive field. Loading/restarting that config
            // cannot reconstruct the original intent from a possibly resolved path.
            let mut legacy = serde_json::to_value(&config).unwrap();
            legacy.as_object_mut().unwrap().remove("init_provenance");
            let loaded: SandboxConfig = serde_json::from_value(legacy).unwrap();
            assert!(loaded.init_provenance.is_none());
            assert!(loaded.clone_for_persistence().init_provenance.is_none());
        }
    }

    #[test]
    fn direct_config_change_cannot_reuse_a_different_init_origin() {
        let mut config = auto_from_image();
        config.spec.init.as_mut().unwrap().cmd = "/sbin/init".into();
        let persisted = config.clone_for_persistence();
        assert_eq!(persisted.spec.init.as_ref().unwrap().cmd, "/sbin/init");
        assert!(persisted.init_provenance.is_none());
        config.spec.init = None;
        assert!(config.clone_for_persistence().init_provenance.is_none());
    }
}
