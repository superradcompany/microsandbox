//! Derive runtime binding consumers from typed fields, never from artifact-supplied timing claims.

use std::collections::{BTreeMap, BTreeSet};

use crate::SnapshotManifestResult;

use super::{SavedInit, SavedRuntimeConfig, SavedScript, SavedText, SavedValue};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A consumer implied by a runtime reference. Activation decides when that consumer runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuntimeBindingConsumer {
    /// Init argv/environment needed before a cold boot. Full resume does not replay init.
    BootInit,
    /// Defaults needed before a new command is started, including a snapshot-backed run.
    NewCommand,
    /// Content needed to reconstruct the registered script files.
    ScriptBacking,
}

/// All consumers of each logical binding; sharing an ID never discards the stricter use.
pub type RuntimeBindingRequirements = BTreeMap<String, BTreeSet<RuntimeBindingConsumer>>;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SavedRuntimeConfig {
    /// Derive potential consumers after validating this runtime section.
    ///
    /// This is deliberately independent of any claimed `consumers` in a binding
    /// inventory. A full resolver must check that inventory against these uses and
    /// combine them with captured-execution and gateway requirements. It must also
    /// resolve clears/overrides/fresh mode before computing activation demand; this
    /// method alone neither authorizes activation nor implements deferred exec checks.
    pub fn binding_requirements(&self) -> SnapshotManifestResult<RuntimeBindingRequirements> {
        self.validate()?;
        let mut requirements = BTreeMap::new();
        for setting in [&self.entrypoint, &self.cmd] {
            if let Some(values) = setting.as_ref().and_then(SavedValue::value) {
                record_texts(
                    &mut requirements,
                    values.iter(),
                    RuntimeBindingConsumer::NewCommand,
                );
            }
        }
        if let Some(env) = self.env.as_ref().and_then(SavedValue::value) {
            record_texts(
                &mut requirements,
                env.values(),
                RuntimeBindingConsumer::NewCommand,
            );
        }
        if let Some(
            SavedInit::Handoff { args, env, .. } | SavedInit::RequestedHandoff { args, env, .. },
        ) = self.init.as_ref().and_then(SavedValue::value)
        {
            record_texts(
                &mut requirements,
                args.iter().chain(env.values()),
                RuntimeBindingConsumer::BootInit,
            );
        }
        if let Some(scripts) = self.scripts.as_ref().and_then(SavedValue::value) {
            for script in scripts.values() {
                if let SavedScript::Binding { id } = script {
                    requirements
                        .entry(id.clone())
                        .or_default()
                        .insert(RuntimeBindingConsumer::ScriptBacking);
                }
            }
        }
        Ok(requirements)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn record_texts<'a>(
    requirements: &mut RuntimeBindingRequirements,
    values: impl Iterator<Item = &'a SavedText>,
    consumer: RuntimeBindingConsumer,
) {
    for value in values {
        if let SavedText::Binding { id } = value {
            requirements.entry(id.clone()).or_default().insert(consumer);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn shared_bindings_retain_every_consumer_regardless_of_map_order() {
        let runtime = SavedRuntimeConfig::from_bytes(
            &serde_json::to_vec(&json!({
                "env": {"state":"value", "origin":"configured", "value": {
                    "TOKEN": {"kind":"binding", "id":"shared"},
                    "PLAIN": {"kind":"literal", "value":"not.a.binding"}
                }},
                "entrypoint": {"state":"value", "origin":"configured", "value": [
                    {"kind":"binding", "id":"entrypoint"}
                ]},
                "cmd": {"state":"value", "origin":"configured", "value": [
                    {"kind":"binding", "id":"args"}, {"kind":"binding", "id":"shared"}
                ]},
                "init": {"state":"value", "origin":"observed", "value": {
                    "kind":"handoff", "selection":"path", "resolved_path":"/sbin/init",
                    "args":[{"kind":"binding", "id":"init.args"}],
                    "env":{"TOKEN":{"kind":"binding", "id":"shared"}}
                }},
                "scripts": {"state":"value", "origin":"configured", "value": {
                    "health":{"kind":"binding", "id":"shared"},
                    "check":{"kind":"binding", "id":"script.check"}
                }}
            }))
            .unwrap(),
        )
        .unwrap();

        let actual = runtime.binding_requirements().unwrap();
        let expected = BTreeMap::from([
            (
                "shared".into(),
                BTreeSet::from([
                    RuntimeBindingConsumer::NewCommand,
                    RuntimeBindingConsumer::BootInit,
                    RuntimeBindingConsumer::ScriptBacking,
                ]),
            ),
            (
                "entrypoint".into(),
                BTreeSet::from([RuntimeBindingConsumer::NewCommand]),
            ),
            (
                "args".into(),
                BTreeSet::from([RuntimeBindingConsumer::NewCommand]),
            ),
            (
                "init.args".into(),
                BTreeSet::from([RuntimeBindingConsumer::BootInit]),
            ),
            (
                "script.check".into(),
                BTreeSet::from([RuntimeBindingConsumer::ScriptBacking]),
            ),
        ]);
        assert_eq!(actual, expected);
    }

    #[test]
    fn artifact_cannot_defer_an_init_binding_with_a_consumer_claim() {
        let bytes = br#"{"init":{"state":"value","origin":"configured","value":{"kind":"handoff","selection":"path","resolved_path":"/bin/init","args":[],"env":{"TOKEN":{"kind":"binding","id":"token","consumers":["new_command"]}}}}}"#;
        assert!(SavedRuntimeConfig::from_bytes(bytes).is_err());
    }

    #[test]
    fn unknown_default_omitted_and_empty_values_invent_no_binding() {
        let runtime = SavedRuntimeConfig::from_bytes(
            br#"{
            "cmd":{"state":"unknown","reason":"not_recorded"},
            "init":{"state":"default"},
            "env":{"state":"value","origin":"configured","value":{}}
        }"#,
        )
        .unwrap();
        assert!(runtime.binding_requirements().unwrap().is_empty());
    }
}
