//! Secret policies introduced in v0.5.0 and reused by v0.6 runtimes.
//! Catalog remapping retains unknown fields for downgrade preservation checks.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::compat::field::Field;
use crate::{
    HostPattern, SecretEntry, SecretSource, SecretSubstitution, SecretViolationAction,
    SecretsConfig,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Previous substitution locations, shared by local and cloud contracts.
#[derive(Clone, Serialize)]
pub struct SecretInjection {
    /// Substitute in ordinary headers.
    #[serde(default = "default_true")]
    pub headers: bool,
    /// Independently substitute in encoded Basic authentication headers.
    #[serde(default = "default_true")]
    pub basic_auth: bool,
    /// Substitute in URL query parameters.
    #[serde(default)]
    pub query_params: bool,
    /// Substitute in request bodies.
    #[serde(default)]
    pub body: bool,
}

#[derive(Deserialize)]
struct ConfigFields {
    #[serde(default, alias = "entries")]
    secrets: Vec<EntryFields>,
    #[serde(default)]
    passthrough_hosts: Field<Option<Vec<HostPattern>>>,
    #[serde(default)]
    violation_action: Field<ViolationAction>,
    #[serde(default)]
    on_violation: Field<ViolationAction>,
}

#[derive(Deserialize)]
struct EntryFields {
    env_var: String,
    #[serde(default)]
    value: zeroize::Zeroizing<String>,
    source: Option<SecretSource>,
    placeholder: String,
    #[serde(default)]
    allowed_hosts: Vec<HostPattern>,
    #[serde(default)]
    substitution: Field<SecretSubstitution>,
    #[serde(default)]
    injection: Field<SecretInjection>,
    #[serde(default)]
    passthrough_hosts: Field<Vec<HostPattern>>,
    #[serde(default)]
    violation_action: Field<Option<ViolationAction>>,
    #[serde(default)]
    on_violation: Field<Option<ViolationAction>>,
    #[serde(default = "default_true")]
    require_tls_identity: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ViolationAction {
    #[serde(alias = "Block")]
    Block,
    #[serde(alias = "BlockAndLog", alias = "block_and_log")]
    BlockAndLog,
    #[serde(alias = "BlockAndTerminate", alias = "block_and_terminate")]
    BlockAndTerminate,
    #[serde(alias = "Passthrough")]
    Passthrough(Vec<HostPattern>),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ViolationAction {
    fn into_current(self) -> (Option<SecretViolationAction>, Option<Vec<HostPattern>>) {
        match self {
            Self::Block => (Some(SecretViolationAction::Block), None),
            Self::BlockAndLog => (Some(SecretViolationAction::BlockAndLog), None),
            Self::BlockAndTerminate => (Some(SecretViolationAction::BlockAndTerminate), None),
            Self::Passthrough(hosts) => (None, Some(hosts)),
        }
    }
}

impl EntryFields {
    fn into_current(self) -> Result<SecretEntry, &'static str> {
        let substitution = match (self.substitution, self.injection) {
            (Field::Present(_), Field::Present(_)) => return Err("conflicting secret scopes"),
            (Field::Present(scopes), Field::Missing) => scopes,
            (Field::Missing, Field::Present(scopes)) => scopes.into(),
            (Field::Missing, Field::Missing) => SecretSubstitution::default(),
        };
        let (violation_action, hosts) = match (self.violation_action, self.on_violation) {
            (Field::Present(_), Field::Present(_)) => return Err("conflicting secret policies"),
            (Field::Present(Some(action)), Field::Missing)
            | (Field::Missing, Field::Present(Some(action))) => action.into_current(),
            _ => (None, None),
        };
        let passthrough_hosts = match (self.passthrough_hosts, hosts) {
            (Field::Present(_), Some(_)) => return Err("conflicting secret passthrough hosts"),
            (Field::Present(hosts), None) => hosts,
            (Field::Missing, hosts) => hosts.unwrap_or_default(),
        };
        Ok(SecretEntry {
            env_var: self.env_var,
            value: self.value,
            source: self.source,
            placeholder: self.placeholder,
            allowed_hosts: self.allowed_hosts,
            substitution,
            passthrough_hosts,
            violation_action,
            require_tls_identity: self.require_tls_identity,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<'de> Deserialize<'de> for SecretInjection {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Fields {
            #[serde(default = "default_true")]
            headers: bool,
            #[serde(default = "default_true")]
            basic_auth: bool,
            #[serde(default)]
            query_params: Field<bool>,
            #[serde(default)]
            query: Field<bool>,
            #[serde(default)]
            body: bool,
        }
        let fields = Fields::deserialize(deserializer)?;
        let query_params = match (fields.query_params, fields.query) {
            (Field::Present(_), Field::Present(_)) => {
                return Err(serde::de::Error::custom(
                    "conflicting previous and current secret fields",
                ));
            }
            (Field::Present(query), Field::Missing) => query,
            (Field::Missing, Field::Present(query)) => query,
            (Field::Missing, Field::Missing) => false,
        };
        Ok(Self {
            headers: fields.headers,
            basic_auth: fields.basic_auth,
            query_params,
            body: fields.body,
        })
    }
}

impl From<SecretInjection> for SecretSubstitution {
    fn from(value: SecretInjection) -> Self {
        Self {
            headers: value.headers || value.basic_auth,
            query: value.query_params,
            body: value.body,
        }
    }
}

impl From<SecretSubstitution> for SecretInjection {
    fn from(value: SecretSubstitution) -> Self {
        Self {
            headers: value.headers,
            basic_auth: value.headers,
            query_params: value.query,
            body: value.body,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Read previous or current secret fields directly, without an intermediate JSON map.
/// Database migration uses the separate remapping functions to retain unknown saved fields.
pub fn deserialize_config<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<SecretsConfig, D::Error> {
    let config = ConfigFields::deserialize(deserializer)
        .map_err(|_| serde::de::Error::custom("invalid secret configuration"))?;
    let (action, hosts) = match (config.violation_action, config.on_violation) {
        (Field::Present(_), Field::Present(_)) => {
            return Err(serde::de::Error::custom("conflicting secret policies"));
        }
        (Field::Present(action), Field::Missing) | (Field::Missing, Field::Present(action)) => {
            action.into_current()
        }
        (Field::Missing, Field::Missing) => (None, None),
    };
    let passthrough_hosts = match (config.passthrough_hosts, hosts) {
        (Field::Present(_), Some(_)) => {
            return Err(serde::de::Error::custom(
                "conflicting secret passthrough hosts",
            ));
        }
        (Field::Present(hosts), None) => hosts,
        (Field::Missing, hosts) => hosts,
    };
    Ok(SecretsConfig {
        secrets: config
            .secrets
            .into_iter()
            .map(EntryFields::into_current)
            .collect::<Result<_, _>>()
            .map_err(serde::de::Error::custom)?,
        violation_action: action.unwrap_or_default(),
        passthrough_hosts,
    })
}

/// Translate previous fields to the current format without discarding unknown saved values.
/// Validate against the current contract; errors never contain secret values.
/// Only replace the caller's document after the entire conversion succeeds.
pub fn to_current(output: &mut Map<String, Value>) -> Result<(), &'static str> {
    let mut value = Value::Object(output.clone());
    let fields = value.as_object_mut().unwrap();
    rename(fields, "entries", "secrets")?;
    policy_to_current(fields, true)?;
    if let Some(entries) = fields.get_mut("secrets") {
        for entry in entries.as_array_mut().ok_or("invalid secret entries")? {
            let entry = entry.as_object_mut().ok_or("invalid secret entry")?;
            substitution_to_current(entry)?;
            policy_to_current(entry, false)?;
            if entry.get("source").is_some_and(Value::is_null) {
                entry.remove("source");
            }
        }
    }
    let current: SecretsConfig =
        serde_json::from_value(value.clone()).map_err(|_| "invalid secret configuration")?;
    let defaults = serde_json::to_value(current).map_err(|_| "invalid secret configuration")?;
    fill_defaults(&mut value, defaults);
    *output = value.as_object().unwrap().clone();
    Ok(())
}

/// Translate to previous spellings for a v0.6 runtime or saved configuration.
pub fn to_previous_version(fields: &mut Map<String, Value>) -> Result<(), &'static str> {
    let mut output = fields.clone();
    to_current(&mut output)?;
    policy_to_previous_version(&mut output, true)?;
    for entry in output.get_mut("secrets").unwrap().as_array_mut().unwrap() {
        let entry = entry.as_object_mut().unwrap();
        policy_to_previous_version(entry, false)?;
        let scopes = entry
            .get_mut("substitution")
            .unwrap()
            .as_object_mut()
            .unwrap();
        if scopes.contains_key("basic_auth") || scopes.contains_key("query_params") {
            return Err("conflicting previous and current secret fields");
        }
        let current: SecretSubstitution = serde_json::from_value(Value::Object(scopes.clone()))
            .map_err(|_| "invalid secret substitution")?;
        let previous = SecretInjection::from(current);
        scopes.insert("basic_auth".into(), json!(previous.basic_auth));
        rename(scopes, "query", "query_params")?;
        rename(entry, "substitution", "injection")?;
    }
    *fields = output;
    Ok(())
}

/// Rename a supplied field, rejecting even null-valued conflicting aliases.
pub(crate) fn rename(
    fields: &mut Map<String, Value>,
    old: &str,
    new: &str,
) -> Result<(), &'static str> {
    if fields.contains_key(old) && fields.contains_key(new) {
        return Err("conflicting previous and current secret fields");
    }
    if let Some(value) = fields.remove(old) {
        fields.insert(new.into(), value);
    }
    Ok(())
}

/// Merge the previous independent header scopes without changing modern defaults.
pub(crate) fn substitution_to_current(entry: &mut Map<String, Value>) -> Result<(), &'static str> {
    let previous = entry.contains_key("injection");
    rename(entry, "injection", "substitution")?;
    if previous {
        let scopes = entry
            .get_mut("substitution")
            .and_then(Value::as_object_mut)
            .ok_or("invalid secret substitution")?;
        let previous: SecretInjection = serde_json::from_value(Value::Object(scopes.clone()))
            .map_err(|_| "invalid secret substitution")?;
        let current = SecretSubstitution::from(previous);
        scopes.remove("basic_auth");
        scopes.insert("headers".into(), json!(current.headers));
        rename(scopes, "query_params", "query")?;
    }
    Ok(())
}

fn default_true() -> bool {
    true
}

fn policy_to_current(fields: &mut Map<String, Value>, global: bool) -> Result<(), &'static str> {
    rename(fields, "on_violation", "violation_action")?;
    if let Some(action) = fields.get_mut("violation_action") {
        match action.as_str() {
            Some("Block") => *action = json!("block"),
            Some("BlockAndLog" | "block_and_log") => *action = json!("block-and-log"),
            Some("BlockAndTerminate") => *action = json!("block-and-terminate"),
            _ => {}
        }
        if let Some(policy) = action.as_object() {
            if policy.len() != 1 {
                return Err("invalid secret violation action");
            }
            let hosts = policy
                .get("passthrough")
                .or_else(|| policy.get("Passthrough"))
                .ok_or("invalid secret violation action")?
                .clone();
            set_passthrough(fields, hosts)?;
        } else if !global && action.is_null() {
            fields.remove("violation_action");
        }
    }
    if global && fields.get("passthrough_hosts").is_some_and(Value::is_null) {
        fields.remove("passthrough_hosts");
    }
    Ok(())
}

/// Move previous passthrough hosts without replacing an explicit current policy.
pub(crate) fn set_passthrough(
    fields: &mut Map<String, Value>,
    hosts: Value,
) -> Result<(), &'static str> {
    if fields.contains_key("passthrough_hosts") {
        return Err("conflicting previous and current secret fields");
    }
    if !hosts.is_array() {
        return Err("invalid secret passthrough hosts");
    }
    fields.remove("violation_action");
    fields.insert("passthrough_hosts".into(), hosts);
    Ok(())
}

fn policy_to_previous_version(
    fields: &mut Map<String, Value>,
    global: bool,
) -> Result<(), &'static str> {
    if let Some(hosts) = fields.remove("passthrough_hosts")
        && (global || !hosts.as_array().unwrap().is_empty())
    {
        if global && fields.get("violation_action") != Some(&json!("block-and-log")) {
            return Err("legacy global passthrough requires the block-and-log fallback");
        }
        if !global && fields.contains_key("violation_action") {
            return Err("legacy per-secret passthrough cannot override the global fallback");
        }
        fields.insert("violation_action".into(), json!({"passthrough": hosts}));
    }
    rename(fields, "violation_action", "on_violation")
}

// Fill current defaults while retaining unknown fields at every nesting level.
fn fill_defaults(value: &mut Value, defaults: Value) {
    match (value, defaults) {
        (Value::Object(fields), Value::Object(defaults)) => {
            for (key, default) in defaults {
                if let Some(value) = fields.get_mut(&key) {
                    fill_defaults(value, default);
                } else {
                    fields.insert(key, default);
                }
            }
        }
        (Value::Array(values), Value::Array(defaults)) => {
            for (value, default) in values.iter_mut().zip(defaults) {
                fill_defaults(value, default);
            }
        }
        _ => {}
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
    fn typed_reader_matches_saved_field_conversion() {
        #[derive(Deserialize)]
        struct Input(#[serde(deserialize_with = "deserialize_config")] SecretsConfig);
        for scopes in [
            json!({}),
            json!({"injection": {}}),
            json!({"injection": {"headers": false}}),
            json!({"injection": {"headers": false, "basic_auth": false, "query_params": true}}),
            json!({"injection": {"query": true}}),
            json!({"substitution": {"headers": false, "query": true}}),
        ] {
            for policy in [
                json!({}),
                json!({"on_violation": "BlockAndLog"}),
                json!({"on_violation": {"Passthrough": ["Any"]}}),
                json!({"passthrough_hosts": []}),
                json!({"passthrough_hosts": null}),
            ] {
                let mut raw = policy;
                let mut entry = json!({"env_var":"KEY", "placeholder":"$KEY", "source":null});
                entry
                    .as_object_mut()
                    .unwrap()
                    .extend(scopes.as_object().unwrap().clone());
                raw["entries"] = json!([entry]);
                let typed: Input = serde_json::from_str(&raw.to_string()).unwrap();
                to_current(raw.as_object_mut().unwrap()).unwrap();
                let mapped: SecretsConfig = serde_json::from_value(raw).unwrap();
                assert_eq!(
                    serde_json::to_value(typed.0).unwrap(),
                    serde_json::to_value(mapped).unwrap()
                );
            }
        }
    }

    #[test]
    fn typed_reader_rejects_duplicate_and_conflicting_policy_fields() {
        #[derive(Deserialize)]
        struct Input(#[serde(deserialize_with = "deserialize_config")] SecretsConfig);
        for raw in [
            r#"{"secrets":[],"entries":[]}"#,
            r#"{"on_violation":"block","on_violation":"block-and-log"}"#,
            r#"{"on_violation":"block","violation_action":"block"}"#,
            r#"{"secrets":[{"env_var":"KEY","placeholder":"$KEY","injection":{"body":true,"body":false}}]}"#,
            r#"{"secrets":[{"env_var":"KEY","placeholder":"$KEY","injection":{},"substitution":{}}]}"#,
        ] {
            assert!(serde_json::from_str::<Input>(raw).is_err());
        }
        // Also read a successful value so the test wrapper is exercised in both directions.
        assert!(
            serde_json::from_str::<Input>("{}")
                .unwrap()
                .0
                .secrets
                .is_empty()
        );
    }

    #[test]
    fn legacy_header_scopes_merge_and_normalized_policies_round_trip() {
        for headers in [false, true] {
            for basic_auth in [false, true] {
                for query in [false, true] {
                    let mut value = json!({
                        "on_violation": {"passthrough": [{"wildcard": "*.example.com"}]},
                        "secrets": [{"env_var":"TOKEN", "value":"synthetic", "placeholder":"$KEY",
                            "allowed_hosts":[{"exact":"allowed.example"}],
                            "injection":{"headers":headers,"basic_auth":basic_auth,"query_params":query},
                            "on_violation":{"passthrough":[{"exact":"other.example"}]}}]
                    });
                    to_current(value.as_object_mut().unwrap()).unwrap();
                    let config: SecretsConfig = serde_json::from_value(value).unwrap();
                    assert_eq!(
                        config.secrets[0].substitution.headers,
                        headers || basic_auth
                    );
                    assert_eq!(config.secrets[0].substitution.query, query);

                    if headers || basic_auth || query {
                        config.validate().unwrap();
                    }
                    let expected = serde_json::to_value(config).unwrap();
                    let mut encoded = expected.clone();
                    to_previous_version(encoded.as_object_mut().unwrap()).unwrap();
                    assert_eq!(
                        encoded["secrets"][0]["injection"]["basic_auth"],
                        headers || basic_auth
                    );
                    to_current(encoded.as_object_mut().unwrap()).unwrap();
                    assert_eq!(encoded, expected);
                }
            }
        }
    }

    #[test]
    fn modern_scopes_stay_modern_and_missing_old_basic_auth_defaults_true() {
        let mut value = serde_json::to_value(SecretsConfig::default()).unwrap();
        let original = value.clone();
        to_current(value.as_object_mut().unwrap()).unwrap();
        assert_eq!(value, original);
        let mut value = json!({"on_violation":"block", "secrets":[{
            "env_var":"TOKEN", "value":"synthetic", "placeholder":"$KEY",
            "injection":{"headers":false}
        }]});
        to_current(value.as_object_mut().unwrap()).unwrap();
        assert_eq!(value["secrets"][0]["substitution"]["headers"], true);
    }

    #[test]
    fn previous_version_outer_names_do_not_enable_modern_scopes() {
        let mut value = json!({"on_violation":"block", "entries":[{
            "env_var":"TOKEN", "placeholder":"$KEY",
            "substitution":{"headers":false,"query":true,"body":false}
        }]});
        to_current(value.as_object_mut().unwrap()).unwrap();
        let config: SecretsConfig = serde_json::from_value(value).unwrap();
        assert!(!config.secrets[0].substitution.headers);
    }

    #[test]
    fn malformed_and_conflicting_legacy_policies_are_rejected() {
        for mut value in [
            json!({"on_violation":{"passthrough":[],"future":"private"}}),
            json!({"on_violation":{"passthrough":"private"}}),
            json!({"on_violation":{"passthrough":[]},"passthrough_hosts":[]}),
            json!({"secrets":[{"injection":{"basic_auth":"private"}}]}),
            json!({"secrets":[{"injection":{"headers":"private","basic_auth":true}}]}),
            json!({"secrets":[{"injection":{"query_params":false,"query":true}}]}),
            json!({"secrets":[{"on_violation":{"passthrough":[]},"passthrough_hosts":[]}]}),
        ] {
            let error = to_current(value.as_object_mut().unwrap()).unwrap_err();
            assert!(!error.contains("private"));
        }
    }
    #[test]
    fn unknown_saved_fields_survive_both_conversion_directions() {
        let mut value = json!({
            "future_policy": {"enabled": true},
            "on_violation": "block-and-log",
            "secrets": [{
                "env_var":"KEY", "placeholder":"$KEY",
                "future_entry": true,
                "source":{"kind":"env","var":"KEY","future_source":true},
                "injection":{"headers":false,"basic_auth":false,"future_scope":true}
            }]
        });
        to_current(value.as_object_mut().unwrap()).unwrap();
        for path in [
            "/future_policy/enabled",
            "/secrets/0/future_entry",
            "/secrets/0/source/future_source",
            "/secrets/0/substitution/future_scope",
        ] {
            assert_eq!(value.pointer(path), Some(&json!(true)), "{path}");
        }
        let normalized = value.clone();
        to_previous_version(value.as_object_mut().unwrap()).unwrap();
        to_current(value.as_object_mut().unwrap()).unwrap();
        assert_eq!(value, normalized);
    }

    #[test]
    fn alternate_catalog_contract_decodes_nonempty_secrets() {
        let mut value = json!({"on_violation":"block_and_log", "entries":[{
            "env_var":"KEY", "placeholder":"$KEY",
            "injection":{"headers":false,"basic_auth":false,"query_params":true,"body":false}
        }]});
        to_current(value.as_object_mut().unwrap()).unwrap();
        assert_eq!(value["violation_action"], "block-and-log");
        assert_eq!(value["secrets"][0]["substitution"]["headers"], false);
        assert_eq!(value["secrets"][0]["substitution"]["query"], true);
        assert!(value.get("entries").is_none());
    }

    #[test]
    fn conflicts_do_not_mutate_the_supplied_configuration() {
        for mut value in [
            json!({"entries":[],"secrets":[]}),
            json!({"on_violation":null,"violation_action":"block"}),
            json!({"secrets":[{"env_var":"KEY","placeholder":"$KEY","injection":{},"substitution":{}}]}),
        ] {
            let original = value.clone();
            assert!(to_current(value.as_object_mut().unwrap()).is_err());
            assert_eq!(value, original);
        }
        for name in ["basic_auth", "query_params"] {
            let mut value = json!({"secrets":[{"env_var":"KEY","placeholder":"$KEY",
                "substitution":{name:true}}]});
            let original = value.clone();
            assert!(to_previous_version(value.as_object_mut().unwrap()).is_err());
            assert_eq!(value, original);
        }
    }
}
