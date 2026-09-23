//! Typed translation of the v0.6 secret policy at persistence and launch boundaries.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::{HostPattern, SecretSource, SecretViolationAction, SecretsConfig};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Historical and current spellings are accepted only at compatibility boundaries.
#[derive(Deserialize)]
struct ConfigInput {
    #[serde(default, alias = "entries")]
    secrets: Vec<EntryInput>,
    #[serde(default, alias = "on_violation")]
    violation_action: Field<Option<HistoricalAction>>,
    #[serde(default)]
    passthrough_hosts: Field<Option<Vec<Preserved<HostPattern>>>>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

#[derive(Deserialize)]
struct EntryInput {
    #[serde(flatten)]
    fields: EntryFields,
    #[serde(default)]
    injection: Field<Injection>,
    #[serde(default)]
    substitution: Field<Substitution>,
    #[serde(default, alias = "on_violation")]
    violation_action: Field<Option<HistoricalAction>>,
    #[serde(default)]
    passthrough_hosts: Field<Vec<Preserved<HostPattern>>>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// Fields whose meaning did not change between the two formats.
#[derive(Serialize, Deserialize)]
struct EntryFields {
    env_var: String,
    #[serde(default)]
    value: Zeroizing<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<Preserved<SecretSource>>,
    placeholder: String,
    #[serde(default)]
    allowed_hosts: Vec<Preserved<HostPattern>>,
    #[serde(default = "default_true")]
    require_tls_identity: bool,
}

#[derive(Serialize, Deserialize)]
struct Injection {
    #[serde(default = "default_true")]
    headers: bool,
    #[serde(default = "default_true")]
    basic_auth: bool,
    #[serde(default, alias = "query")]
    query_params: bool,
    #[serde(default)]
    body: bool,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

#[derive(Serialize, Deserialize)]
struct Substitution {
    #[serde(default = "default_true")]
    headers: bool,
    #[serde(default)]
    query: bool,
    #[serde(default)]
    body: bool,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum HistoricalAction {
    #[serde(alias = "Block")]
    Block,
    #[serde(alias = "BlockAndLog", alias = "block_and_log")]
    BlockAndLog,
    #[serde(alias = "BlockAndTerminate")]
    BlockAndTerminate,
    #[serde(alias = "Passthrough")]
    Passthrough(Vec<Preserved<HostPattern>>),
}

#[derive(Serialize)]
struct CurrentConfig {
    secrets: Vec<CurrentEntry>,
    violation_action: SecretViolationAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    passthrough_hosts: Option<Vec<Preserved<HostPattern>>>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

#[derive(Serialize)]
struct CurrentEntry {
    #[serde(flatten)]
    fields: EntryFields,
    substitution: Substitution,
    passthrough_hosts: Vec<Preserved<HostPattern>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    violation_action: Option<SecretViolationAction>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

#[derive(Serialize)]
pub(super) struct HistoricalConfig {
    pub(super) secrets: Vec<HistoricalEntry>,
    pub(super) on_violation: HistoricalAction,
    #[serde(flatten)]
    pub(super) extra: Map<String, Value>,
}

#[derive(Serialize)]
pub(super) struct HistoricalEntry {
    #[serde(flatten)]
    fields: EntryFields,
    injection: Injection,
    #[serde(skip_serializing_if = "Option::is_none")]
    on_violation: Option<HistoricalAction>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// Distinguish missing fields from explicit nulls when checking conflicts.
#[derive(Default)]
enum Field<T> {
    #[default]
    Missing,
    Present(T),
}

/// Validate unchanged leaf types without discarding unrecognized saved fields.
/// Their original JSON remains visible to callers' preservation checks.
pub(super) struct Preserved<T> {
    _typed: T,
    original: Value,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ConfigInput {
    fn from_fields(fields: &Map<String, Value>) -> Result<Self, &'static str> {
        serde_json::from_value(Value::Object(fields.clone())).map_err(|error| {
            // Serde aliases reject simultaneous old/new spellings as duplicates.
            // Return fixed messages rather than exposing values from parse errors.
            if error.to_string().starts_with("duplicate field ") {
                "conflicting historical and current secret fields"
            } else {
                "invalid secret configuration"
            }
        })
    }

    fn into_current(self) -> Result<CurrentConfig, &'static str> {
        let (violation_action, historical_hosts) = match self.violation_action {
            Field::Missing => (SecretViolationAction::default(), None),
            Field::Present(None) => return Err("invalid secret violation action"),
            Field::Present(Some(HistoricalAction::Passthrough(hosts))) => {
                (SecretViolationAction::default(), Some(hosts))
            }
            Field::Present(Some(action)) => (action.blocking_action()?, None),
        };
        let passthrough_hosts = match (historical_hosts, self.passthrough_hosts) {
            (Some(_), Field::Present(_)) => {
                return Err("conflicting historical and current secret fields");
            }
            (Some(hosts), Field::Missing) => Some(hosts),
            (None, Field::Present(hosts)) => hosts,
            (None, Field::Missing) => None,
        };
        Ok(CurrentConfig {
            secrets: self
                .secrets
                .into_iter()
                .map(EntryInput::into_current)
                .collect::<Result<_, _>>()?,
            violation_action,
            passthrough_hosts,
            extra: self.extra,
        })
    }
}

impl EntryInput {
    fn into_current(self) -> Result<CurrentEntry, &'static str> {
        let substitution = match (self.injection, self.substitution) {
            (Field::Present(_), Field::Present(_)) => {
                return Err("conflicting historical and current secret fields");
            }
            (Field::Present(injection), Field::Missing) => injection.into(),
            (Field::Missing, Field::Present(substitution)) => substitution,
            (Field::Missing, Field::Missing) => Substitution {
                headers: true,
                query: false,
                body: false,
                extra: Map::new(),
            },
        };
        let (violation_action, historical_hosts) = match self.violation_action {
            Field::Missing | Field::Present(None) => (None, None),
            Field::Present(Some(HistoricalAction::Passthrough(hosts))) => (None, Some(hosts)),
            Field::Present(Some(action)) => (Some(action.blocking_action()?), None),
        };
        let passthrough_hosts = match (historical_hosts, self.passthrough_hosts) {
            (Some(_), Field::Present(_)) => {
                return Err("conflicting historical and current secret fields");
            }
            (Some(hosts), Field::Missing) | (None, Field::Present(hosts)) => hosts,
            (None, Field::Missing) => Vec::new(),
        };
        Ok(CurrentEntry {
            fields: self.fields,
            substitution,
            passthrough_hosts,
            violation_action,
            extra: self.extra,
        })
    }
}

impl HistoricalAction {
    fn blocking_action(self) -> Result<SecretViolationAction, &'static str> {
        match self {
            Self::Block => Ok(SecretViolationAction::Block),
            Self::BlockAndLog => Ok(SecretViolationAction::BlockAndLog),
            Self::BlockAndTerminate => Ok(SecretViolationAction::BlockAndTerminate),
            Self::Passthrough(_) => Err("expected a blocking secret violation action"),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<Injection> for Substitution {
    fn from(input: Injection) -> Self {
        Self {
            headers: input.headers || input.basic_auth,
            query: input.query_params,
            body: input.body,
            extra: input.extra,
        }
    }
}

impl From<Substitution> for Injection {
    fn from(input: Substitution) -> Self {
        Self {
            headers: input.headers,
            basic_auth: input.headers,
            query_params: input.query,
            body: input.body,
            extra: input.extra,
        }
    }
}

impl From<SecretViolationAction> for HistoricalAction {
    fn from(action: SecretViolationAction) -> Self {
        match action {
            SecretViolationAction::Block => Self::Block,
            SecretViolationAction::BlockAndLog => Self::BlockAndLog,
            SecretViolationAction::BlockAndTerminate => Self::BlockAndTerminate,
        }
    }
}

impl TryFrom<CurrentConfig> for HistoricalConfig {
    type Error = &'static str;

    fn try_from(config: CurrentConfig) -> Result<Self, Self::Error> {
        let on_violation = if let Some(hosts) = config.passthrough_hosts {
            if config.violation_action != SecretViolationAction::BlockAndLog {
                return Err("legacy global passthrough requires the block-and-log fallback");
            }
            HistoricalAction::Passthrough(hosts)
        } else {
            config.violation_action.into()
        };
        Ok(Self {
            secrets: config
                .secrets
                .into_iter()
                .map(HistoricalEntry::try_from)
                .collect::<Result<_, _>>()?,
            on_violation,
            extra: config.extra,
        })
    }
}

impl TryFrom<CurrentEntry> for HistoricalEntry {
    type Error = &'static str;

    fn try_from(entry: CurrentEntry) -> Result<Self, Self::Error> {
        if entry.substitution.extra.contains_key("basic_auth")
            || entry.substitution.extra.contains_key("query_params")
        {
            return Err("conflicting historical and current secret fields");
        }
        let on_violation = if entry.passthrough_hosts.is_empty() {
            entry.violation_action.map(Into::into)
        } else {
            if entry.violation_action.is_some() {
                return Err("legacy per-secret passthrough cannot override the global fallback");
            }
            Some(HistoricalAction::Passthrough(entry.passthrough_hosts))
        };
        Ok(Self {
            fields: entry.fields,
            injection: entry.substitution.into(),
            on_violation,
            extra: entry.extra,
        })
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Field<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(Self::Present)
    }
}

impl<'de, T: serde::de::DeserializeOwned> Deserialize<'de> for Preserved<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let original = Value::deserialize(deserializer)?;
        let typed = serde_json::from_value(original.clone()).map_err(serde::de::Error::custom)?;
        Ok(Self {
            _typed: typed,
            original,
        })
    }
}

impl<T> Serialize for Preserved<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.original.serialize(serializer)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Normalize released fields using typed input and current output contracts.
/// Unknown saved fields remain present for the caller's preservation checks.
/// Errors never contain secret values.
pub fn normalize(fields: &mut Map<String, Value>) -> Result<(), &'static str> {
    let input = ConfigInput::from_fields(fields)?;
    *fields = object(input.into_current()?)?;
    Ok(())
}

/// Restore released spellings when talking to a v0.6 runtime or catalog.
pub fn encode(fields: &mut Map<String, Value>) -> Result<(), &'static str> {
    *fields = object(historical(fields)?)?;
    Ok(())
}

pub(super) fn historical(fields: &Map<String, Value>) -> Result<HistoricalConfig, &'static str> {
    HistoricalConfig::try_from(ConfigInput::from_fields(fields)?.into_current()?)
}

pub(super) fn object(value: impl Serialize) -> Result<Map<String, Value>, &'static str> {
    match serde_json::to_value(value).map_err(|_| "invalid secret configuration")? {
        Value::Object(fields) => Ok(fields),
        _ => Err("invalid secret configuration"),
    }
}

fn default_true() -> bool {
    true
}

/// Resolve saved defaults into fields understood by released v0.7 runtimes.
/// This projection is launch-only: the source retains defaults for later edits.
pub fn for_current_runtime(source: &SecretsConfig) -> SecretsConfig {
    let mut policy = source.clone();
    policy.passthrough_hosts = None;
    for entry in &mut policy.secrets {
        if entry.violation_action.is_none()
            && let Some(hosts) = &source.passthrough_hosts
        {
            for host in hosts {
                if !entry.passthrough_hosts.contains(host) {
                    entry.passthrough_hosts.push(host.clone());
                }
            }
        }
    }
    policy
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

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
                    normalize(value.as_object_mut().unwrap()).unwrap();
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
                    encode(encoded.as_object_mut().unwrap()).unwrap();
                    assert_eq!(
                        encoded["secrets"][0]["injection"]["basic_auth"],
                        headers || basic_auth
                    );
                    normalize(encoded.as_object_mut().unwrap()).unwrap();
                    assert_eq!(encoded, expected);
                }
            }
        }
    }

    #[test]
    fn modern_scopes_stay_modern_and_missing_old_basic_auth_defaults_true() {
        let mut value = serde_json::to_value(SecretsConfig::default()).unwrap();
        let original = value.clone();
        normalize(value.as_object_mut().unwrap()).unwrap();
        assert_eq!(value, original);
        let mut value = json!({"on_violation":"block", "secrets":[{
            "env_var":"TOKEN", "value":"synthetic", "placeholder":"$KEY",
            "injection":{"headers":false}
        }]});
        normalize(value.as_object_mut().unwrap()).unwrap();
        assert_eq!(value["secrets"][0]["substitution"]["headers"], true);
    }

    #[test]
    fn historical_outer_names_do_not_enable_modern_scopes() {
        let mut value = json!({"on_violation":"block", "entries":[{
            "env_var":"TOKEN", "placeholder":"$KEY",
            "substitution":{"headers":false,"query":true,"body":false}
        }]});
        normalize(value.as_object_mut().unwrap()).unwrap();
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
            let error = normalize(value.as_object_mut().unwrap()).unwrap_err();
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
        normalize(value.as_object_mut().unwrap()).unwrap();
        for path in [
            "/future_policy/enabled",
            "/secrets/0/future_entry",
            "/secrets/0/source/future_source",
            "/secrets/0/substitution/future_scope",
        ] {
            assert_eq!(value.pointer(path), Some(&json!(true)), "{path}");
        }
        let normalized = value.clone();
        encode(value.as_object_mut().unwrap()).unwrap();
        normalize(value.as_object_mut().unwrap()).unwrap();
        assert_eq!(value, normalized);
    }

    #[test]
    fn alternate_catalog_contract_round_trips_nonempty_secrets() {
        let mut value = json!({"secrets":[{"env_var":"KEY","placeholder":"$KEY",
            "substitution":{"headers":false,"query":true}}]});
        normalize(value.as_object_mut().unwrap()).unwrap();
        let expected = value.clone();
        crate::compatibility::v0_6::local::catalog_v0_6_5::encode(value.as_object_mut().unwrap())
            .unwrap();
        assert_eq!(value["on_violation"], "block_and_log");
        assert_eq!(value["entries"][0]["injection"]["basic_auth"], false);
        assert_eq!(value["entries"][0]["injection"]["query_params"], true);
        assert!(value.get("secrets").is_none());
        normalize(value.as_object_mut().unwrap()).unwrap();
        assert_eq!(value, expected);
    }

    #[test]
    fn conflicts_do_not_mutate_the_supplied_configuration() {
        for mut value in [
            json!({"entries":[],"secrets":[]}),
            json!({"on_violation":null,"violation_action":"block"}),
            json!({"secrets":[{"env_var":"KEY","placeholder":"$KEY","injection":{},"substitution":{}}]}),
        ] {
            let original = value.clone();
            assert!(normalize(value.as_object_mut().unwrap()).is_err());
            assert_eq!(value, original);
        }
        for name in ["basic_auth", "query_params"] {
            let mut value = json!({"secrets":[{"env_var":"KEY","placeholder":"$KEY",
                "substitution":{name:true}}]});
            let original = value.clone();
            assert!(encode(value.as_object_mut().unwrap()).is_err());
            assert_eq!(value, original);
        }
    }
}
