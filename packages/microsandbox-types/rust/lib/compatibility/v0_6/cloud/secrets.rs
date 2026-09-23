//! Typed inputs for historical and current cloud secret policies.

use serde::{Deserialize, Deserializer};

use crate::SecretSubstitution;
use crate::cloud::{
    CloudHostPattern, CloudSecretEntry, CloudSecretSource, CloudSecretsConfig, CloudViolationAction,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Deserialize)]
struct ConfigInput {
    #[serde(default)]
    entries: Vec<EntryInput>,
    #[serde(flatten)]
    policy: PolicyInput,
}

#[derive(Deserialize)]
struct EntryInput {
    env_var: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    source: Option<CloudSecretSource>,
    placeholder: String,
    #[serde(default)]
    allowed_hosts: Vec<CloudHostPattern>,
    #[serde(default)]
    injection: Field<InjectionInput>,
    #[serde(default)]
    substitution: Field<SecretSubstitution>,
    #[serde(flatten)]
    policy: PolicyInput,
    #[serde(default = "default_true")]
    require_tls_identity: bool,
}

/// Keep both spellings explicit so mixed requests cannot silently override one another.
#[derive(Default, Deserialize)]
struct PolicyInput {
    #[serde(default)]
    on_violation: Field<Option<HistoricalAction>>,
    #[serde(default)]
    violation_action: Field<Option<CloudViolationAction>>,
    #[serde(default)]
    passthrough_hosts: Field<Option<Vec<CloudHostPattern>>>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum HistoricalAction {
    Block,
    BlockAndLog,
    BlockAndTerminate,
    Passthrough { hosts: Vec<CloudHostPattern> },
}

#[derive(Deserialize)]
struct InjectionInput {
    #[serde(default = "default_true")]
    headers: bool,
    #[serde(default = "default_true")]
    basic_auth: bool,
    #[serde(default, alias = "query")]
    query_params: bool,
    #[serde(default)]
    body: bool,
}

/// Presence matters: an explicit null must not hide conflicting field names.
#[derive(Default)]
enum Field<T> {
    #[default]
    Missing,
    Present(T),
}

struct ResolvedPolicy {
    action: Option<CloudViolationAction>,
    passthrough_hosts: Option<Vec<CloudHostPattern>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ConfigInput {
    fn into_current(self) -> Result<CloudSecretsConfig, &'static str> {
        // Global actions cannot be null; per-secret null means inherit the default.
        if matches!(self.policy.on_violation, Field::Present(None))
            || matches!(self.policy.violation_action, Field::Present(None))
        {
            return Err("invalid cloud secret violation action");
        }
        let policy = self.policy.resolve()?;
        Ok(CloudSecretsConfig {
            entries: self
                .entries
                .into_iter()
                .map(EntryInput::into_current)
                .collect::<Result<_, _>>()?,
            violation_action: policy.action.unwrap_or_default(),
            passthrough_hosts: policy.passthrough_hosts,
        })
    }
}

impl EntryInput {
    fn into_current(self) -> Result<CloudSecretEntry, &'static str> {
        let substitution = match (self.injection, self.substitution) {
            (Field::Present(_), Field::Present(_)) => {
                return Err("conflicting historical and current secret fields");
            }
            (Field::Present(injection), Field::Missing) => injection.into(),
            (Field::Missing, Field::Present(substitution)) => substitution,
            (Field::Missing, Field::Missing) => SecretSubstitution::default(),
        };
        if matches!(self.policy.passthrough_hosts, Field::Present(None)) {
            return Err("invalid cloud secret hosts");
        }
        let policy = self.policy.resolve()?;
        Ok(CloudSecretEntry {
            env_var: self.env_var,
            value: self.value,
            source: self.source,
            placeholder: self.placeholder,
            allowed_hosts: self.allowed_hosts,
            substitution,
            passthrough_hosts: policy.passthrough_hosts.unwrap_or_default(),
            violation_action: policy.action,
            require_tls_identity: self.require_tls_identity,
        })
    }
}

impl PolicyInput {
    fn resolve(self) -> Result<ResolvedPolicy, &'static str> {
        let action = match (self.on_violation, self.violation_action) {
            (Field::Present(_), Field::Present(_)) => {
                return Err("conflicting historical and current secret fields");
            }
            (Field::Present(Some(HistoricalAction::Passthrough { hosts })), Field::Missing) => {
                if matches!(self.passthrough_hosts, Field::Present(_)) {
                    return Err("conflicting historical and current secret fields");
                }
                return Ok(ResolvedPolicy {
                    action: None,
                    passthrough_hosts: Some(hosts),
                });
            }
            (Field::Present(Some(HistoricalAction::Block)), Field::Missing) => {
                Some(CloudViolationAction::Block)
            }
            (Field::Present(Some(HistoricalAction::BlockAndLog)), Field::Missing) => {
                Some(CloudViolationAction::BlockAndLog)
            }
            (Field::Present(Some(HistoricalAction::BlockAndTerminate)), Field::Missing) => {
                Some(CloudViolationAction::BlockAndTerminate)
            }
            (Field::Missing, Field::Present(action)) => action,
            _ => None,
        };
        let passthrough_hosts = match self.passthrough_hosts {
            Field::Missing => None,
            Field::Present(hosts) => hosts,
        };
        Ok(ResolvedPolicy {
            action,
            passthrough_hosts,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<InjectionInput> for SecretSubstitution {
    fn from(input: InjectionInput) -> Self {
        Self {
            // Current header substitution also covers decoded Basic Auth credentials.
            headers: input.headers || input.basic_auth,
            query: input.query_params,
            body: input.body,
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Field<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(Self::Present)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn config<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<CloudSecretsConfig, D::Error> {
    let input = ConfigInput::deserialize(deserializer)
        .map_err(|_| serde::de::Error::custom("invalid cloud secret configuration"))?;
    input.into_current().map_err(serde::de::Error::custom)
}

pub(crate) fn entry<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<CloudSecretEntry, D::Error> {
    let input = EntryInput::deserialize(deserializer)
        .map_err(|_| serde::de::Error::custom("invalid cloud secret entry"))?;
    input.into_current().map_err(serde::de::Error::custom)
}

fn default_true() -> bool {
    true
}
