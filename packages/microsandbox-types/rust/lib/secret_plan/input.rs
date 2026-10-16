//! Value-free planner input and the adapters that build it.

use std::collections::BTreeMap;

use crate::cloud::{
    CloudHostPattern, CloudSecretApplyEntry, CloudSecretMaterial, CloudSecretPlanEntry,
};
use crate::domain::{HostPattern, SecretEntry, SecretSubstitution, SecretViolationAction};
use crate::modify::{ModificationPolicy, SecretModificationPatch, SecretSource};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Sandbox status as the planner classifies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretPlanStatus {
    /// No VM runs: every change persists for the next start.
    Stopped,

    /// A VM runs: a change applies live, needs a restart, or waits for the
    /// next start under the `next_start` policy.
    Running,

    /// Between states: only `next_start` changes can be planned.
    Transitional {
        /// Status name shown in reasons.
        name: &'static str,
    },
}

/// Value-free settings of one secret, as saved or as the running sandbox has them.
#[derive(Debug, Clone)]
pub struct SecretSettings {
    /// Secret name (its environment variable).
    pub name: String,

    /// Guest-visible placeholder.
    pub placeholder: String,

    /// Hosts allowed to receive the value, as user-facing host strings.
    pub allowed_hosts: Vec<String>,

    /// Request locations where the placeholder is substituted.
    pub substitution: SecretSubstitution,

    /// Hosts allowed to receive the placeholder unchanged.
    pub passthrough_hosts: Vec<String>,

    /// Per-secret violation action, if one overrides the default.
    pub violation_action: Option<SecretViolationAction>,

    /// Whether substitution requires verified TLS identity.
    pub require_tls_identity: bool,
}

/// What the running sandbox has for one secret.
///
/// A name missing from the map means the running sandbox has no such secret.
#[derive(Debug, Clone)]
pub enum RunningSecret {
    /// The running sandbox uses these settings.
    Known(SecretSettings),

    /// The running sandbox may have the secret, with settings the backend cannot see.
    Unknown,
}

/// What a backend can do to a running sandbox's secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretPlanCapability {
    /// The backend can modify secrets at all. Each backend supplies it. When it is
    /// false, every secret change is planned unsupported with Local's reason, a
    /// build without the `net` feature, since only Local can lack support.
    pub supported: bool,

    /// A rotation, an allowed-hosts change and a removal reach the running sandbox.
    pub live: bool,

    /// `modify` can restart the sandbox to apply restart-required changes.
    pub restart: bool,
}

/// Material a desired secret carries, without the value itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesiredMaterial {
    /// No new material: the secret keeps its value.
    Keep,

    /// A caller-supplied value.
    Value,

    /// A host-side source reference.
    Source(SecretSource),

    /// Both a value and a source, which the planner refuses.
    ValueAndSource(SecretSource),
}

/// One value-free secret spec of a modification patch.
#[derive(Debug, Clone)]
pub struct DesiredSecret {
    /// Secret name (its environment variable).
    pub name: String,

    /// Material the spec carries.
    pub material: DesiredMaterial,

    /// Requested placeholder, if any.
    pub placeholder: Option<String>,

    /// Requested allowed hosts; empty leaves an existing list unchanged.
    pub allowed_hosts: Vec<String>,

    /// Requested substitution locations; `None` leaves them unchanged.
    pub substitution: Option<SecretSubstitution>,

    /// Requested passthrough hosts; empty leaves an existing list unchanged.
    pub passthrough_hosts: Vec<String>,

    /// Requested violation action; `None` leaves it unchanged.
    pub violation_action: Option<SecretViolationAction>,

    /// Requested TLS identity requirement; `None` leaves it unchanged.
    pub require_tls_identity: Option<bool>,
}

/// Everything the planner reads, borrowed from the caller.
#[derive(Debug, Clone, Copy)]
pub struct SecretPlanInput<'a> {
    /// Sandbox status.
    pub status: SecretPlanStatus,

    /// Requested modification policy.
    pub policy: ModificationPolicy,

    /// What the backend can do to a running sandbox.
    pub capability: SecretPlanCapability,

    /// Saved settings of every configured secret.
    pub saved: &'a [SecretSettings],

    /// The running sandbox's secrets; `None` when the backend has no view of them.
    pub running: Option<&'a BTreeMap<String, RunningSecret>>,

    /// Requested secret specs.
    pub secrets: &'a [DesiredSecret],

    /// Requested removals.
    pub secrets_remove: &'a [String],
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DesiredMaterial {
    /// Whether the spec carries new material: a value, a source, or both.
    pub fn carries_material(&self) -> bool {
        !matches!(self, Self::Keep)
    }

    /// The source reference, if the spec carries one.
    pub fn source(&self) -> Option<&SecretSource> {
        match self {
            Self::Source(source) | Self::ValueAndSource(source) => Some(source),
            Self::Keep | Self::Value => None,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<&SecretEntry> for SecretSettings {
    fn from(entry: &SecretEntry) -> Self {
        Self {
            name: entry.env_var.clone(),
            placeholder: entry.placeholder.clone(),
            allowed_hosts: entry.allowed_hosts.iter().map(host_string).collect(),
            substitution: entry.substitution.clone(),
            passthrough_hosts: entry.passthrough_hosts.iter().map(host_string).collect(),
            violation_action: entry.violation_action.clone(),
            require_tls_identity: entry.require_tls_identity,
        }
    }
}

impl From<&SecretModificationPatch> for DesiredSecret {
    fn from(spec: &SecretModificationPatch) -> Self {
        let material = match (spec.value.is_empty(), &spec.source) {
            (true, None) => DesiredMaterial::Keep,
            (false, None) => DesiredMaterial::Value,
            (true, Some(source)) => DesiredMaterial::Source(source.clone()),
            (false, Some(source)) => DesiredMaterial::ValueAndSource(source.clone()),
        };
        Self {
            name: spec.name.clone(),
            material,
            placeholder: spec.placeholder.clone(),
            allowed_hosts: spec.allowed_hosts.clone(),
            substitution: spec.substitution.clone(),
            passthrough_hosts: spec.passthrough_hosts.clone(),
            violation_action: spec.violation_action.clone(),
            require_tls_identity: spec.require_tls_identity,
        }
    }
}

impl From<&CloudSecretPlanEntry> for DesiredSecret {
    fn from(entry: &CloudSecretPlanEntry) -> Self {
        Self {
            name: entry.name.clone(),
            material: match entry.material {
                CloudSecretMaterial::Provided => DesiredMaterial::Value,
                CloudSecretMaterial::Absent => DesiredMaterial::Keep,
            },
            placeholder: entry.placeholder.clone(),
            allowed_hosts: cloud_host_strings(entry.allowed_hosts.as_deref()),
            substitution: entry.substitution.clone(),
            passthrough_hosts: cloud_host_strings(entry.passthrough_hosts.as_deref()),
            violation_action: entry.violation_action.clone().map(Into::into),
            require_tls_identity: entry.require_tls_identity,
        }
    }
}

/// The value stays with the apply entry; the planner sees only that one is present.
impl From<&CloudSecretApplyEntry> for DesiredSecret {
    fn from(entry: &CloudSecretApplyEntry) -> Self {
        Self {
            name: entry.name.clone(),
            material: if entry.value.is_some() {
                DesiredMaterial::Value
            } else {
                DesiredMaterial::Keep
            },
            placeholder: entry.placeholder.clone(),
            allowed_hosts: cloud_host_strings(entry.allowed_hosts.as_deref()),
            substitution: entry.substitution.clone(),
            passthrough_hosts: cloud_host_strings(entry.passthrough_hosts.as_deref()),
            violation_action: entry.violation_action.clone().map(Into::into),
            require_tls_identity: entry.require_tls_identity,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// The default guest-visible placeholder for a secret.
///
/// The same format as `microsandbox_utils::secret::default_placeholder`, which
/// this crate does not depend on; a test checks that both agree.
pub(super) fn default_placeholder(name: &str) -> String {
    format!("$MSB_{name}")
}

/// Wire host patterns as patch host strings; absent means "unchanged", as empty does.
fn cloud_host_strings(hosts: Option<&[CloudHostPattern]>) -> Vec<String> {
    hosts
        .into_iter()
        .flatten()
        .map(|host| host_string(&HostPattern::from(host.clone())))
        .collect()
}

/// The user-facing string of a host pattern, as a patch states it.
fn host_string(host: &HostPattern) -> String {
    match host {
        HostPattern::Exact(host) | HostPattern::Wildcard(host) => host.clone(),
        HostPattern::Any => "*".to_string(),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::*;

    fn entry() -> SecretEntry {
        SecretEntry {
            env_var: "API_KEY".into(),
            value: Zeroizing::new("dummy-value".into()),
            source: None,
            placeholder: "$MSB_API_KEY".into(),
            allowed_hosts: vec![HostPattern::Exact("api.example.com".into())],
            substitution: SecretSubstitution::default(),
            passthrough_hosts: Vec::new(),
            violation_action: None,
            require_tls_identity: true,
        }
    }

    #[test]
    fn default_placeholder_matches_utils() {
        for name in ["API_KEY", "a", "OPENAI_API_KEY_2"] {
            assert_eq!(
                default_placeholder(name),
                microsandbox_utils::secret::default_placeholder(name)
            );
        }
    }

    #[test]
    fn host_string_formats_each_pattern() {
        for (pattern, expected) in [
            (
                HostPattern::Exact("api.example.com".into()),
                "api.example.com",
            ),
            (
                HostPattern::Wildcard("*.example.com".into()),
                "*.example.com",
            ),
            (HostPattern::Any, "*"),
        ] {
            assert_eq!(host_string(&pattern), expected);
            assert_eq!(HostPattern::parse(&host_string(&pattern)), pattern);
        }
    }

    #[test]
    fn secret_settings_from_entry() {
        let hosts = vec![
            HostPattern::Exact("api.example.com".into()),
            HostPattern::Wildcard("*.example.org".into()),
            HostPattern::Any,
        ];
        let host_strings = vec!["api.example.com", "*.example.org", "*"];
        let substitutions = [
            SecretSubstitution::default(),
            SecretSubstitution {
                headers: false,
                header_fields: Vec::new(),
                query: true,
                body: true,
            },
            SecretSubstitution {
                header_fields: vec!["authorization".into()],
                ..SecretSubstitution::default()
            },
        ];
        let actions = [
            None,
            Some(SecretViolationAction::Block),
            Some(SecretViolationAction::BlockAndLog),
            Some(SecretViolationAction::BlockAndTerminate),
        ];
        for substitution in &substitutions {
            for action in &actions {
                for require_tls_identity in [true, false] {
                    let entry = SecretEntry {
                        allowed_hosts: hosts.clone(),
                        substitution: substitution.clone(),
                        passthrough_hosts: hosts.clone(),
                        violation_action: action.clone(),
                        require_tls_identity,
                        ..entry()
                    };
                    let settings = SecretSettings::from(&entry);
                    assert_eq!(settings.name, "API_KEY");
                    assert_eq!(settings.placeholder, "$MSB_API_KEY");
                    assert_eq!(settings.allowed_hosts, host_strings);
                    assert_eq!(settings.passthrough_hosts, host_strings);
                    assert_eq!(settings.substitution.headers, substitution.headers);
                    assert_eq!(
                        settings.substitution.header_fields,
                        substitution.header_fields
                    );
                    assert_eq!(settings.substitution.query, substitution.query);
                    assert_eq!(settings.substitution.body, substitution.body);
                    assert_eq!(settings.violation_action, *action);
                    assert_eq!(settings.require_tls_identity, require_tls_identity);
                    assert!(!format!("{settings:?}").contains("dummy-value"));
                }
            }
        }
    }

    #[test]
    fn desired_secret_from_cloud_requests_matches_the_patch() {
        use crate::cloud::{
            CloudSandboxModificationApplyRequest, CloudSandboxModificationPlanRequest,
        };
        use crate::modify::{ModificationPolicy, SandboxModificationPatch};

        let spec = |value: &str| SecretModificationPatch {
            name: "API_KEY".into(),
            value: Zeroizing::new(value.into()),
            placeholder: Some("$API_KEY".into()),
            allowed_hosts: vec!["api.example.com".into(), "*.example.org".into(), "*".into()],
            substitution: Some(SecretSubstitution {
                query: true,
                ..SecretSubstitution::default()
            }),
            passthrough_hosts: vec!["logs.example.com".into()],
            violation_action: Some(SecretViolationAction::BlockAndTerminate),
            require_tls_identity: Some(false),
            ..SecretModificationPatch::default()
        };
        for value in ["dummy-value", ""] {
            let patch = SandboxModificationPatch {
                secrets: vec![spec(value)],
                ..SandboxModificationPatch::default()
            };
            let expected = format!("{:?}", DesiredSecret::from(&patch.secrets[0]));
            let plan = CloudSandboxModificationPlanRequest::from_patch(
                &patch,
                ModificationPolicy::NoRestart,
            )
            .unwrap();
            let apply = CloudSandboxModificationApplyRequest::from_patch(
                &patch,
                ModificationPolicy::NoRestart,
                |_| None,
            )
            .unwrap();
            assert_eq!(
                format!("{:?}", DesiredSecret::from(&plan.secrets[0])),
                expected
            );
            assert_eq!(
                format!("{:?}", DesiredSecret::from(&apply.secrets[0])),
                expected
            );
            assert!(!expected.contains("dummy-value"));
        }
    }

    #[test]
    fn desired_secret_from_patch_drops_the_value() {
        let source = SecretSource::env("API_KEY");
        for (value, source, expected) in [
            ("", None, DesiredMaterial::Keep),
            ("dummy-value", None, DesiredMaterial::Value),
            (
                "",
                Some(source.clone()),
                DesiredMaterial::Source(source.clone()),
            ),
            (
                "dummy-value",
                Some(source.clone()),
                DesiredMaterial::ValueAndSource(source.clone()),
            ),
        ] {
            let spec = SecretModificationPatch {
                name: "API_KEY".into(),
                value: Zeroizing::new(value.into()),
                source,
                allowed_hosts: vec!["api.example.com".into()],
                ..SecretModificationPatch::default()
            };
            let desired = DesiredSecret::from(&spec);
            assert_eq!(desired.material, expected);
            assert_eq!(desired.allowed_hosts, ["api.example.com"]);
            assert!(!format!("{desired:?}").contains("dummy-value"));
        }
    }
}
