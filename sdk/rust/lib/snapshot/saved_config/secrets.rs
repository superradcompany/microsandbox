//! Keyed substitution selection without reading credentials or authorizing guest activation.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_ENTRIES, SavedBindingUses, SavedNetworkConfig, SavedRuntimeConfig,
    SavedSecret, SavedSecretsConfig, SavedValue, collect_binding_uses,
};
use microsandbox_types::{SecretEntry, SecretsConfigPatch};

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One substitution identity. Explicit credentials remain destination inputs, never metadata.
#[derive(Clone)]
pub struct SecretInputSelection {
    /// Stable configured environment key, independent of the secret's value.
    pub env_var: String,
    /// Recorded placeholder and policy, if known.
    pub saved: Option<SavedSecret>,
    /// Explicit destination entry; its value/source must never be exported as a saved literal.
    pub destination: Option<SecretEntry>,
}

/// Selection only; binding preparation, policy enforcement and captured-state checks remain.
pub struct SecretInputPlan {
    /// Saved order with replacements in place, followed by new destination entries.
    pub entries: Vec<SecretInputSelection>,
    /// Lower-priority global policy only; this patch never contains secret entries or values.
    pub global_defaults: SecretsConfigPatch,
    /// A recorded absent global passthrough value must not revive an inherited global policy.
    pub global_passthrough_absent: bool,
    /// Remaining logical inputs derived from unsupplied entries, with shared IDs preserved.
    pub remaining_bindings: SavedBindingUses,
    /// Saved entries disabling TLS identity need field-specific destination approval.
    pub tls_identity_approvals: BTreeSet<String>,
    /// Unknown source metadata is not a checked empty substitution inventory.
    pub source_unknown: bool,
    /// A recorded builtin default requires explicit default application during assembly.
    pub source_defaulted: bool,
    /// Full resume still requires independently checked captured placeholders/connections.
    pub requires_full_identity: bool,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for SecretInputSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretInputSelection")
            .field("has_saved", &self.saved.is_some())
            .field("has_destination", &self.destination.is_some())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for SecretInputPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretInputPlan")
            .field("entry_count", &self.entries.len())
            .field("binding_count", &self.remaining_bindings.len())
            .field("approval_count", &self.tls_identity_approvals.len())
            .field("source_unknown", &self.source_unknown)
            .field("source_defaulted", &self.source_defaulted)
            .field("requires_full_identity", &self.requires_full_identity)
            .finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Match selected secret requirements by environment key, preserving all other requirements.
///
/// Mode/optional-clear selection precedes this step; required captured uses must also be
/// merged independently into binding demand. An explicit empty list is not permission to
/// discard other selected bindings. Full resume cannot change a known captured placeholder.
/// New explicit entries are destination defaults/policy, never an instruction to inject
/// environment into captured processes. No credential source is opened or resolved here.
pub fn select_secret_inputs(
    saved: Option<&SavedValue<SavedSecretsConfig>>,
    explicit: Option<&SecretsConfigPatch>,
    full_resume: bool,
) -> MicrosandboxResult<SecretInputPlan> {
    // Validate the original section before any override can hide malformed identities.
    let source = SavedNetworkConfig {
        secrets: saved.cloned(),
        ..Default::default()
    };
    source
        .validate()
        .map_err(|_| error("SCFG_VALUE", "invalid saved substitution metadata"))?;
    let configured = saved.and_then(SavedValue::value);
    // Substitution can depend on order (including overlapping placeholders). Use
    // the map only for identity lookup, never to reorder the resulting policy.
    let mut positions = BTreeMap::new();
    let mut entries = Vec::new();
    if let Some(source) = configured {
        for secret in &source.entries {
            positions.insert(secret.env_var.clone(), entries.len());
            entries.push(SecretInputSelection {
                env_var: secret.env_var.clone(),
                saved: Some(secret.clone()),
                destination: None,
            });
        }
    }
    let supplied = explicit.and_then(SecretsConfigPatch::get_secrets);
    if supplied.is_some_and(|values| values.len() > MAX_SAVED_CONFIG_ENTRIES) {
        return Err(error("SCFG_LIMIT", "too many destination secret entries"));
    }
    let mut supplied_names = BTreeSet::new();
    for secret in supplied.into_iter().flatten() {
        if !supplied_names.insert(&secret.env_var) {
            return Err(error(
                "SCFG_IDENTITY",
                "duplicate destination environment key",
            ));
        }
        secret
            .validate(0)
            .map_err(|_| error("SCFG_VALUE", "invalid destination substitution policy"))?;
        let position = *positions.entry(secret.env_var.clone()).or_insert_with(|| {
            entries.push(SecretInputSelection {
                env_var: secret.env_var.clone(),
                saved: None,
                destination: None,
            });
            entries.len() - 1
        });
        let entry = &mut entries[position];
        if full_resume
            && entry
                .saved
                .as_ref()
                .is_some_and(|saved| saved.placeholder != secret.placeholder)
        {
            return Err(error(
                "SCFG_FULL_STATE",
                "destination substitution changes a recorded placeholder",
            ));
        }
        entry.destination = Some(secret.clone());
    }
    if entries.len() > MAX_SAVED_CONFIG_ENTRIES {
        return Err(error("SCFG_LIMIT", "too many combined secret entries"));
    }
    // Validate the combined view, not just each input list. Reusing a placeholder for
    // a different surviving key would route existing guest traffic to another secret.
    let mut placeholders = BTreeSet::new();
    for entry in &entries {
        let placeholder = match (&entry.destination, &entry.saved) {
            (Some(destination), _) => &destination.placeholder,
            (None, Some(saved)) => &saved.placeholder,
            (None, None) => unreachable!("selected entry has a source or destination"),
        };
        if !placeholders.insert(placeholder) {
            return Err(error(
                "SCFG_IDENTITY",
                "conflicting selected placeholder identities",
            ));
        }
    }
    let mut remaining = configured.cloned();
    if let Some(remaining) = &mut remaining {
        remaining
            .entries
            .retain(|entry| !supplied_names.contains(&entry.env_var));
    }
    let mut remaining_source = source;
    if let Some(SavedValue::Value { value, .. }) = &mut remaining_source.secrets {
        *value = remaining.expect("concrete source has a remaining projection");
    }
    let remaining_bindings =
        collect_binding_uses(&SavedRuntimeConfig::default(), &remaining_source)
            .map_err(|_| error("SCFG_BINDING", "invalid selected secret requirements"))?;
    let mut global_defaults = SecretsConfigPatch::new();
    let mut global_passthrough_absent = false;
    if let Some(source) = configured {
        if explicit.is_none_or(|patch| patch.passthrough_hosts.is_none()) {
            global_defaults.passthrough_hosts = source.passthrough_hosts.clone();
            global_passthrough_absent = source.passthrough_hosts.is_none();
        }
        if explicit.is_none_or(|patch| patch.violation_action.is_none()) {
            global_defaults.violation_action = Some(source.violation_action.clone());
        }
    }
    let tls_identity_approvals = entries
        .iter()
        .filter(|entry| {
            entry.destination.is_none()
                && entry
                    .saved
                    .as_ref()
                    .is_some_and(|saved| !saved.require_tls_identity)
        })
        .map(|entry| entry.env_var.clone())
        .collect();
    Ok(SecretInputPlan {
        entries,
        global_defaults,
        global_passthrough_absent,
        remaining_bindings,
        tls_identity_approvals,
        source_unknown: saved.is_none() || matches!(saved, Some(SavedValue::Unknown { .. })),
        source_defaulted: matches!(saved, Some(SavedValue::Default {})),
        requires_full_identity: full_resume,
    })
}

fn error(code: &str, reason: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(format!("{code}: network.secrets: {reason}"))
}
