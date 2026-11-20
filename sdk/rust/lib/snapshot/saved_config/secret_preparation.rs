//! Compose destination substitution inputs without resolving or exporting credentials.

use std::collections::BTreeMap;
use std::fmt;

use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_BYTES, MAX_SAVED_CONFIG_ENTRIES, MAX_SAVED_TEXT_BYTES, SavedSecret,
    SavedSecretsConfig, SavedValue,
};
use microsandbox_types::{
    SecretEntry, SecretSource, SecretSubstitution, SecretsConfig, SecretsConfigPatch,
};
use zeroize::Zeroizing;

use super::{SecretInputPlan, select_secret_inputs};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Destination credential, never a portable literal or an instruction from source metadata.
pub enum SecretBindingInput {
    /// Explicit material retained only in zeroizing native runtime inputs.
    Value(Zeroizing<String>),
    /// Destination-owned reference, still unresolved by preparation.
    Source(SecretSource),
}

/// Native entries with immutable source-selection obligations. This does not authorize
/// activation, relax TLS identity policy, or verify captured placeholder/connection state.
pub struct SecretConfigurationPlan {
    config: SecretsConfig,
    selection: SecretInputPlan,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SecretConfigurationPlan {
    /// Retain shared source requirements, explicit approvals and full-state obligations.
    pub fn selection(&self) -> &SecretInputPlan {
        &self.selection
    }

    /// Apply the complete selected substitution configuration, without partially merging
    /// entries into a lower list. Unknown inventory refuses before destination mutation.
    pub fn apply_to(&self, destination: &mut SecretsConfig) -> MicrosandboxResult<()> {
        if self.selection.source_unknown {
            return Err(error(
                "SCFG_UNKNOWN",
                "substitution inventory needs resolution",
            ));
        }
        *destination = self.config.clone();
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for SecretBindingInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBindingInput([REDACTED])")
    }
}

impl fmt::Debug for SecretConfigurationPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretConfigurationPlan")
            .field("selection", &self.selection)
            .finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Prepare mode/clear-selected secrets after global binding-demand validation. Each
/// surviving substitution binding is immediate, including bindings shared with future exec.
/// Native credential sources remain references for the destination's normal resolver.
/// Neither the source record nor any portable representation receives supplied material.
pub fn prepare_secret_configuration(
    saved: Option<&SavedValue<SavedSecretsConfig>>,
    explicit: Option<&SecretsConfigPatch>,
    inputs: &BTreeMap<String, SecretBindingInput>,
    full_resume: bool,
) -> MicrosandboxResult<SecretConfigurationPlan> {
    let selection = select_secret_inputs(saved, explicit, full_resume)?;
    if inputs.len() > MAX_SAVED_CONFIG_ENTRIES {
        return Err(error("SCFG_LIMIT", "too many substitution binding inputs"));
    }
    if inputs
        .keys()
        .any(|id| !selection.remaining_bindings.contains_key(id))
        || selection
            .remaining_bindings
            .keys()
            .any(|id| !inputs.contains_key(id))
    {
        return Err(error(
            "SCFG_BINDING",
            "substitution binding inputs do not match requirements",
        ));
    }

    let mut config = SecretsConfig::default();
    selection.global_defaults.clone().apply_to(&mut config);
    // Native passthrough absence is meaningful. Do not revive policy from a lower layer.
    if selection.global_passthrough_absent {
        config.passthrough_hosts = None;
    }
    if let Some(explicit) = explicit {
        if let Some(hosts) = &explicit.passthrough_hosts {
            config.passthrough_hosts = Some(hosts.clone());
        }
        if let Some(action) = &explicit.violation_action {
            config.violation_action = action.clone();
        }
    }
    let mut expanded_bytes = 0usize;
    for entry in &selection.entries {
        // Check each expanded credential before cloning it, including repeated shared
        // bindings. Portable metadata limits do not bound supplied credential lengths.
        let prepared = if let Some(destination) = &entry.destination {
            account_credential(
                &mut expanded_bytes,
                &destination.value,
                destination.source.as_ref(),
            )?;
            destination.clone()
        } else {
            let source = entry.saved.as_ref().expect("selected entry has a source");
            let input = &inputs[&source.binding.id];
            let (value, reference) = match input {
                SecretBindingInput::Value(value) => {
                    account_credential(&mut expanded_bytes, value, None)?;
                    (value.clone(), None)
                }
                SecretBindingInput::Source(reference) => {
                    account_credential(&mut expanded_bytes, "", Some(reference))?;
                    (Zeroizing::new(String::new()), Some(reference.clone()))
                }
            };
            from_saved(source, value, reference)
        };
        config.secrets.push(prepared);
    }
    config
        .validate()
        .map_err(|_| error("SCFG_VALUE", "invalid substitution configuration"))?;
    Ok(SecretConfigurationPlan { config, selection })
}

fn from_saved(
    saved: &SavedSecret,
    value: Zeroizing<String>,
    source: Option<SecretSource>,
) -> SecretEntry {
    let SavedSecret {
        env_var,
        binding: _,
        placeholder,
        allowed_hosts,
        substitution,
        passthrough_hosts,
        violation_action,
        require_tls_identity,
    } = saved;
    SecretEntry {
        env_var: env_var.clone(),
        value,
        source,
        placeholder: placeholder.clone(),
        allowed_hosts: allowed_hosts.clone(),
        substitution: SecretSubstitution {
            headers: substitution.headers,
            header_fields: substitution.header_fields.clone(),
            query: substitution.query,
            body: substitution.body,
        },
        passthrough_hosts: passthrough_hosts.clone(),
        violation_action: violation_action.clone(),
        require_tls_identity: *require_tls_identity,
    }
}

fn account_credential(
    total: &mut usize,
    value: &str,
    source: Option<&SecretSource>,
) -> MicrosandboxResult<()> {
    account(total, value.as_bytes(), false)?;
    if let Some(source) = source {
        if !value.is_empty() {
            return Err(error(
                "SCFG_VALUE",
                "substitution input has both value and source",
            ));
        }
        let (SecretSource::Env { var } | SecretSource::Store { reference: var }) = source;
        account(total, var.as_bytes(), true)?;
    }
    Ok(())
}

fn account(total: &mut usize, bytes: &[u8], reference: bool) -> MicrosandboxResult<()> {
    if bytes.len() > MAX_SAVED_TEXT_BYTES || (reference && (bytes.is_empty() || bytes.contains(&0)))
    {
        return Err(error("SCFG_VALUE", "invalid substitution input"));
    }
    *total = total
        .checked_add(bytes.len())
        .ok_or_else(|| error("SCFG_LIMIT", "expanded substitution inputs are too large"))?;
    if *total > MAX_SAVED_CONFIG_BYTES {
        return Err(error(
            "SCFG_LIMIT",
            "expanded substitution inputs are too large",
        ));
    }
    Ok(())
}

fn error(code: &str, reason: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(format!("{code}: network.secrets: {reason}"))
}
