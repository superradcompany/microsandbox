//! Explicit safe projection of typed secret policy. Never serialize the live source object.

use std::collections::BTreeMap;

use crate::{SecretEntry, SecretSubstitution, SecretsConfig, SnapshotManifestResult};

use super::network::{
    SavedBindingReference, SavedSecret, SavedSecretSubstitution, SavedSecretsConfig,
};
use super::network_validation::validate_secrets;
use super::validation::{count, encoded_size, invalid};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SavedSecretsConfig {
    /// Project placeholder policy with an explicit destination requirement for every secret.
    ///
    /// This never copies resolved values or host-side source references. Binding IDs
    /// are selected by capture policy; missing or misspelled mappings fail instead of
    /// exporting credentials or producing silently incomplete substitution policy.
    pub fn from_source(
        source: &SecretsConfig,
        bindings: &BTreeMap<String, SavedBindingReference>,
    ) -> SnapshotManifestResult<Self> {
        // Exhaustive destructuring makes newly introduced source fields require an
        // explicit portability decision rather than inheriting a generic serializer.
        let SecretsConfig {
            passthrough_hosts,
            secrets,
            violation_action,
        } = source;
        count(secrets.len(), "active.network.secrets.entries")?;
        if bindings.len() != secrets.len() {
            return invalid(
                "SCFG_BINDING",
                "active.network.secrets",
                "each secret needs exactly one destination binding",
            );
        }
        let mut entries = Vec::with_capacity(secrets.len());
        for (index, source) in secrets.iter().enumerate() {
            let SecretEntry {
                env_var,
                value: _,
                source: _,
                placeholder,
                allowed_hosts,
                substitution,
                passthrough_hosts,
                violation_action,
                require_tls_identity,
            } = source;
            let Some(binding) = bindings.get(env_var) else {
                return invalid(
                    "SCFG_BINDING",
                    &format!("active.network.secrets.entries[{index}].binding"),
                    "missing destination secret requirement",
                );
            };
            let SecretSubstitution {
                headers,
                header_fields,
                query,
                body,
            } = substitution;
            entries.push(SavedSecret {
                env_var: env_var.clone(),
                binding: binding.clone(),
                placeholder: placeholder.clone(),
                allowed_hosts: allowed_hosts.clone(),
                substitution: SavedSecretSubstitution {
                    headers: *headers,
                    header_fields: header_fields.clone(),
                    query: *query,
                    body: *body,
                },
                passthrough_hosts: passthrough_hosts.clone(),
                violation_action: violation_action.clone(),
                require_tls_identity: *require_tls_identity,
            });
        }
        let result = Self {
            passthrough_hosts: passthrough_hosts.clone(),
            entries,
            violation_action: violation_action.clone(),
        };
        encoded_size(&result, "active.network.secrets")?;
        validate_secrets(&result)?;
        Ok(result)
    }
}
