//! Live-swappable view of the active secrets configuration.
//!
//! The proxy layers load the current [`SecretsConfig`] snapshot when they build a per-connection
//! [`SecretsHandler`](super::handler::SecretsHandler), so swapping the snapshot here makes
//! rotation, removal, and allowed-host updates take effect for all future guest connections
//! without restarting the sandbox. In-flight connections keep the snapshot they started with.

use std::sync::{Arc, RwLock};

use super::config::{HostPattern, SecretsConfig};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Shared handle to the secrets configuration consumed by the network stack.
///
/// Cloning is cheap; all clones observe the same swappable snapshot.
#[derive(Clone)]
pub struct SecretsHandle {
    inner: Arc<RwLock<Arc<SecretsConfig>>>,
}

/// A live secrets update that could not be applied.
///
/// Errors carry secret identities only, never values.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecretsUpdateError {
    /// No secret with this name exists in the active configuration.
    #[error("no secret named {name} is configured")]
    UnknownSecret {
        /// Secret identity (the guest environment variable name).
        name: String,
    },

    /// An allowed-host update would leave the secret with no allowed hosts.
    #[error("secret {name}: at least one allowed host is required")]
    MissingAllowedHosts {
        /// Secret identity (the guest environment variable name).
        name: String,
    },
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SecretsHandle {
    /// Create a handle over the boot-time secrets configuration.
    pub fn new(config: SecretsConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Arc::new(config))),
        }
    }

    /// Load the current snapshot.
    pub fn load(&self) -> Arc<SecretsConfig> {
        self.inner.read().expect("secrets lock poisoned").clone()
    }

    /// Replace the value of an existing secret. The guest-visible placeholder
    /// and host allow-list are unchanged.
    pub fn rotate_value(&self, name: &str, value: String) -> Result<(), SecretsUpdateError> {
        self.update(name, |entry| {
            entry.value = zeroize::Zeroizing::new(value);
        })
    }

    /// Stop resolving and injecting a secret for future connections. Removing
    /// an already-absent secret is a no-op: the goal state is reached.
    pub fn remove(&self, name: &str) {
        let mut guard = self.inner.write().expect("secrets lock poisoned");
        if !guard.entries.iter().any(|entry| entry.env_var == name) {
            return;
        }
        let mut config = (**guard).clone();
        config.entries.retain(|entry| entry.env_var != name);
        *guard = Arc::new(config);
    }

    /// Replace the allowed hosts of an existing secret.
    pub fn set_allowed_hosts(
        &self,
        name: &str,
        hosts: &[String],
    ) -> Result<(), SecretsUpdateError> {
        if hosts.is_empty() {
            return Err(SecretsUpdateError::MissingAllowedHosts {
                name: name.to_string(),
            });
        }
        let hosts: Vec<HostPattern> = hosts.iter().map(|host| HostPattern::parse(host)).collect();
        self.update(name, |entry| entry.allowed_hosts = hosts)
    }

    /// Swap in a new snapshot with `mutate` applied to the named secret.
    fn update(
        &self,
        name: &str,
        mutate: impl FnOnce(&mut super::config::SecretEntry),
    ) -> Result<(), SecretsUpdateError> {
        let mut guard = self.inner.write().expect("secrets lock poisoned");
        let mut config = (**guard).clone();
        let entry = config
            .entries
            .iter_mut()
            .find(|entry| entry.env_var == name)
            .ok_or_else(|| SecretsUpdateError::UnknownSecret {
                name: name.to_string(),
            })?;
        mutate(entry);
        *guard = Arc::new(config);
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::config::{SecretEntry, SecretInjection};
    use super::*;

    fn config_with_secret(name: &str, value: &str) -> SecretsConfig {
        SecretsConfig {
            entries: vec![SecretEntry {
                env_var: name.to_string(),
                value: zeroize::Zeroizing::new(value.to_string()),
                source: None,
                placeholder: format!("$MSB_{name}"),
                allowed_hosts: vec![HostPattern::Exact("api.example.com".into())],
                injection: SecretInjection::default(),
                on_violation: None,
                require_tls_identity: true,
            }],
            ..SecretsConfig::default()
        }
    }

    #[test]
    fn rotate_swaps_value_for_future_loads() {
        let handle = SecretsHandle::new(config_with_secret("API_KEY", "old"));
        let before = handle.load();

        handle.rotate_value("API_KEY", "new".into()).unwrap();

        // The pre-rotation snapshot is untouched; new loads see the new value.
        assert_eq!(before.entries[0].value.as_str(), "old");
        assert_eq!(handle.load().entries[0].value.as_str(), "new");
        assert_eq!(handle.load().entries[0].placeholder, "$MSB_API_KEY");
    }

    #[test]
    fn rotate_unknown_secret_is_an_error() {
        let handle = SecretsHandle::new(config_with_secret("API_KEY", "old"));

        assert_eq!(
            handle.rotate_value("MISSING", "new".into()),
            Err(SecretsUpdateError::UnknownSecret {
                name: "MISSING".into()
            })
        );
    }

    #[test]
    fn remove_drops_entry_and_is_idempotent() {
        let handle = SecretsHandle::new(config_with_secret("API_KEY", "old"));

        handle.remove("API_KEY");
        handle.remove("API_KEY");

        assert!(handle.load().entries.is_empty());
    }

    #[test]
    fn set_allowed_hosts_replaces_patterns() {
        let handle = SecretsHandle::new(config_with_secret("API_KEY", "old"));

        handle
            .set_allowed_hosts("API_KEY", &["*.example.org".into(), "one.test".into()])
            .unwrap();

        assert_eq!(
            handle.load().entries[0].allowed_hosts,
            vec![
                HostPattern::Wildcard("*.example.org".into()),
                HostPattern::Exact("one.test".into()),
            ]
        );
    }

    #[test]
    fn set_allowed_hosts_rejects_empty_list() {
        let handle = SecretsHandle::new(config_with_secret("API_KEY", "old"));

        assert_eq!(
            handle.set_allowed_hosts("API_KEY", &[]),
            Err(SecretsUpdateError::MissingAllowedHosts {
                name: "API_KEY".into()
            })
        );
        assert_eq!(handle.load().entries[0].allowed_hosts.len(), 1);
    }
}
