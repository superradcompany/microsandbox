//! Registry authentication.

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Authentication credentials for OCI registry access.
///
/// Resolution chain (in [`Registry`](crate::Registry)):
/// 1. Explicit [`RegistryAuth`] via [`RegistryBuilder::auth()`](crate::RegistryBuilder::auth)
/// 2. OS keyring / credential store (when configured by the caller)
/// 3. Global config `registries.auth` (`store`, `password_env`, or `secret_name`)
/// 4. Docker credential store/config fallback (when enabled by the caller)
/// 5. [`Anonymous`](Self::Anonymous) fallback
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum RegistryAuth {
    /// No authentication. Works for public registries.
    #[default]
    Anonymous,

    /// Username + password authentication.
    Basic {
        /// Registry username.
        username: String,
        /// Registry password or token.
        password: String,
    },
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<&RegistryAuth> for oci_client::secrets::RegistryAuth {
    fn from(auth: &RegistryAuth) -> Self {
        match auth {
            RegistryAuth::Anonymous => oci_client::secrets::RegistryAuth::Anonymous,
            RegistryAuth::Basic { username, password } => {
                oci_client::secrets::RegistryAuth::Basic(username.clone(), password.clone())
            }
        }
    }
}
