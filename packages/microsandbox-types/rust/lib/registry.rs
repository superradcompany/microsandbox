//! Registry authentication contracts shared by local and cloud clients.

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Authentication credentials for OCI registry access.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum RegistryAuth {
    /// No authentication. Works for public registries.
    #[default]
    Anonymous,
    /// Username and password or token authentication.
    Basic {
        /// Registry username.
        username: String,
        /// Registry password or token.
        password: String,
    },
}
