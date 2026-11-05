//! Live-swappable view of the sandbox's network policy.
//!
//! The poll loop and the proxy layers load the current [`NetworkPolicy`] snapshot whenever they
//! evaluate a new flow, so a policy set here decides the next connection, datagram, and DNS query
//! without restarting the sandbox.

use std::sync::{Arc, RwLock};

use crate::policy::NetworkPolicy;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Shared handle to the network policy enforced for a running sandbox.
///
/// Cloning is cheap; all clones observe the same swappable snapshot.
#[derive(Clone)]
pub struct PolicyHandle {
    inner: Arc<RwLock<Arc<NetworkPolicy>>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PolicyHandle {
    /// Create a handle over the boot-time policy.
    pub fn new(policy: NetworkPolicy) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Arc::new(policy))),
        }
    }

    /// Load the current snapshot.
    pub fn load(&self) -> Arc<NetworkPolicy> {
        self.inner.read().expect("policy lock poisoned").clone()
    }

    /// Replace the policy for every flow evaluated from now on.
    pub fn set(&self, policy: NetworkPolicy) {
        *self.inner.write().expect("policy lock poisoned") = Arc::new(policy);
    }
}
