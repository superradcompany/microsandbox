//! Borrow the sandbox's retained destination without I/O or allocation.

use super::Sandbox;
use crate::Context;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// The destination retained by this resource. This performs no backend I/O.
    pub fn context(&self) -> &dyn Context {
        self.backend.as_ref()
    }
}
