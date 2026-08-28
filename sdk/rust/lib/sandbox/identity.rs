//! Stable sandbox identity exposed by lifecycle handles.

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// An opaque, backend-assigned identity for one persisted sandbox.
///
/// Names are reusable labels. This identity is stable for the lifetime of the
/// persisted sandbox and changes when a sandbox is removed and recreated with
/// the same name.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SandboxId(pub(crate) String);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SandboxId {
    pub(crate) fn local(db_id: i32) -> Self {
        Self(format!("local:{db_id}"))
    }

    pub(crate) fn cloud(id: &str) -> Self {
        Self(format!("cloud:{id}"))
    }

    /// Return the opaque identity as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Display for SandboxId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for SandboxId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
