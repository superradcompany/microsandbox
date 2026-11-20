//! Opaque identity for a persisted volume, independent of its reusable name.

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A backend-assigned identity. Removing and recreating a name produces a new identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VolumeId(String);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl VolumeId {
    #[cfg(feature = "local")]
    pub(crate) fn local(id: i32) -> Self {
        Self(format!("local:{id}"))
    }

    #[cfg(feature = "cloud")]
    pub(crate) fn remote(id: &str) -> Self {
        Self(format!("remote:{id}"))
    }

    /// Borrow the opaque identity string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Display for VolumeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl AsRef<str> for VolumeId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Internal local dispatch target. It is never serialized into configuration or sent to a VM.
#[cfg(feature = "local")]
pub(super) fn local_target(target: &str) -> crate::MicrosandboxResult<(&str, Option<i32>)> {
    let Some(bound) = target.strip_prefix("local-id:") else {
        return Ok((target, None));
    };
    let (id, name) = bound.split_once(':').ok_or_else(|| {
        crate::MicrosandboxError::InvalidConfig("invalid volume identity target".into())
    })?;
    let id = id.parse::<i32>().ok().filter(|id| *id > 0).ok_or_else(|| {
        crate::MicrosandboxError::InvalidConfig("invalid local volume identity".into())
    })?;
    Ok((name, Some(id)))
}
