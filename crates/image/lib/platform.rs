//! Target platform for OCI image resolution.

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Target platform for OCI image resolution.
///
/// Used to select the correct manifest from a multi-platform OCI index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    /// Operating system (always `linux` for microsandbox).
    pub os: String,
    /// CPU architecture (e.g., `amd64`, `arm64`).
    pub arch: String,
    /// Optional architecture variant (e.g., `v7` for armv7).
    pub variant: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Platform {
    /// Create a new platform.
    pub fn new(os: impl Into<String>, arch: impl Into<String>) -> Self {
        Self {
            os: os.into(),
            arch: arch.into(),
            variant: None,
        }
    }

    /// Create a new platform with variant.
    pub fn with_variant(
        os: impl Into<String>,
        arch: impl Into<String>,
        variant: impl Into<String>,
    ) -> Self {
        Self {
            os: os.into(),
            arch: arch.into(),
            variant: Some(variant.into()),
        }
    }

    /// Returns the platform for the current host, with OS forced to `linux`.
    ///
    /// Architecture detected via `std::env::consts::ARCH`:
    /// `x86_64` -> `amd64`, `aarch64` -> `arm64`.
    pub fn host_linux() -> Self {
        let arch = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            other => other,
        };
        Self::new("linux", arch)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for Platform {
    fn default() -> Self {
        Self::host_linux()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_linux() {
        let p = Platform::host_linux();
        assert_eq!(p.os, "linux");
        assert!(p.arch == "amd64" || p.arch == "arm64" || !p.arch.is_empty());
    }

    #[test]
    fn test_default_is_host_linux() {
        let p = Platform::default();
        assert_eq!(p.os, "linux");
    }
}
