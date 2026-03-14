//! OCI content-addressable digest type.

use std::{fmt, str::FromStr};

use crate::error::ImageError;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// OCI content-addressable digest (e.g., `sha256:e3b0c44298fc1c14...`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Digest {
    /// Hash algorithm (e.g., `sha256`).
    algorithm: String,
    /// Hex-encoded hash value.
    hex: String,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Digest {
    /// Create a new digest from algorithm and hex components.
    pub fn new(algorithm: impl Into<String>, hex: impl Into<String>) -> Self {
        Self {
            algorithm: algorithm.into(),
            hex: hex.into(),
        }
    }

    /// Hash algorithm (e.g., `sha256`).
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Hex-encoded hash value.
    pub fn hex(&self) -> &str {
        &self.hex
    }

    /// Filesystem-safe representation for use in paths.
    ///
    /// Replaces `:` with `_` (e.g., `sha256_abc123...`).
    pub fn to_path_safe(&self) -> String {
        format!("{}_{}", self.algorithm, self.hex)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl FromStr for Digest {
    type Err = ImageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (algo, hex) = s.split_once(':').ok_or_else(|| {
            ImageError::ManifestParse(format!("invalid digest (missing ':'): {s}"))
        })?;

        if algo.is_empty() || hex.is_empty() {
            return Err(ImageError::ManifestParse(format!(
                "invalid digest (empty component): {s}"
            )));
        }

        Ok(Self {
            algorithm: algo.to_string(),
            hex: hex.to_string(),
        })
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm, self.hex)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_digest() {
        let d: Digest = "sha256:abc123".parse().unwrap();
        assert_eq!(d.algorithm(), "sha256");
        assert_eq!(d.hex(), "abc123");
    }

    #[test]
    fn test_display() {
        let d = Digest::new("sha256", "abc123");
        assert_eq!(d.to_string(), "sha256:abc123");
    }

    #[test]
    fn test_path_safe() {
        let d = Digest::new("sha256", "abc123");
        assert_eq!(d.to_path_safe(), "sha256_abc123");
    }

    #[test]
    fn test_parse_missing_colon() {
        assert!("sha256abc123".parse::<Digest>().is_err());
    }

    #[test]
    fn test_parse_empty_components() {
        assert!(":abc123".parse::<Digest>().is_err());
        assert!("sha256:".parse::<Digest>().is_err());
    }
}
