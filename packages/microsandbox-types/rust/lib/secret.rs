//! Redacting, zeroizing wrapper for secret material.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Secret material that is redacted in diagnostics and cleared on drop.
///
/// Wrapped so any `Debug`-formatted request or error path shows `[redacted]`
/// instead of the value, and zeroized on drop so the plaintext does not linger
/// in freed memory.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SecretValue(pub String);

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let value = SecretValue("sentinel-secret-value".into());

        let debug = format!("{value:?}");

        assert_eq!(debug, "[redacted]");
        assert!(!debug.contains("sentinel-secret-value"));
    }

    #[test]
    fn serde_form_is_a_plain_json_string() {
        let value = SecretValue("x".into());

        let json = serde_json::to_string(&value).unwrap();
        let parsed: SecretValue = serde_json::from_str(&json).unwrap();

        assert_eq!(json, "\"x\"");
        assert_eq!(parsed.0, "x");
    }

    #[test]
    fn zeroize_clears_the_value() {
        fn requires_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        requires_zeroize_on_drop::<SecretValue>();

        let mut value = SecretValue("sentinel-secret-value".into());

        value.zeroize();

        assert!(value.0.is_empty());
    }
}
