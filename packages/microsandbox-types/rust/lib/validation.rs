//! Shared validation rules for sandbox task descriptors.

use crate::{TypesError, TypesResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum UTF-8 byte length for a sandbox name.
pub const MAX_SANDBOX_NAME_BYTES: usize = 128;

/// Maximum UTF-8 byte length for a guest hostname (Linux `__NEW_UTS_LEN`).
pub const MAX_HOSTNAME_BYTES: usize = 64;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Validate that a sandbox name is safe: alphanumeric / dot / hyphen / underscore, 1..=128 bytes, and must start alphanumeric.
pub fn validate_sandbox_name(name: &str) -> TypesResult<()> {
    if name.is_empty() {
        return Err(TypesError::invalid_config("sandbox name must not be empty"));
    }

    if name.len() > MAX_SANDBOX_NAME_BYTES {
        return Err(TypesError::invalid_config(format!(
            "sandbox name must be at most {MAX_SANDBOX_NAME_BYTES} characters: got {}",
            name.len()
        )));
    }

    let first_alphanumeric = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric());
    let charset_ok = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_');

    if !first_alphanumeric || !charset_ok {
        return Err(TypesError::invalid_config(format!(
            "sandbox name must start with an alphanumeric and contain only \
             alphanumeric, dots, hyphens, and underscores: {name}"
        )));
    }

    Ok(())
}

/// Validate an optional explicit guest hostname before it is forwarded to the guest agent.
pub fn validate_hostname(hostname: Option<&str>) -> TypesResult<()> {
    let Some(hostname) = hostname else {
        return Ok(());
    };

    if hostname.is_empty() {
        return Err(TypesError::invalid_config("hostname must not be empty"));
    }

    let len = hostname.len();
    if len > MAX_HOSTNAME_BYTES {
        return Err(TypesError::invalid_config(format!(
            "hostname is too long: {len} bytes (max {MAX_HOSTNAME_BYTES})"
        )));
    }

    Ok(())
}

/// Derive a guest hostname from a sandbox name while fitting within [`MAX_HOSTNAME_BYTES`].
pub fn hostname_from_sandbox_name(name: &str) -> String {
    if name.len() <= MAX_HOSTNAME_BYTES {
        return name.to_string();
    }

    // 55-byte prefix + '-' + 8 hex chars of sha256 = 64 bytes.
    const HASH_HEX_LEN: usize = 8;
    const PREFIX_MAX: usize = MAX_HOSTNAME_BYTES - 1 - HASH_HEX_LEN;

    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(name.as_bytes());
    let digest = hasher.finalize();
    let suffix = format!(
        "{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3]
    );

    let mut end = PREFIX_MAX;
    while end > 0 && !name.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}-{}", &name[..end], suffix)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_name_accepts_typical() {
        for name in [
            "foo",
            "foo-bar",
            "foo.bar",
            "foo_bar",
            "FooBar",
            "abc123",
            "a",
            "0",
            "agent-1",
            "my.app_2026",
        ] {
            assert!(
                validate_sandbox_name(name).is_ok(),
                "expected {name:?} to be accepted"
            );
        }
    }

    #[test]
    fn sandbox_name_rejects_empty() {
        assert_eq!(
            validate_sandbox_name("").unwrap_err().to_string(),
            "invalid config: sandbox name must not be empty"
        );
    }

    #[test]
    fn sandbox_name_rejects_too_long() {
        let long = "a".repeat(MAX_SANDBOX_NAME_BYTES + 1);
        assert_eq!(
            validate_sandbox_name(&long).unwrap_err().to_string(),
            "invalid config: sandbox name must be at most 128 characters: got 129"
        );
    }

    #[test]
    fn sandbox_name_accepts_at_max_length() {
        let max = "a".repeat(MAX_SANDBOX_NAME_BYTES);
        assert!(validate_sandbox_name(&max).is_ok());
    }

    #[test]
    fn sandbox_name_rejects_disallowed_chars() {
        for name in [
            "foo bar", "foo/bar", "foo:bar", "foo!", "foo@bar", "foo#1", "✨",
        ] {
            assert!(
                validate_sandbox_name(name).is_err(),
                "expected {name:?} to be rejected"
            );
        }
    }

    #[test]
    fn sandbox_name_rejects_non_alphanumeric_start() {
        for name in [".foo", "-foo", "_foo"] {
            assert!(
                validate_sandbox_name(name).is_err(),
                "expected {name:?} to be rejected (non-alphanumeric start)"
            );
        }
    }

    #[test]
    fn hostname_from_sandbox_name_passes_short_names_through() {
        let name = "short-name";
        assert_eq!(hostname_from_sandbox_name(name), name);

        let name = "a".repeat(MAX_HOSTNAME_BYTES);
        assert_eq!(hostname_from_sandbox_name(&name), name);
    }

    #[test]
    fn hostname_from_sandbox_name_collapses_long_names_to_64_bytes() {
        let derived = hostname_from_sandbox_name(&"a".repeat(MAX_HOSTNAME_BYTES + 1));
        assert_eq!(derived.len(), MAX_HOSTNAME_BYTES);

        let derived = hostname_from_sandbox_name(&"a".repeat(MAX_SANDBOX_NAME_BYTES));
        assert_eq!(derived.len(), MAX_HOSTNAME_BYTES);

        let bytes = derived.as_bytes();
        assert_eq!(bytes[MAX_HOSTNAME_BYTES - 9], b'-');
        assert!(
            bytes[MAX_HOSTNAME_BYTES - 8..]
                .iter()
                .all(u8::is_ascii_hexdigit)
        );
    }

    #[test]
    fn hostname_from_sandbox_name_is_deterministic_and_unique() {
        let a = "a".repeat(MAX_SANDBOX_NAME_BYTES);
        let mut b = a.clone();
        b.pop();
        b.push('b');

        assert_eq!(
            hostname_from_sandbox_name(&a),
            hostname_from_sandbox_name(&a)
        );
        assert_ne!(
            hostname_from_sandbox_name(&a),
            hostname_from_sandbox_name(&b)
        );
    }

    #[test]
    fn hostname_from_sandbox_name_respects_utf8_boundaries() {
        let name = "é".repeat(64);
        assert_eq!(name.len(), 128);

        let derived = hostname_from_sandbox_name(&name);
        assert!(derived.len() <= MAX_HOSTNAME_BYTES);
        assert!(derived.is_char_boundary(derived.len()));
    }

    #[test]
    fn validate_hostname_accepts_absent_and_64_byte_hostname() {
        validate_hostname(None).unwrap();
        validate_hostname(Some(&"y".repeat(MAX_HOSTNAME_BYTES))).unwrap();
    }

    #[test]
    fn validate_hostname_rejects_empty_hostname() {
        assert_eq!(
            validate_hostname(Some("")).unwrap_err().to_string(),
            "invalid config: hostname must not be empty"
        );
    }

    #[test]
    fn validate_hostname_rejects_over_64_byte_hostname() {
        assert_eq!(
            validate_hostname(Some(&"y".repeat(MAX_HOSTNAME_BYTES + 1)))
                .unwrap_err()
                .to_string(),
            "invalid config: hostname is too long: 65 bytes (max 64)"
        );
    }
}
