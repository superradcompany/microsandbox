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

/// Validate a single bind-mount `hide_path` pattern for the mount wire format.
///
/// Patterns are rendered as `hide-path=<pattern>` inside a comma-joined option block
/// that is colon-split from the host path, so a `,`, `:`, newline, or NUL would
/// fail the parse or silently attenuate other mount options. Leading or
/// trailing whitespace is rejected because option tokens are trimmed, which
/// would reinterpret a value like `" !secret"` as the allow rule `!secret`.
///
/// Shared by the Rust SDK, the Go native binding, and the runtime so a pattern
/// accepted by one layer is accepted by all of them.
pub fn validate_hide_path_pattern(pattern: &str) -> TypesResult<()> {
    if pattern.is_empty() {
        return Err(TypesError::invalid_config(
            "hide-path pattern must not be empty",
        ));
    }

    // gitignore treats a leading `#` as a comment, so the rule would be silently
    // dropped and enforce nothing. A literal leading `#` must be escaped (`\#`).
    if pattern.starts_with('#') {
        return Err(TypesError::invalid_config(format!(
            "hide-path pattern must not start with '#' (gitignore treats it as a comment; \
             escape a literal '#' as '\\#'): {pattern:?}"
        )));
    }

    if pattern.contains(',')
        || pattern.contains(':')
        || pattern.contains('\n')
        || pattern.contains('\0')
    {
        return Err(TypesError::invalid_config(format!(
            "hide-path pattern must not contain ',', ':', newline, or NUL: {pattern:?}"
        )));
    }

    if pattern.trim() != pattern {
        return Err(TypesError::invalid_config(format!(
            "hide-path pattern must not have leading or trailing whitespace: {pattern:?}"
        )));
    }

    // `.` and `..` name the current and parent directory. gitignore cannot
    // express either as a rule, so the pattern would compile to an empty
    // matcher and enforce nothing.
    if pattern == "." || pattern == ".." {
        return Err(TypesError::invalid_config(format!(
            "hide-path pattern must not be '.' or '..'; hide_path a named entry instead \
             (e.g. 'secret' or 'secret/'), not the current or parent directory: {pattern:?}"
        )));
    }

    // A leading `//` (including a leading `/` immediately followed by another
    // `/`) is not a rooted path in gitignore and would compile to nothing.
    if pattern.starts_with("//") {
        return Err(TypesError::invalid_config(format!(
            "hide-path pattern must not start with '//'; write a mount-relative path \
             with a single separator (e.g. 'a/b') or a name pattern (e.g. 'secret'): {pattern:?}"
        )));
    }

    // A leading `./` is a no-op path prefix in gitignore, so the rule would be
    // silently dropped.
    if pattern.starts_with("./") {
        return Err(TypesError::invalid_config(format!(
            "hide-path pattern must not start with './'; write the mount-relative path \
             directly (e.g. 'secret' or 'sub/secret'): {pattern:?}"
        )));
    }

    // A bare `!` is a negation with nothing to negate, so it compiles to an
    // empty matcher. `!name` (an allow rule) stays valid.
    if pattern == "!" {
        return Err(TypesError::invalid_config(format!(
            "hide-path pattern must not be a bare '!'; a negation needs a rule to negate \
             (e.g. '!keep.txt'): {pattern:?}"
        )));
    }

    // Repeated `/` creates an empty path component (e.g. `a//b`, `foo//`), which
    // gitignore does not match, so the rule would enforce nothing.
    if pattern.contains("//") {
        return Err(TypesError::invalid_config(format!(
            "hide-path pattern must not contain repeated '/'; use a single separator \
             between path components (e.g. 'a/b', 'foo/'): {pattern:?}"
        )));
    }

    // A `.` or `..` path component is never present in a reconstructed
    // mount-relative path, so a pattern like `a/./b` or `../secret` would match
    // only its literal spelling and be a silent no-op. Only exact components are
    // rejected; dot-prefixed names (`.env`, `..foo`, `...`) stay valid.
    if pattern
        .split('/')
        .any(|component| component == "." || component == "..")
    {
        return Err(TypesError::invalid_config(format!(
            "hide-path pattern must not contain a '.' or '..' path component; path components \
             are matched literally and never contain '.' or '..', so the rule would be a \
             no-op; use a real path or name pattern (e.g. 'a/b', 'secret'): {pattern:?}"
        )));
    }

    Ok(())
}

/// Reject path hide-path patterns (`sub/.env`, `**/env.secret`) on a writable mount.
///
/// A path pattern is matched against the entry's reconstructed mount-relative
/// path, so a guest with a writable mount can rename an ancestor directory and
/// make the denied path stop matching. Name-only (`.env`) and directory-only
/// (`node_modules/`) patterns match anywhere and stay valid, and a read-only
/// mount cannot rename, so path patterns remain valid there.
pub fn reject_writable_path_patterns(patterns: &[String]) -> TypesResult<()> {
    if let Some(pattern) = patterns
        .iter()
        .find(|pattern| pattern.trim_end_matches('/').contains('/'))
    {
        return Err(TypesError::invalid_config(format!(
            "hide-path pattern {pattern:?} is a path pattern, which a writable mount can bypass by \
             renaming an ancestor directory; use a name-only pattern, or mark the mount read-only"
        )));
    }

    Ok(())
}

/// Validate a bind-mount `hide_path` list.
///
/// Every pattern must be wire-safe, and a writable mount (`readonly` false) must
/// not carry a path pattern. An empty list is always valid.
pub fn validate_hide_path_list(patterns: &[String], readonly: bool) -> TypesResult<()> {
    for pattern in patterns {
        validate_hide_path_pattern(pattern)?;
    }

    if !readonly {
        reject_writable_path_patterns(patterns)?;
    }

    Ok(())
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

    #[test]
    fn hide_path_pattern_rejects_wire_and_whitespace_hazards() {
        assert_eq!(
            validate_hide_path_pattern("").unwrap_err().to_string(),
            "invalid config: hide-path pattern must not be empty"
        );
        for bad in ["a,b", "a:b", "a\nb", "a\0b"] {
            assert!(
                validate_hide_path_pattern(bad)
                    .unwrap_err()
                    .to_string()
                    .contains("must not contain"),
                "{bad:?}"
            );
        }
        for bad in [" .env", ".env ", "\tsecret"] {
            assert!(
                validate_hide_path_pattern(bad)
                    .unwrap_err()
                    .to_string()
                    .contains("leading or trailing whitespace"),
                "{bad:?}"
            );
        }
        validate_hide_path_pattern(".env").unwrap();
        validate_hide_path_pattern("sub/secret").unwrap();
    }

    #[test]
    fn hide_path_pattern_rejects_gitignore_comment_prefix() {
        // A leading `#` is a gitignore comment, so such a rule would be accepted
        // and then enforce nothing — a silent security no-op.
        let err = validate_hide_path_pattern("#secret")
            .unwrap_err()
            .to_string();
        assert!(err.contains("must not start with '#'"), "{err}");

        // Escaping stays available for a literal leading `#`.
        validate_hide_path_pattern("\\#secret").unwrap();

        // `!` is still valid: it drives allowlist negation alongside a `*` rule.
        validate_hide_path_pattern("!keep.txt").unwrap();
    }

    #[test]
    fn rejects_non_canonical_patterns() {
        for bad in [
            "./secret",
            "//secret",
            "a//b",
            "!",
            ".",
            "..",
            "foo//",
            "a/./b",
            "a/../b",
            "../secret",
            "./a",
        ] {
            assert!(validate_hide_path_pattern(bad).is_err(), "{bad:?}");
        }
        for ok in [
            ".env",
            "sub/.env",
            "**/env.secret",
            "node_modules/",
            "\\#x",
            "!keep.txt",
            "..foo",
            "...",
            "a/..foo/b",
        ] {
            validate_hide_path_pattern(ok).unwrap();
        }
    }

    #[test]
    fn non_canonical_patterns_have_distinct_actionable_messages() {
        let message = |bad: &str| validate_hide_path_pattern(bad).unwrap_err().to_string();

        // Each rejected form names the exact mistake; `.`/`..` share the
        // directory rule but every form points at the fix.
        assert!(message("./secret").contains("must not start with './'"));
        assert!(message("//secret").contains("must not start with '//'"));
        assert!(message("a//b").contains("must not contain repeated '/'"));
        assert!(message("foo//").contains("must not contain repeated '/'"));
        assert!(message("!").contains("must not be a bare '!'"));
        assert!(message(".").contains("must not be '.' or '..'"));
        assert!(message("..").contains("must not be '.' or '..'"));
        assert!(message("a/./b").contains("must not contain a '.' or '..' path component"));
        assert!(message("a/../b").contains("must not contain a '.' or '..' path component"));
        assert!(message("../secret").contains("must not contain a '.' or '..' path component"));

        // The five independent forms carry five distinct reasons.
        let reasons = ["./secret", "//secret", "a//b", "!", "a/./b"].map(message);
        let unique: std::collections::BTreeSet<&String> = reasons.iter().collect();
        assert_eq!(unique.len(), 5, "expected distinct messages: {reasons:?}");
    }

    #[test]
    fn hide_path_list_rejects_path_pattern_on_writable_mount_only() {
        let path_pattern = vec!["sub/.env".to_string()];
        assert!(validate_hide_path_list(&path_pattern, false).is_err());
        validate_hide_path_list(&path_pattern, true).unwrap();

        let name_only = vec![".env".to_string(), "node_modules/".to_string()];
        validate_hide_path_list(&name_only, false).unwrap();
        validate_hide_path_list(&[], false).unwrap();
    }
}
