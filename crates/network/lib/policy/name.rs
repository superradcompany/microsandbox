//! Validated DNS name type used in [`super::Destination`] rules.
//!
//! Rules stored on a [`NetworkPolicy`] identify hosts by string, and
//! user input reaches the policy through several paths (programmatic
//! construction, JSON deserialization, CLI-supplied JSON). Each path
//! used to re-apply the same ad-hoc canonicalization (lowercase, trim
//! trailing dot, strip leading dot for suffixes) and it was easy to
//! miss — struct-literal construction, in particular, bypassed every
//! entry point and silently produced rules that never matched.
//!
//! [`DomainName`] closes that gap. The inner field is private and the
//! only way to build one is via [`str::parse`] (or serde, which routes
//! through the same parser), so the canonical form is a type-level
//! invariant rather than a convention. Matching code then collapses
//! to byte equality on the pre-canonicalized string.
//!
//! Validation is delegated to `hickory_proto::rr::Name`, which accepts
//! the real-world DNS label grammar (RFC 2181 §11) rather than the
//! stricter "preferred name syntax" of RFC 1035 §2.3.1 / RFC 1123
//! §2.1. That lets `_service._tcp.example.com`, DKIM selectors, and
//! similarly underscore-bearing names through, matching what the
//! sandbox's DNS interceptor will actually resolve on the wire.
//!
//! [`NetworkPolicy`]: super::NetworkPolicy

use std::fmt;
use std::str::FromStr;

use hickory_proto::ProtoError;
use hickory_proto::rr::Name;
use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Canonical DNS name used in network policy rules.
///
/// Constructed via `str::parse` or `TryFrom<String>`; both route through
/// the same validation and canonicalization. The inner form is
/// lowercased ASCII with no leading or trailing dots — the same form
/// the DNS interceptor stores on the resolved-hostname cache, which
/// lets match-time comparisons be byte-equal rather than
/// case-insensitive.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DomainName(String);

/// Errors reported when a string cannot be turned into a [`DomainName`].
#[derive(Debug, thiserror::Error)]
pub enum DomainNameError {
    /// Input was empty (or contained only dots).
    #[error("domain name is empty")]
    Empty,

    /// Input failed the DNS label grammar check (bad length, control
    /// chars, invalid UTF-8 for an ASCII name, etc.).
    #[error("invalid domain name: {0}")]
    Invalid(#[from] ProtoError),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DomainName {
    /// Borrow the canonical string form. The returned slice has no
    /// trailing dot and is lowercased ASCII.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for DomainName {
    type Err = DomainNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Leading-dot acceptance is ergonomic for suffixes
        // (`.example.com`). Trailing-dot acceptance matches FQDN
        // inputs coming from DNS responses or hand-typed FQDNs.
        let trimmed = s.trim_start_matches('.').trim_end_matches('.');
        if trimmed.is_empty() {
            return Err(DomainNameError::Empty);
        }
        // Validate via hickory. We discard the parsed Name and keep
        // the lowercased ASCII string so matching is a plain `==`
        // against the cache entries.
        let _name: Name = trimmed.parse()?;
        Ok(Self(trimmed.to_ascii_lowercase()))
    }
}

impl TryFrom<String> for DomainName {
    type Error = DomainNameError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<&str> for DomainName {
    type Error = DomainNameError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<DomainName> for String {
    fn from(name: DomainName) -> Self {
        name.0
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_lowercase_name() {
        let name: DomainName = "pypi.org".parse().unwrap();
        assert_eq!(name.as_str(), "pypi.org");
    }

    #[test]
    fn canonicalizes_case_and_trailing_dot() {
        let name: DomainName = "PyPI.Org.".parse().unwrap();
        assert_eq!(name.as_str(), "pypi.org");
    }

    #[test]
    fn strips_leading_dot_for_suffix_ergonomics() {
        let name: DomainName = ".pythonhosted.org".parse().unwrap();
        assert_eq!(name.as_str(), "pythonhosted.org");
    }

    #[test]
    fn canonical_form_is_idempotent() {
        let once: DomainName = "Example.COM.".parse().unwrap();
        let twice: DomainName = once.as_str().parse().unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn accepts_underscore_labels() {
        // SRV / DKIM / Kubernetes names rely on underscore labels
        // (RFC 2181 §11). Rejecting them would break real-world
        // policy inputs.
        let name: DomainName = "_http._tcp.example.com".parse().unwrap();
        assert_eq!(name.as_str(), "_http._tcp.example.com");
    }

    #[test]
    fn rejects_empty_input() {
        assert!(matches!(
            "".parse::<DomainName>(),
            Err(DomainNameError::Empty)
        ));
        assert!(matches!(
            "...".parse::<DomainName>(),
            Err(DomainNameError::Empty)
        ));
    }

    #[test]
    fn rejects_whitespace_in_labels() {
        assert!("foo bar.example".parse::<DomainName>().is_err());
    }

    #[test]
    fn serde_round_trip_preserves_canonical_form() {
        let name: DomainName = ".PyPI.Org.".parse().unwrap();
        let json = serde_json::to_string(&name).unwrap();
        assert_eq!(json, r#""pypi.org""#);
        let back: DomainName = serde_json::from_str(&json).unwrap();
        assert_eq!(back, name);
    }

    #[test]
    fn serde_deserialize_validates() {
        assert!(serde_json::from_str::<DomainName>(r#""foo bar.example""#).is_err());
        assert!(serde_json::from_str::<DomainName>(r#""""#).is_err());
    }
}
