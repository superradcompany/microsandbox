//! Bypass list matching for TLS interception.
//!
//! Connections to bypassed domains are spliced directly to the real server
//! without TLS termination. The guest's TLS session reaches the real server
//! unmodified.

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Matches domain names against a bypass list to decide whether to intercept
/// or pass through a TLS connection.
pub struct BypassMatcher {
    entries: Vec<BypassEntry>,
}

/// A single bypass entry: either an exact domain or a suffix wildcard.
enum BypassEntry {
    /// Exact domain match (case-insensitive).
    Exact(String),

    /// Suffix match: `*.example.com` matches `foo.example.com` and
    /// `bar.baz.example.com` but not `example.com` itself.
    Suffix(String),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl BypassMatcher {
    /// Creates a new bypass matcher from a list of patterns.
    ///
    /// Patterns starting with `*.` are treated as suffix matches. All other
    /// patterns are exact matches. Matching is case-insensitive.
    pub fn new(patterns: &[String]) -> Self {
        let entries = patterns
            .iter()
            .map(|p| {
                if let Some(suffix) = p.strip_prefix("*.") {
                    BypassEntry::Suffix(suffix.to_ascii_lowercase())
                } else {
                    BypassEntry::Exact(p.to_ascii_lowercase())
                }
            })
            .collect();

        Self { entries }
    }

    /// Returns `true` if the given SNI domain should bypass TLS interception.
    pub fn is_bypassed(&self, sni: &str) -> bool {
        let lower = sni.to_ascii_lowercase();
        self.entries.iter().any(|entry| match entry {
            BypassEntry::Exact(domain) => lower == *domain,
            BypassEntry::Suffix(suffix) => {
                lower.ends_with(suffix) && lower.len() > suffix.len() && {
                    // Ensure the character before the suffix is a dot.
                    let prefix_len = lower.len() - suffix.len();
                    lower.as_bytes()[prefix_len - 1] == b'.'
                }
            }
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let matcher = BypassMatcher::new(&["example.com".to_string()]);
        assert!(matcher.is_bypassed("example.com"));
        assert!(matcher.is_bypassed("EXAMPLE.COM"));
        assert!(!matcher.is_bypassed("foo.example.com"));
        assert!(!matcher.is_bypassed("notexample.com"));
    }

    #[test]
    fn test_suffix_match() {
        let matcher = BypassMatcher::new(&["*.pinned.com".to_string()]);
        assert!(matcher.is_bypassed("foo.pinned.com"));
        assert!(matcher.is_bypassed("bar.baz.pinned.com"));
        assert!(matcher.is_bypassed("FOO.PINNED.COM"));
        assert!(!matcher.is_bypassed("pinned.com"));
        assert!(!matcher.is_bypassed("notpinned.com"));
    }

    #[test]
    fn test_no_match() {
        let matcher = BypassMatcher::new(&["example.com".to_string(), "*.pinned.com".to_string()]);
        assert!(!matcher.is_bypassed("other.com"));
        assert!(!matcher.is_bypassed("evil.net"));
    }

    #[test]
    fn test_empty_list() {
        let matcher = BypassMatcher::new(&[]);
        assert!(!matcher.is_bypassed("anything.com"));
    }

    #[test]
    fn test_multiple_patterns() {
        let matcher = BypassMatcher::new(&[
            "exact.com".to_string(),
            "*.wildcard.org".to_string(),
            "another.net".to_string(),
        ]);
        assert!(matcher.is_bypassed("exact.com"));
        assert!(matcher.is_bypassed("sub.wildcard.org"));
        assert!(matcher.is_bypassed("another.net"));
        assert!(!matcher.is_bypassed("wildcard.org"));
    }
}
