//! Secret substitution handler for the TLS proxy.
//!
//! Scans decrypted plaintext for placeholder strings and replaces them
//! with real secret values, but only when the destination host is allowed.

use std::borrow::Cow;

use super::config::{SecretsConfig, ViolationAction};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Handles secret placeholder substitution in TLS-intercepted plaintext.
///
/// Created from [`SecretsConfig`] and the destination SNI. Determines which
/// secrets are eligible for this connection based on host matching.
pub struct SecretsHandler {
    /// Secrets eligible for substitution on this connection.
    eligible: Vec<EligibleSecret>,
    /// All placeholder strings (for violation detection on disallowed hosts).
    all_placeholders: Vec<String>,
    /// Violation action.
    on_violation: ViolationAction,
    /// Whether any ineligible secrets exist (pre-computed for fast-path skip).
    has_ineligible: bool,
    /// Whether this connection is TLS-intercepted (not bypass).
    tls_intercepted: bool,
}

/// A secret that passed host matching for this connection.
struct EligibleSecret {
    placeholder: String,
    value: String,
    inject_headers: bool,
    inject_basic_auth: bool,
    inject_query_params: bool,
    inject_body: bool,
    require_tls_identity: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SecretsHandler {
    /// Create a handler for a specific connection.
    ///
    /// Filters secrets by host matching against the SNI. Only secrets
    /// whose `allowed_hosts` match `sni` will be substituted.
    /// `tls_intercepted` indicates whether this is a MITM connection
    /// (true) or a bypass/plain connection (false).
    pub fn new(config: &SecretsConfig, sni: &str, tls_intercepted: bool) -> Self {
        let mut eligible = Vec::new();
        let mut all_placeholders = Vec::new();

        for secret in &config.secrets {
            all_placeholders.push(secret.placeholder.clone());

            let host_allowed = secret.allowed_hosts.is_empty()
                || secret.allowed_hosts.iter().any(|p| p.matches(sni));

            if host_allowed {
                eligible.push(EligibleSecret {
                    placeholder: secret.placeholder.clone(),
                    value: secret.value.clone(),
                    inject_headers: secret.injection.headers,
                    inject_basic_auth: secret.injection.basic_auth,
                    inject_query_params: secret.injection.query_params,
                    inject_body: secret.injection.body,
                    require_tls_identity: secret.require_tls_identity,
                });
            }
        }

        let has_ineligible = eligible.len() < all_placeholders.len();

        Self {
            eligible,
            all_placeholders,
            on_violation: config.on_violation.clone(),
            has_ineligible,
            tls_intercepted,
        }
    }

    /// Substitute secrets in plaintext data (guest → server direction).
    ///
    /// Splits the HTTP message on `\r\n\r\n` to scope substitution:
    /// - `headers`: substitutes in the header portion (before boundary)
    /// - `basic_auth`: substitutes in Authorization headers specifically
    /// - `query_params`: substitutes in the request line (first line, query portion)
    /// - `body`: substitutes in the body portion (after boundary)
    ///
    /// Returns `None` if a violation is detected (placeholder going to a
    /// disallowed host) or `BlockAndTerminate` is triggered.
    pub fn substitute<'a>(&self, data: &'a [u8]) -> Option<Cow<'a, [u8]>> {
        // Fast path: skip violation check when no ineligible secrets exist.
        if self.has_ineligible {
            let text = String::from_utf8_lossy(data);
            if self.has_violation(&text) {
                match self.on_violation {
                    ViolationAction::Block => return None,
                    ViolationAction::BlockAndLog => {
                        tracing::warn!(
                            "secret violation: placeholder detected for disallowed host"
                        );
                        return None;
                    }
                    ViolationAction::BlockAndTerminate => {
                        tracing::error!(
                            "secret violation: placeholder detected for disallowed host — terminating"
                        );
                        return None;
                    }
                }
            }
        }

        if self.eligible.is_empty() {
            // No substitution needed — return borrowed slice (zero-copy).
            return Some(Cow::Borrowed(data));
        }

        // Split raw bytes at the header boundary BEFORE converting to owned strings.
        // This avoids position shifts from from_utf8_lossy replacement chars.
        let boundary = find_header_boundary(data);
        let (header_bytes, body_bytes) = match boundary {
            Some(pos) => (&data[..pos], &data[pos..]),
            None => (data, &[] as &[u8]),
        };
        let mut header_str = String::from_utf8_lossy(header_bytes).into_owned();
        let mut body_str = if boundary.is_some() {
            String::from_utf8_lossy(body_bytes).into_owned()
        } else {
            String::new()
        };

        for secret in &self.eligible {
            // Skip secrets that require TLS identity on non-intercepted connections.
            if secret.require_tls_identity && !self.tls_intercepted {
                continue;
            }

            if boundary.is_some() {
                // Header portion: substitute based on headers/basic_auth/query_params scopes.
                if secret.inject_headers || secret.inject_basic_auth || secret.inject_query_params {
                    // Guard: only allocate a new String if the placeholder is actually present.
                    if header_str.contains(&secret.placeholder) {
                        header_str = substitute_in_headers(
                            &header_str,
                            &secret.placeholder,
                            &secret.value,
                            secret.inject_headers,
                            secret.inject_basic_auth,
                            secret.inject_query_params,
                        );
                    }
                }

                // Body portion.
                if secret.inject_body && body_str.contains(&secret.placeholder) {
                    body_str = body_str.replace(&secret.placeholder, &secret.value);
                }
            } else {
                // No boundary found — treat entire message as headers.
                if secret.inject_headers && header_str.contains(&secret.placeholder) {
                    header_str = header_str.replace(&secret.placeholder, &secret.value);
                }
            }
        }

        let mut output = header_str;
        output.push_str(&body_str);
        Some(Cow::Owned(output.into_bytes()))
    }

    /// Returns true if no secrets are configured.
    pub fn is_empty(&self) -> bool {
        self.all_placeholders.is_empty()
    }
}

impl SecretsHandler {
    /// Check if any placeholder appears in data for a host that isn't allowed.
    fn has_violation(&self, text: &str) -> bool {
        // Fast path: if all placeholders have matching eligible entries, no
        // violation is possible (every secret is allowed for this host).
        if self.eligible.len() == self.all_placeholders.len() {
            return false;
        }

        for placeholder in &self.all_placeholders {
            if text.contains(placeholder.as_str())
                && !self.eligible.iter().any(|s| s.placeholder == *placeholder)
            {
                return true;
            }
        }

        false
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Substitute a placeholder in the headers portion with scoping:
/// - `headers`: replace anywhere in headers
/// - `basic_auth`: replace only in Authorization header lines
/// - `query_params`: replace only in the request line's query string
fn substitute_in_headers(
    headers: &str,
    placeholder: &str,
    value: &str,
    inject_all_headers: bool,
    inject_basic_auth: bool,
    inject_query_params: bool,
) -> String {
    if inject_all_headers {
        // Replace everywhere in headers.
        return headers.replace(placeholder, value);
    }

    // Line-by-line scoping.
    let mut result = String::with_capacity(headers.len());
    for (i, line) in headers.split("\r\n").enumerate() {
        if i > 0 {
            result.push_str("\r\n");
        }

        if i == 0 && inject_query_params {
            // Request line — substitute in query portion.
            result.push_str(&line.replace(placeholder, value));
        } else if inject_basic_auth
            && line
                .as_bytes()
                .get(..14)
                .is_some_and(|b| b.eq_ignore_ascii_case(b"authorization:"))
        {
            // Authorization header — substitute.
            result.push_str(&line.replace(placeholder, value));
        } else {
            result.push_str(line);
        }
    }

    result
}

/// Find the `\r\n\r\n` boundary between HTTP headers and body.
fn find_header_boundary(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::config::*;

    fn make_config(secrets: Vec<SecretEntry>) -> SecretsConfig {
        SecretsConfig {
            secrets,
            on_violation: ViolationAction::Block,
        }
    }

    fn make_secret(placeholder: &str, value: &str, host: &str) -> SecretEntry {
        SecretEntry {
            env_var: "TEST_KEY".into(),
            value: value.into(),
            placeholder: placeholder.into(),
            allowed_hosts: vec![HostPattern::Exact(host.into())],
            injection: SecretInjection::default(),
            require_tls_identity: true,
        }
    }

    #[test]
    fn substitute_in_headers() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let handler = SecretsHandler::new(&config, "api.openai.com", true);

        let input = b"GET / HTTP/1.1\r\nAuthorization: Bearer $KEY\r\n\r\n";
        let output = handler.substitute(input).unwrap();
        assert_eq!(
            String::from_utf8(output.into_owned()).unwrap(),
            "GET / HTTP/1.1\r\nAuthorization: Bearer real-secret\r\n\r\n"
        );
    }

    #[test]
    fn no_substitute_for_wrong_host() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let handler = SecretsHandler::new(&config, "evil.com", true);

        let input = b"GET / HTTP/1.1\r\nAuthorization: Bearer $KEY\r\n\r\n";
        assert!(handler.substitute(input).is_none());
    }

    #[test]
    fn body_injection_disabled_by_default() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let handler = SecretsHandler::new(&config, "api.openai.com", true);

        let input = b"POST / HTTP/1.1\r\n\r\n{\"key\": \"$KEY\"}";
        let output = handler.substitute(input).unwrap();
        assert!(
            String::from_utf8(output.into_owned())
                .unwrap()
                .contains("$KEY")
        );
    }

    #[test]
    fn body_injection_when_enabled() {
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.injection.body = true;
        let config = make_config(vec![secret]);
        let handler = SecretsHandler::new(&config, "api.openai.com", true);

        let input = b"POST / HTTP/1.1\r\n\r\n{\"key\": \"$KEY\"}";
        let output = handler.substitute(input).unwrap();
        assert_eq!(
            String::from_utf8(output.into_owned()).unwrap(),
            "POST / HTTP/1.1\r\n\r\n{\"key\": \"real-secret\"}"
        );
    }

    #[test]
    fn no_secrets_passthrough() {
        let config = make_config(vec![]);
        let handler = SecretsHandler::new(&config, "anything.com", true);

        let input = b"GET / HTTP/1.1\r\n\r\n";
        let output = handler.substitute(input).unwrap();
        assert_eq!(&*output, input);
    }

    #[test]
    fn require_tls_identity_blocks_on_non_intercepted() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        // tls_intercepted = false — secret requires TLS identity
        let handler = SecretsHandler::new(&config, "api.openai.com", false);

        let input = b"GET / HTTP/1.1\r\nAuthorization: Bearer $KEY\r\n\r\n";
        let output = handler.substitute(input).unwrap();
        // Placeholder should NOT be substituted.
        assert!(
            String::from_utf8(output.into_owned())
                .unwrap()
                .contains("$KEY")
        );
    }

    #[test]
    fn basic_auth_only_substitution() {
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.injection = SecretInjection {
            headers: false,
            basic_auth: true,
            query_params: false,
            body: false,
        };
        let config = make_config(vec![secret]);
        let handler = SecretsHandler::new(&config, "api.openai.com", true);

        let input = b"GET / HTTP/1.1\r\nAuthorization: Bearer $KEY\r\nX-Custom: $KEY\r\n\r\n";
        let output = handler.substitute(input).unwrap();
        let result = String::from_utf8(output.into_owned()).unwrap();
        // Authorization header should be substituted.
        assert!(result.contains("Authorization: Bearer real-secret"));
        // Other headers should NOT be substituted.
        assert!(result.contains("X-Custom: $KEY"));
    }

    #[test]
    fn query_params_substitution() {
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.injection = SecretInjection {
            headers: false,
            basic_auth: false,
            query_params: true,
            body: false,
        };
        let config = make_config(vec![secret]);
        let handler = SecretsHandler::new(&config, "api.openai.com", true);

        let input = b"GET /api?key=$KEY HTTP/1.1\r\nHost: api.openai.com\r\n\r\n";
        let output = handler.substitute(input).unwrap();
        let result = String::from_utf8(output.into_owned()).unwrap();
        // Request line should be substituted.
        assert!(result.contains("GET /api?key=real-secret HTTP/1.1"));
        // Other headers should NOT be substituted.
    }
}
