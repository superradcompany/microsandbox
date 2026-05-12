//! Secret substitution handler for the TLS proxy.
//!
//! Scans decrypted plaintext for placeholder strings and replaces them
//! with real secret values, but only when the destination host is allowed.

use std::borrow::Cow;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

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

impl EligibleSecret {
    /// Returns true if any of the header-side injection scopes is enabled
    /// (`headers`, `basic_auth`, or `query_params`).
    fn wants_header_injection(&self) -> bool {
        self.inject_headers || self.inject_basic_auth || self.inject_query_params
    }

    /// Substitute this secret's placeholder in the headers portion, scoped by
    /// the secret's `headers` / `basic_auth` / `query_params` flags.
    fn substitute_in_headers(&self, headers: &str) -> String {
        let mut result = String::with_capacity(headers.len());
        for (i, line) in headers.split("\r\n").enumerate() {
            if i > 0 {
                result.push_str("\r\n");
            }
            match self.substitute_in_header_line(line, i == 0) {
                Some(s) => result.push_str(&s),
                None => result.push_str(line),
            }
        }
        result
    }

    /// Substitute this secret's placeholder in a single header line. Returns
    /// `None` if the line is not in scope for any of the requested injection
    /// modes.
    fn substitute_in_header_line(&self, line: &str, is_request_line: bool) -> Option<String> {
        if self.inject_basic_auth && is_authorization_header(line) {
            return Some(self.substitute_basic_auth_header(line));
        }
        if self.inject_headers {
            return Some(line.replace(&self.placeholder, &self.value));
        }
        if is_request_line && self.inject_query_params {
            return Some(line.replace(&self.placeholder, &self.value));
        }
        None
    }

    /// Substitute this secret's placeholder inside an `Authorization` header.
    /// For `Basic <base64>` headers the base64 payload is decoded, the
    /// placeholder is substituted in the decoded credentials, and the result
    /// is re-encoded. All other schemes (e.g. `Bearer`) fall back to a literal
    /// replacement so placeholders appearing in plaintext tokens are still
    /// substituted.
    fn substitute_basic_auth_header(&self, line: &str) -> String {
        let Some(decoded) = decode_basic_credentials(line) else {
            return line.replace(&self.placeholder, &self.value);
        };
        if !decoded.contains(&self.placeholder) {
            return line.replace(&self.placeholder, &self.value);
        }
        let Some((name, _)) = line.split_once(':') else {
            return line.replace(&self.placeholder, &self.value);
        };
        let replaced = decoded.replace(&self.placeholder, &self.value);
        format!("{name}: Basic {}", BASE64.encode(replaced.as_bytes()))
    }
}

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

        // Fast path: skip violation check when no ineligible secrets exist.
        if self.has_ineligible && self.has_violation(&header_str, &body_str) {
            match self.on_violation {
                ViolationAction::Block => return None,
                ViolationAction::BlockAndLog => {
                    tracing::warn!("secret violation: placeholder detected for disallowed host");
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

        if self.eligible.is_empty() {
            // No substitution needed. Return borrowed slice (zero-copy).
            return Some(Cow::Borrowed(data));
        }

        for secret in &self.eligible {
            // Skip secrets that require TLS identity on non-intercepted connections.
            if secret.require_tls_identity && !self.tls_intercepted {
                continue;
            }
            if secret.wants_header_injection() {
                header_str = secret.substitute_in_headers(&header_str);
            }
            if boundary.is_some() && secret.inject_body && body_str.contains(&secret.placeholder) {
                body_str = body_str.replace(&secret.placeholder, &secret.value);
            }
        }

        // If body substitution changed the length, update Content-Length.
        if boundary.is_some() && body_str.len() != body_bytes.len() {
            header_str = update_content_length(&header_str, body_str.len());
        }

        let mut output = header_str;
        output.push_str(&body_str);
        Some(Cow::Owned(output.into_bytes()))
    }

    /// Returns true if no secrets are configured.
    pub fn is_empty(&self) -> bool {
        self.all_placeholders.is_empty()
    }

    /// Returns true if a violation should terminate the sandbox.
    pub fn terminates_on_violation(&self) -> bool {
        matches!(self.on_violation, ViolationAction::BlockAndTerminate)
    }

    /// Check if any placeholder appears in data for a host that isn't allowed.
    fn has_violation(&self, headers: &str, body: &str) -> bool {
        // Fast path: if all placeholders have matching eligible entries, no
        // violation is possible (every secret is allowed for this host).
        if self.eligible.len() == self.all_placeholders.len() {
            return false;
        }

        for placeholder in &self.all_placeholders {
            if self.eligible.iter().any(|s| s.placeholder == *placeholder) {
                continue;
            }
            if headers.contains(placeholder.as_str())
                || body.contains(placeholder.as_str())
                || basic_auth_decoded_contains(headers, placeholder)
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

/// Returns true if `line` starts with the `Authorization:` header name
/// (case-insensitive).
fn is_authorization_header(line: &str) -> bool {
    line.as_bytes()
        .get(..14)
        .is_some_and(|b| b.eq_ignore_ascii_case(b"authorization:"))
}

/// Decode the credentials of a `Basic` `Authorization` header line. Returns
/// `None` if the line is not `Basic`-scheme or the payload is not valid
/// base64 / UTF-8.
fn decode_basic_credentials(line: &str) -> Option<String> {
    let (_, raw_value) = line.split_once(':')?;
    let (scheme, encoded) = split_auth_scheme(raw_value.trim_start())?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let bytes = BASE64.decode(encoded.trim()).ok()?;
    String::from_utf8(bytes).ok()
}

/// Split an `Authorization` header value into `(scheme, rest)` at the first
/// whitespace. Returns `None` if no whitespace separator is found.
fn split_auth_scheme(header_value: &str) -> Option<(&str, &str)> {
    let split_at = header_value.find(char::is_whitespace)?;
    let (scheme, rest) = header_value.split_at(split_at);
    Some((scheme, rest.trim_start()))
}

/// Returns true if any `Authorization: Basic` line in `headers` decodes to
/// credentials containing `placeholder`.
fn basic_auth_decoded_contains(headers: &str, placeholder: &str) -> bool {
    headers
        .split("\r\n")
        .filter(|line| is_authorization_header(line))
        .filter_map(decode_basic_credentials)
        .any(|decoded| decoded.contains(placeholder))
}

/// Update the Content-Length header value in `headers` to `new_len`.
///
/// Performs a case-insensitive line scan. If no Content-Length header exists
/// (e.g. chunked transfer encoding), the headers are returned unchanged.
fn update_content_length(headers: &str, new_len: usize) -> String {
    let mut result = String::with_capacity(headers.len());
    for (i, line) in headers.split("\r\n").enumerate() {
        if i > 0 {
            result.push_str("\r\n");
        }
        if line
            .as_bytes()
            .get(..15)
            .is_some_and(|b| b.eq_ignore_ascii_case(b"content-length:"))
        {
            result.push_str(&format!("Content-Length: {new_len}"));
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

    fn basic_auth_only() -> SecretInjection {
        SecretInjection {
            headers: false,
            basic_auth: true,
            query_params: false,
            body: false,
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
    fn body_injection_updates_content_length() {
        let mut secret = make_secret("$KEY", "a]longer]secret]value", "api.openai.com");
        secret.injection.body = true;
        let config = make_config(vec![secret]);
        let handler = SecretsHandler::new(&config, "api.openai.com", true);

        let body = "{\"key\": \"$KEY\"}";
        let input = format!(
            "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let output = handler.substitute(input.as_bytes()).unwrap();
        let result = String::from_utf8(output.into_owned()).unwrap();

        let expected_body = "{\"key\": \"a]longer]secret]value\"}";
        assert!(result.contains(expected_body));
        assert!(result.contains(&format!("Content-Length: {}", expected_body.len())));
    }

    #[test]
    fn body_injection_no_content_length_header() {
        let mut secret = make_secret("$KEY", "longer-secret", "api.openai.com");
        secret.injection.body = true;
        let config = make_config(vec![secret]);
        let handler = SecretsHandler::new(&config, "api.openai.com", true);

        // No Content-Length header (e.g. chunked).
        let input = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n{\"key\": \"$KEY\"}";
        let output = handler.substitute(input).unwrap();
        let result = String::from_utf8(output.into_owned()).unwrap();
        assert!(result.contains("longer-secret"));
        assert!(!result.contains("Content-Length"));
    }

    #[test]
    fn header_only_substitution_preserves_content_length() {
        let config = make_config(vec![make_secret("$KEY", "longer-value", "api.openai.com")]);
        let handler = SecretsHandler::new(&config, "api.openai.com", true);

        let input =
            b"GET / HTTP/1.1\r\nAuthorization: Bearer $KEY\r\nContent-Length: 5\r\n\r\nhello";
        let output = handler.substitute(input).unwrap();
        let result = String::from_utf8(output.into_owned()).unwrap();
        // Body unchanged, Content-Length should stay 5.
        assert!(result.contains("Content-Length: 5"));
        assert!(result.ends_with("hello"));
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
        secret.injection = basic_auth_only();
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
    fn basic_auth_decodes_substitutes_and_reencodes_credentials() {
        let mut user = make_secret("$MSB_USER", "alice", "api.openai.com");
        user.env_var = "USER".into();
        user.injection = basic_auth_only();
        let mut password = make_secret("$MSB_PASSWORD", "s3cr3t", "api.openai.com");
        password.env_var = "PASSWORD".into();
        password.injection = basic_auth_only();
        let config = make_config(vec![user, password]);
        let handler = SecretsHandler::new(&config, "api.openai.com", true);

        let encoded = BASE64.encode(b"$MSB_USER:$MSB_PASSWORD");
        let input = format!("GET / HTTP/1.1\r\nAuthorization: Basic {encoded}\r\n\r\n");
        let output = handler.substitute(input.as_bytes()).unwrap();
        let result = String::from_utf8(output.into_owned()).unwrap();

        assert!(result.contains(&format!(
            "Authorization: Basic {}",
            BASE64.encode(b"alice:s3cr3t")
        )));
        assert!(!result.contains("$MSB_USER"));
        assert!(!result.contains("$MSB_PASSWORD"));
    }

    #[test]
    fn basic_auth_encoded_placeholder_is_blocked_for_wrong_host() {
        let mut secret = make_secret("$MSB_PASSWORD", "s3cr3t", "api.openai.com");
        secret.injection = basic_auth_only();
        let config = make_config(vec![secret]);
        let handler = SecretsHandler::new(&config, "evil.com", true);

        let encoded = BASE64.encode(b"user:$MSB_PASSWORD");
        let input = format!("GET / HTTP/1.1\r\nAuthorization: Basic {encoded}\r\n\r\n");

        assert!(handler.substitute(input.as_bytes()).is_none());
    }

    #[test]
    fn basic_auth_encoded_placeholder_is_not_replaced_when_scope_disabled() {
        let mut secret = make_secret("$MSB_PASSWORD", "s3cr3t", "api.openai.com");
        secret.injection = SecretInjection {
            headers: false,
            basic_auth: false,
            query_params: false,
            body: false,
        };
        let config = make_config(vec![secret]);
        let handler = SecretsHandler::new(&config, "api.openai.com", true);

        let encoded = BASE64.encode(b"user:$MSB_PASSWORD");
        let input = format!("GET / HTTP/1.1\r\nAuthorization: Basic {encoded}\r\n\r\n");
        let output = handler.substitute(input.as_bytes()).unwrap();

        assert_eq!(String::from_utf8(output.into_owned()).unwrap(), input);
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
