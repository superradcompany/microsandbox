//! HTTP/HTTPS bodies returned to the guest when egress is denied.
//!
//! Policy still closes the upstream path. For HTTP and intercepted HTTPS the
//! proxy answers the guest with `403 Forbidden` so clients surface a readable
//! error instead of a bare connection reset.

use serde_json::json;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Placeholder replaced with the blocked hostname in deny templates.
pub const HOST_PLACEHOLDER: &str = "{host}";

/// Default body shown to HTTP/HTTPS clients for a denied host.
pub const DEFAULT_HTTP_DENY_MESSAGE: &str = "\
This host is not allowed by the sandbox network policy config.\n\
\n\
Note to agent: `{host}` is not in the allowed-host list. \
Ask the user to add it to the sandbox network allow list.\n";

/// Default JSON network-denial message.
pub const NETWORK_JSON_DENY_MESSAGE: &str = "Request blocked by network policy.";

/// Explanation for a placeholder rejected by the secret policy.
pub(crate) const SECRET_HTTP_DENY_MESSAGE: &str = "Request blocked by secret policy.";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Classify a denied first flight as HTTP/1.x, another protocol, or incomplete.
/// A method prefix alone is not enough to choose a response protocol.
pub(crate) fn classify_http_request(buf: &[u8]) -> Option<bool> {
    let mut line = buf;

    while let Some(rest) = line.strip_prefix(b"\r\n") {
        line = rest;
    }
    if line.is_empty() || line == b"\r" {
        return None;
    }
    if !line[0].is_ascii_alphabetic() {
        return Some(false);
    }

    let Some(end) = line.windows(2).position(|pair| pair == b"\r\n") else {
        return line
            .iter()
            .any(|byte| !byte.is_ascii() || (*byte < b' ' && *byte != b'\r'))
            .then_some(false);
    };

    let mut headers = [];
    let mut request = httparse::Request::new(&mut headers);
    let parsed = request.parse(&line[..end + 2]);
    let is_http1 = parsed.is_ok()
        && matches!(request.version, Some(0 | 1))
        && request.method.is_some()
        && request.path.is_some();

    Some(is_http1)
}

/// Render a deny-message template, substituting [`HOST_PLACEHOLDER`].
pub fn render_http_deny_message(template: &str, host: &str) -> String {
    let host = host.trim();
    let host = if host.is_empty() { "this host" } else { host };
    template.replace(HOST_PLACEHOLDER, host)
}

/// Build a close-delimited HTTP/1.1 403 response for `body`.
pub fn http_forbidden_response(body: &str) -> Vec<u8> {
    let body = body.as_bytes();
    let mut response = Vec::with_capacity(128 + body.len());
    response.extend_from_slice(b"HTTP/1.1 403 Forbidden\r\n");
    response.extend_from_slice(b"Content-Type: text/plain; charset=utf-8\r\n");
    response.extend_from_slice(b"Connection: close\r\n");
    response.extend_from_slice(b"Cache-Control: no-store\r\n");
    response.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    response.extend_from_slice(body);
    response
}

/// Build an HTTP/1.1 403 with a stable network-policy code and JSON message and requested domain.
pub fn json_http_forbidden_response(message: &str, host: &str) -> Vec<u8> {
    forbidden_response("network_policy_denied", message, host)
}

/// Build an HTTP/1.1 403 with a stable JSON error for a secret-policy violation.
pub(crate) fn secret_http_forbidden_response(message: &str, host: &str) -> Vec<u8> {
    forbidden_response("secret_policy_denied", message, host)
}

fn forbidden_response(code: &str, message: &str, host: &str) -> Vec<u8> {
    // Serialize custom messages so quotes, control characters and Unicode
    // remain message content rather than changing the error envelope.
    let domain = (!host.is_empty()).then_some(host);
    let json = json!({ "code": code, "message": message, "domain": domain }).to_string();
    let body = json.as_bytes();
    let mut response = Vec::with_capacity(128 + body.len());
    response.extend_from_slice(b"HTTP/1.1 403 Forbidden\r\n");
    response.extend_from_slice(b"Content-Type: application/json\r\n");
    response.extend_from_slice(b"Connection: close\r\n");
    response.extend_from_slice(b"Cache-Control: no-store\r\n");
    response.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    response.extend_from_slice(body);
    response
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{classify_http_request, json_http_forbidden_response};

    #[test]
    fn classification_requires_a_complete_http1_request_line() {
        for request in [
            b"GET / HTTP/1.1\r\n".as_slice(),
            b"QUERY / HTTP/1.0\r\n",
            b"\r\nGET / HTTP/1.1\r\n",
        ] {
            for end in 0..request.len() {
                assert_eq!(
                    classify_http_request(&request[..end]),
                    None,
                    "prefix: {:?}",
                    &request[..end]
                );
            }
            assert_eq!(classify_http_request(request), Some(true));
        }
        for request in [
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".as_slice(),
            b"SSH-2.0-OpenSSH\r\n",
            b"EHLO mail.example\r\n",
            b"GET file\r\n",
            b"GET / HTTP/3.0\r\n",
            b"\x16\x03\x01",
            b"\x00binary",
        ] {
            assert_eq!(
                classify_http_request(request),
                Some(false),
                "request: {request:?}"
            );
        }
    }

    #[test]
    fn forbidden_response_is_http11_with_a_json_error() {
        for (message, host, expected_domain) in [
            ("nope\n", "example.com", Some("example.com")),
            ("", "", None),
            (
                "blocked \"example.com\": use C:\\policy\n雪\t\u{0000}",
                "example.com",
                Some("example.com"),
            ),
        ] {
            let response = json_http_forbidden_response(message, host);
            let text = std::str::from_utf8(&response).unwrap();
            let (headers, body) = text.split_once("\r\n\r\n").unwrap();
            assert!(headers.starts_with("HTTP/1.1 403 Forbidden\r\n"));
            assert!(headers.contains("Content-Type: application/json\r\n"));
            assert!(headers.contains("Connection: close\r\n"));
            let error: serde_json::Value = serde_json::from_str(body).unwrap();
            assert_eq!(error["code"], "network_policy_denied");
            assert_eq!(error["message"], message);
            assert_eq!(error["domain"], serde_json::json!(expected_domain));
            let content_length: usize = headers
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .unwrap()
                .parse()
                .unwrap();
            assert_eq!(content_length, body.len());
        }
    }
}
