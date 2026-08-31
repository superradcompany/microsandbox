//! HTTP/HTTPS bodies returned to the guest when egress is denied.
//!
//! Policy still closes the upstream path. For HTTP and intercepted HTTPS the
//! proxy answers the guest with `403 Forbidden` so clients surface a readable
//! error instead of a bare connection reset.

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Placeholder replaced with the blocked hostname in deny templates.
pub const HOST_PLACEHOLDER: &str = "{host}";

/// Default body shown to HTTP/HTTPS clients for a denied host.
pub const DEFAULT_HTTP_DENY_MESSAGE: &str = "\
This host is not allowed by the sandbox network policy.\n\
\n\
Note to agent: `{host}` is not in the allowed-host list. Ask the user to add it to the sandbox network allow list.\n";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{DEFAULT_HTTP_DENY_MESSAGE, http_forbidden_response, render_http_deny_message};

    #[test]
    fn default_message_names_the_blocked_host() {
        let body = render_http_deny_message(DEFAULT_HTTP_DENY_MESSAGE, "evil.example");
        assert!(body.contains("`evil.example`"));
        assert!(body.contains("Note to agent:"));
        assert!(!body.contains("{host}"));
    }

    #[test]
    fn empty_host_falls_back_to_this_host() {
        let body = render_http_deny_message("blocked: {host}", "  ");
        assert_eq!(body, "blocked: this host");
    }

    #[test]
    fn forbidden_response_is_http11_with_the_body() {
        let response = http_forbidden_response("nope\n");
        let text = std::str::from_utf8(&response).unwrap();
        assert!(text.starts_with("HTTP/1.1 403 Forbidden\r\n"));
        assert!(text.contains("Content-Type: text/plain; charset=utf-8\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        assert!(text.ends_with("\r\n\r\nnope\n"));
        assert!(text.contains("Content-Length: 5\r\n"));
    }
}
