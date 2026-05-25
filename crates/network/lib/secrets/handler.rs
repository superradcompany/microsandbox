//! Secret substitution handler for the TLS proxy.
//!
//! Scans decrypted plaintext for placeholder strings and replaces them
//! with real secret values, but only when the destination host is allowed.

use std::borrow::Cow;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use percent_encoding::percent_decode;

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
    eligible_for_substitution: Vec<EligibleSecret>,
    /// Secret placeholders that should trigger an effective blocking action.
    ineligible_for_substitution: Vec<IneligibleSecret>,
    /// Whether this connection is TLS-intercepted (not bypass).
    tls_intercepted: bool,
    /// Longest placeholder length. Sizes the sliding-window tail.
    max_placeholder_len: usize,
    /// Trailing bytes carried over from the previous `substitute` call so a
    /// placeholder split across TCP writes still trips the violation check.
    /// Capped at `max_placeholder_len - 1` bytes.
    prev_tail: Vec<u8>,
    /// HTTP framing state for the request stream. Tracks whether the next
    /// chunk should be parsed as a request start (headers) or treated as a
    /// continuation of the current request's body.
    http_state: HttpState,
}

/// HTTP request framing state for the guest→server byte stream.
#[derive(Debug, Clone)]
enum HttpState {
    /// Scanning for the start of a request. The next `\r\n\r\n` ends headers.
    AwaitingHeaders,
    /// Inside a request body. `remaining` is the number of body bytes left
    /// per Content-Length; `None` means unknown framing (chunked or
    /// connection-close).
    InBody { remaining: Option<usize> },
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

/// A secret that did not pass substitution or passthrough host matching.
struct IneligibleSecret {
    placeholder: String,
    action: BlockingAction,
}

/// Blocking action to take when an ineligible placeholder is detected.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum BlockingAction {
    Block,
    #[default]
    BlockAndLog,
    BlockAndTerminate,
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

    /// Returns true when the current header bytes contain this secret's
    /// placeholder in a header-substitution scope.
    fn may_substitute_in_headers(&self, headers: &[u8]) -> bool {
        if !self.wants_header_injection() {
            return false;
        }

        let needle = self.placeholder.as_bytes();
        if (self.inject_headers || self.inject_query_params) && contains_bytes(headers, needle) {
            return true;
        }

        // Search decoded Basic auth credentials, not the raw header value.
        if self.inject_basic_auth {
            return basic_auth_decoded_contains(
                String::from_utf8_lossy(headers).as_ref(),
                &self.placeholder,
            );
        }

        false
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
        if self.inject_basic_auth
            && is_authorization_header(line)
            && let Some(replaced) = self.substitute_basic_auth_header(line)
        {
            return Some(replaced);
        }
        if self.inject_headers {
            return Some(line.replace(&self.placeholder, &self.value));
        }
        if is_request_line && self.inject_query_params {
            return Some(line.replace(&self.placeholder, &self.value));
        }
        None
    }

    /// Decode `Basic <base64>` credentials, substitute the placeholder in the
    /// decoded `user:password`, and return the re-encoded line. Returns `None`
    /// if the line isn't `Basic` scheme or the decoded credentials don't
    /// contain the placeholder. Non-Basic schemes (e.g. `Bearer`) are handled
    /// by `inject_headers` instead.
    fn substitute_basic_auth_header(&self, line: &str) -> Option<String> {
        let decoded = decode_basic_credentials(line)?;
        if !decoded.contains(&self.placeholder) {
            return None;
        }
        let (name, _) = line.split_once(':')?;
        let replaced = decoded.replace(&self.placeholder, &self.value);
        Some(format!(
            "{name}: Basic {}",
            BASE64.encode(replaced.as_bytes())
        ))
    }
}

impl BlockingAction {
    fn from_violation_action(action: &ViolationAction) -> Option<Self> {
        match action {
            ViolationAction::Block => Some(Self::Block),
            ViolationAction::BlockAndLog => Some(Self::BlockAndLog),
            ViolationAction::BlockAndTerminate => Some(Self::BlockAndTerminate),
            ViolationAction::Passthrough(_) => None,
        }
    }

    fn into_violation_action(self) -> ViolationAction {
        match self {
            Self::Block => ViolationAction::Block,
            Self::BlockAndLog => ViolationAction::BlockAndLog,
            Self::BlockAndTerminate => ViolationAction::BlockAndTerminate,
        }
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
        let mut eligible_for_substitution = Vec::new();
        let mut ineligible_for_substitution = Vec::new();
        let mut max_placeholder_len = 0;

        for secret in &config.secrets {
            max_placeholder_len = max_placeholder_len.max(secret.placeholder.len());

            let host_allowed = secret.allowed_hosts.is_empty()
                || secret.allowed_hosts.iter().any(|p| p.matches(sni));

            // If the SNI matches an allowed host for this secret, add it to the
            // eligible list for substitution, and skip violation checks for this secret.
            if host_allowed {
                eligible_for_substitution.push(EligibleSecret {
                    placeholder: secret.placeholder.clone(),
                    value: secret.value.clone(),
                    inject_headers: secret.injection.headers,
                    inject_basic_auth: secret.injection.basic_auth,
                    inject_query_params: secret.injection.query_params,
                    inject_body: secret.injection.body,
                    require_tls_identity: secret.require_tls_identity,
                });

                continue;
            }

            let action = secret.on_violation.as_ref().unwrap_or(&config.on_violation);

            // Passthrough means the placeholder can be forwarded unchanged to this SNI.
            if let ViolationAction::Passthrough(hosts) = action
                && hosts.iter().any(|p| p.matches(sni))
            {
                continue;
            }

            // Non-matching passthrough policies fall back to the default blocking action.
            ineligible_for_substitution.push(IneligibleSecret {
                placeholder: secret.placeholder.clone(),
                action: BlockingAction::from_violation_action(action).unwrap_or_default(),
            });
        }

        Self {
            eligible_for_substitution,
            ineligible_for_substitution,
            tls_intercepted,
            max_placeholder_len,
            prev_tail: Vec::new(),
            http_state: HttpState::AwaitingHeaders,
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
    /// Returns the violation action if a placeholder is detected going to a
    /// disallowed host.
    pub fn substitute<'a>(&mut self, data: &'a [u8]) -> Result<Cow<'a, [u8]>, ViolationAction> {
        // Body-continuation chunk: previous chunk(s) already contained the
        // request line and headers.
        if let HttpState::InBody { remaining } = self.http_state {
            return self.substitute_body_chunk(data, remaining);
        }

        // Split raw bytes at the header boundary BEFORE converting to owned strings.
        // This avoids position shifts from from_utf8_lossy replacement chars.
        let boundary = find_header_boundary(data);
        let (header_bytes, after_headers) = match boundary {
            Some(pos) => (&data[..pos], &data[pos..]),
            None => (data, &[] as &[u8]),
        };

        // A single chunk may carry headers + body + the start of the next
        // pipelined request. Compute how many post-boundary bytes belong to
        // THIS request; the rest is spillover that gets its own recursive
        // pass through `substitute()` so its headers are substituted and
        // its violations are detected.
        let (body_bytes, spillover) = if boundary.is_some() {
            let (next_state, body_in_request) = next_state_after_headers(
                String::from_utf8_lossy(header_bytes).as_ref(),
                after_headers.len(),
            );
            self.http_state = next_state;
            after_headers.split_at(body_in_request)
        } else {
            (after_headers, &[] as &[u8])
        };

        // Everything from `data` belonging to this request, headers and body.
        let this_request = &data[..header_bytes.len() + body_bytes.len()];

        // Check for disallowed placeholders before forwarding or substituting data.
        if let Some(action) = self
            .detect_blocking_action(this_request, String::from_utf8_lossy(header_bytes).as_ref())
        {
            match action {
                BlockingAction::Block => return Err(action.into_violation_action()),
                BlockingAction::BlockAndLog => {
                    tracing::warn!("secret violation: placeholder detected for disallowed host");
                    return Err(action.into_violation_action());
                }
                BlockingAction::BlockAndTerminate => {
                    tracing::error!(
                        "secret violation: placeholder detected for disallowed host - terminating"
                    );
                    return Err(action.into_violation_action());
                }
            }
        }
        self.update_tail(this_request);

        if self.eligible_for_substitution.is_empty() {
            // No substitution needed; pass this request through and let the
            // recursive call handle the spillover (if any).
            return self.append_pipelined_spillover(data, this_request, spillover);
        }

        // Start with borrowed bytes; allocate only when a substitution is needed.
        let mut header_str = None;
        let mut body = None;

        for secret in &self.eligible_for_substitution {
            // Skip secrets that require TLS identity on non-intercepted connections.
            if secret.require_tls_identity && !self.tls_intercepted {
                continue;
            }

            // Header substitution still uses string helpers after a scoped match.
            if secret.may_substitute_in_headers(header_bytes) {
                let current = header_str
                    .get_or_insert_with(|| String::from_utf8_lossy(header_bytes).into_owned());
                *current = secret.substitute_in_headers(current);
            }

            // Body substitution works on bytes so encoded payloads stay valid.
            if boundary.is_some() && secret.inject_body {
                let source = body.as_deref().unwrap_or(body_bytes);
                if let Some(replaced) = replace_bytes(
                    source,
                    secret.placeholder.as_bytes(),
                    secret.value.as_bytes(),
                ) {
                    body = Some(replaced);
                }
            }
        }

        let header_changed = header_str
            .as_ref()
            .is_some_and(|headers| headers.as_bytes() != header_bytes);
        let body_changed = body.is_some();

        // No header or body replacement was produced. Forward this request
        // unchanged and recurse on the spillover.
        if !header_changed && !body_changed {
            return self.append_pipelined_spillover(data, this_request, spillover);
        }

        let header_len = header_str
            .as_ref()
            .map_or(header_bytes.len(), |headers| headers.len());
        let body_len = body.as_ref().map_or(body_bytes.len(), Vec::len);
        let mut output = Vec::with_capacity(header_len + body_len + spillover.len());

        let body_bytes_out = body.as_deref().unwrap_or(body_bytes);
        // Update Content-Length only when body substitution changed the size.
        //
        // FIXME: `body_bytes_out.len()` is the chunk's substituted body length,
        // not the request's total. If `inject_body=true` and the body spans
        // multiple `substitute()` calls, continuation chunks are forwarded
        // as-is past this rewritten Content-Length.
        if body_changed && body_bytes_out.len() != body_bytes.len() {
            let headers = match header_str {
                Some(headers) => update_content_length(&headers, body_bytes_out.len()),
                None => update_content_length(
                    String::from_utf8_lossy(header_bytes).as_ref(),
                    body_bytes_out.len(),
                ),
            };
            output.extend_from_slice(headers.as_bytes());
        } else if let Some(headers) = header_str {
            output.extend_from_slice(headers.as_bytes());
        } else {
            output.extend_from_slice(header_bytes);
        }

        output.extend_from_slice(body_bytes_out);

        if !spillover.is_empty() {
            let next_out = self.substitute(spillover)?;
            output.extend_from_slice(next_out.as_ref());
        }
        Ok(Cow::Owned(output))
    }

    /// Forward `this_request` (an unchanged subslice of `parent`) and
    /// recursively `substitute()` the `spillover` (the start of a
    /// pipelined next request). When both halves pass through unchanged,
    /// returns `Cow::Borrowed(parent)` for zero-copy.
    fn append_pipelined_spillover<'a>(
        &mut self,
        parent: &'a [u8],
        this_request: &'a [u8],
        spillover: &'a [u8],
    ) -> Result<Cow<'a, [u8]>, ViolationAction> {
        if spillover.is_empty() {
            return Ok(Cow::Borrowed(parent));
        }
        let next_out = self.substitute(spillover)?;
        if let Cow::Borrowed(b) = &next_out
            && std::ptr::eq(b.as_ptr(), spillover.as_ptr())
            && b.len() == spillover.len()
        {
            // Spillover passed through unchanged; both halves are contiguous
            // subslices of `parent`, so the whole parent can be returned
            // borrowed.
            return Ok(Cow::Borrowed(parent));
        }
        let next_bytes = next_out.as_ref();
        let mut out = Vec::with_capacity(this_request.len() + next_bytes.len());
        out.extend_from_slice(this_request);
        out.extend_from_slice(next_bytes);
        Ok(Cow::Owned(out))
    }

    /// Handle a chunk that is the continuation of the current request's
    /// body (no headers present at the start). The body bytes are
    /// forwarded as-is after a violation scan. If the body ends inside
    /// this chunk and the remaining bytes are a pipelined next request,
    /// they are recursively dispatched through `substitute()` so their
    /// headers are substituted and their violations are detected.
    ///
    /// Body substitution across chunks is unsupported (would require
    /// rewriting Content-Length in already-forwarded headers).
    fn substitute_body_chunk<'a>(
        &mut self,
        data: &'a [u8],
        remaining: Option<usize>,
    ) -> Result<Cow<'a, [u8]>, ViolationAction> {
        // Determine where this request's body ends inside the chunk.
        //
        // - Content-Length framing (`remaining = Some(n)`): split at `n`.
        //   Trailing bytes are a pipelined next request.
        // - Chunked framing (`remaining = None`): scan for the terminator
        //   `0\r\n\r\n`. Trailing bytes are a pipelined next request.
        // - No detected terminator under chunked framing: stay in body
        //   mode; no spillover this chunk.
        let body_end = match remaining {
            Some(n) if data.len() > n => Some(n),
            Some(_) => None,
            None => find_chunked_body_end(data),
        };
        let (body_part, spillover) = match body_end {
            Some(end) => data.split_at(end),
            None => (data, &[] as &[u8]),
        };

        if let Some(action) = self.detect_blocking_action(body_part, "") {
            match action {
                BlockingAction::Block => return Err(action.into_violation_action()),
                BlockingAction::BlockAndLog => {
                    tracing::warn!("secret violation: placeholder detected for disallowed host");
                    return Err(action.into_violation_action());
                }
                BlockingAction::BlockAndTerminate => {
                    tracing::error!(
                        "secret violation: placeholder detected for disallowed host - terminating"
                    );
                    return Err(action.into_violation_action());
                }
            }
        }
        self.update_tail(body_part);

        // Advance framing state. If the body completes within this chunk,
        // the spillover below is the start of a fresh request.
        self.http_state = match (remaining, body_end) {
            (_, Some(_)) => HttpState::AwaitingHeaders,
            (Some(n), None) => HttpState::InBody {
                remaining: Some(n - body_part.len()),
            },
            (None, None) => HttpState::InBody { remaining: None },
        };

        self.append_pipelined_spillover(data, body_part, spillover)
    }

    /// Returns true if this connection needs no secret substitution or violation detection.
    pub fn is_empty(&self) -> bool {
        self.eligible_for_substitution.is_empty() && self.ineligible_for_substitution.is_empty()
    }

    /// Returns the strongest blocking action for any placeholder appearing in data
    /// for a host that isn't allowed to receive either the real secret or the placeholder.
    ///
    /// Scans the raw bytes (stitched with the previous call's tail for
    /// cross-write detection), plus URL- and JSON-decoded variants for
    /// encoded-placeholder bypass attempts, plus base64-decoded Basic auth
    /// credentials.
    fn detect_blocking_action(&self, data: &[u8], headers: &str) -> Option<BlockingAction> {
        if self.ineligible_for_substitution.is_empty() {
            return None;
        }

        let scan_buf: Cow<[u8]> = if self.prev_tail.is_empty() {
            Cow::Borrowed(data)
        } else {
            let mut stitched = Vec::with_capacity(self.prev_tail.len() + data.len());
            stitched.extend_from_slice(&self.prev_tail);
            stitched.extend_from_slice(data);
            Cow::Owned(stitched)
        };
        let scan = scan_buf.as_ref();

        let mut detected = None;
        for secret in &self.ineligible_for_substitution {
            let needle = secret.placeholder.as_bytes();
            if contains_bytes(scan, needle)
                || url_decoded_contains(scan, needle)
                || json_escaped_contains(scan, needle)
                || basic_auth_decoded_contains(headers, &secret.placeholder)
            {
                detected = Some(strictest_violation_action(detected, secret.action));
            }
        }

        detected
    }

    /// Update the sliding-window tail with the trailing bytes of `data`, so
    /// the next `substitute` call can detect placeholders split across the
    /// boundary.
    fn update_tail(&mut self, data: &[u8]) {
        let tail_size = self.max_placeholder_len.saturating_sub(1);
        if tail_size == 0 {
            return;
        }
        if data.len() >= tail_size {
            self.prev_tail.clear();
            self.prev_tail
                .extend_from_slice(&data[data.len() - tail_size..]);
            return;
        }
        self.prev_tail.extend_from_slice(data);
        let overflow = self.prev_tail.len().saturating_sub(tail_size);
        if overflow > 0 {
            self.prev_tail.drain(..overflow);
        }
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

/// Byte-slice substring check.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Compute the framing state for the next chunk and how many of the
/// post-boundary bytes belong to THIS request's body. `body_in_chunk` is
/// the number of bytes that followed `\r\n\r\n` in this chunk; the
/// returned `body_in_request` is at most `body_in_chunk`, and any
/// remaining bytes are spillover from a pipelined next request.
fn next_state_after_headers(headers: &str, body_in_chunk: usize) -> (HttpState, usize) {
    if is_transfer_chunked(headers) {
        // Chunked framing doesn't expose a Content-Length up front. The
        // chunked body terminator (`0\r\n\r\n`) is detected later by
        // `substitute_body_chunk` so the connection can return to
        // `AwaitingHeaders` for subsequent keep-alive requests.
        return (HttpState::InBody { remaining: None }, body_in_chunk);
    }
    match parse_content_length(headers) {
        Some(cl) if body_in_chunk >= cl => (HttpState::AwaitingHeaders, cl),
        Some(cl) => (
            HttpState::InBody {
                remaining: Some(cl - body_in_chunk),
            },
            body_in_chunk,
        ),
        // Per RFC 9112 §6.3 case 6, a request with neither `Content-Length`
        // nor `Transfer-Encoding` has a zero-length body. Any trailing
        // bytes are the start of a pipelined next request.
        None => (HttpState::AwaitingHeaders, 0),
    }
}

/// Parse a `Content-Length:` value from the headers block. Case-insensitive
/// header name match; returns `None` if absent or unparseable.
fn parse_content_length(headers: &str) -> Option<usize> {
    for line in headers.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            return value.trim().parse().ok();
        }
    }
    None
}

/// True if the headers contain `Transfer-Encoding: chunked` (case-insensitive,
/// last value in the comma-list per RFC 7230).
fn is_transfer_chunked(headers: &str) -> bool {
    for line in headers.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value
                .split(',')
                .next_back()
                .map(|s| s.trim().eq_ignore_ascii_case("chunked"))
                .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

/// Replace all occurrences of `needle` in `haystack`.
///
/// Returns `None` when no replacement is needed so callers can preserve the
/// original byte slice without rebuilding arbitrary binary payloads.
fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Option<Vec<u8>> {
    if !contains_bytes(haystack, needle) {
        return None;
    }

    let mut result = Vec::with_capacity(haystack.len());
    let mut cursor = 0;
    while cursor < haystack.len() {
        if haystack[cursor..].starts_with(needle) {
            result.extend_from_slice(replacement);
            cursor += needle.len();
        } else {
            result.push(haystack[cursor]);
            cursor += 1;
        }
    }
    Some(result)
}

/// Returns true if `haystack`, after URL percent-decoding, contains `needle`.
fn url_decoded_contains(haystack: &[u8], needle: &[u8]) -> bool {
    let decoded: Vec<u8> = percent_decode(haystack).collect();
    contains_bytes(&decoded, needle)
}

/// Returns true if `haystack`, after JSON `\uXXXX` decoding, contains `needle`.
/// Only `\uXXXX` escapes are expanded (sufficient to detect ASCII placeholders
/// hidden via unicode escapes); other JSON escapes pass through.
fn json_escaped_contains(haystack: &[u8], needle: &[u8]) -> bool {
    let mut decoded = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        if haystack[i] == b'\\'
            && i + 5 < haystack.len()
            && haystack[i + 1] == b'u'
            && let (Some(a), Some(b), Some(c), Some(d)) = (
                hex_digit(haystack[i + 2]),
                hex_digit(haystack[i + 3]),
                hex_digit(haystack[i + 4]),
                hex_digit(haystack[i + 5]),
            )
        {
            let cp = ((a as u32) << 12) | ((b as u32) << 8) | ((c as u32) << 4) | (d as u32);
            if let Some(ch) = char::from_u32(cp) {
                let mut buf = [0u8; 4];
                decoded.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            }
            i += 6;
            continue;
        }
        decoded.push(haystack[i]);
        i += 1;
    }
    contains_bytes(&decoded, needle)
}

fn hex_digit(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
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

/// Locate the end of a chunked-encoded request body inside `data` and
/// return the byte position right after the terminator.
///
/// Looks for the zero-size last chunk with an empty trailer section:
/// either `\r\n0\r\n\r\n` (the common case, where the preceding chunk's
/// closing `\r\n` is still in this slice) or a chunk that starts directly
/// with `0\r\n\r\n` (TLS reads aligning so the closing `\r\n` ended the
/// previous slice).
///
/// Trailers in the last chunk (`0\r\n<Trailer>:<value>\r\n\r\n`) are not
/// supported and will not be detected here; they are exceedingly rare
/// in request direction. Terminators that straddle a TLS read boundary
/// are likewise not detected (would need a small dedicated lookahead).
fn find_chunked_body_end(data: &[u8]) -> Option<usize> {
    if let Some(pos) = data.windows(7).position(|w| w == b"\r\n0\r\n\r\n") {
        return Some(pos + 7);
    }
    if data.starts_with(b"0\r\n\r\n") {
        return Some(5);
    }
    None
}

/// Returns the stricter of two blocking actions, where
/// `BlockAndTerminate` > `BlockAndLog` > `Block`.
fn strictest_violation_action(
    current: Option<BlockingAction>,
    candidate: BlockingAction,
) -> BlockingAction {
    match (current, candidate) {
        (Some(BlockingAction::BlockAndTerminate), _) | (_, BlockingAction::BlockAndTerminate) => {
            BlockingAction::BlockAndTerminate
        }
        (Some(BlockingAction::BlockAndLog), _) | (_, BlockingAction::BlockAndLog) => {
            BlockingAction::BlockAndLog
        }
        (Some(BlockingAction::Block), _) | (None, BlockingAction::Block) => BlockingAction::Block,
    }
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
            on_violation: None,
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
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

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
        let mut handler = SecretsHandler::new(&config, "evil.com", true);

        let input = b"GET / HTTP/1.1\r\nAuthorization: Bearer $KEY\r\n\r\n";
        assert_eq!(
            handler.substitute(input).unwrap_err(),
            ViolationAction::Block
        );
    }

    #[test]
    fn allowed_placeholder_substitutes_when_another_secret_is_ineligible() {
        let allowed = make_secret("$ALLOWED", "allowed-secret", "api.openai.com");
        let blocked = make_secret("$BLOCKED", "blocked-secret", "api.github.com");
        let config = make_config(vec![allowed, blocked]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let input = b"GET / HTTP/1.1\r\nAuthorization: Bearer $ALLOWED\r\n\r\n";
        let output = handler.substitute(input).unwrap();

        assert_eq!(
            String::from_utf8(output.into_owned()).unwrap(),
            "GET / HTTP/1.1\r\nAuthorization: Bearer allowed-secret\r\n\r\n"
        );
    }

    #[test]
    fn global_passthrough_host_forwards_placeholder_unchanged() {
        let mut config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        config.on_violation =
            ViolationAction::Passthrough(vec![HostPattern::Exact("api.anthropic.com".into())]);
        let mut handler = SecretsHandler::new(&config, "api.anthropic.com", true);

        let input = b"GET / HTTP/1.1\r\nAuthorization: Bearer $KEY\r\n\r\n";
        let output = handler.substitute(input).unwrap();
        assert_eq!(&*output, input);
    }

    #[test]
    fn per_secret_passthrough_host_forwards_placeholder_unchanged() {
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.on_violation = Some(ViolationAction::Passthrough(vec![HostPattern::Exact(
            "api.anthropic.com".into(),
        )]));
        let config = make_config(vec![secret]);
        let mut handler = SecretsHandler::new(&config, "api.anthropic.com", true);

        let input = b"GET / HTTP/1.1\r\nAuthorization: Bearer $KEY\r\n\r\n";
        let output = handler.substitute(input).unwrap();
        assert_eq!(&*output, input);
    }

    #[test]
    fn global_passthrough_action_forwards_disallowed_placeholder_unchanged() {
        let mut config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        config.on_violation = ViolationAction::Passthrough(vec![HostPattern::Any]);
        let mut handler = SecretsHandler::new(&config, "evil.com", true);

        let input = b"GET / HTTP/1.1\r\nAuthorization: Bearer $KEY\r\n\r\n";
        let output = handler.substitute(input).unwrap();
        assert_eq!(&*output, input);
    }

    #[test]
    fn passthrough_only_connection_has_no_handler_work() {
        let mut config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        config.on_violation = ViolationAction::Passthrough(vec![HostPattern::Any]);
        let handler = SecretsHandler::new(&config, "evil.com", true);

        assert!(handler.is_empty());
    }

    #[test]
    fn passthrough_host_does_not_allow_other_disallowed_placeholders() {
        let mut passthrough = make_secret("$PASSTHROUGH", "real-secret-a", "api.openai.com");
        passthrough.on_violation = Some(ViolationAction::Passthrough(vec![HostPattern::Exact(
            "api.anthropic.com".into(),
        )]));
        let blocked = make_secret("$BLOCKED", "real-secret-b", "api.github.com");
        let config = make_config(vec![passthrough, blocked]);
        let mut handler = SecretsHandler::new(&config, "api.anthropic.com", true);

        let input = b"GET / HTTP/1.1\r\nX-A: $PASSTHROUGH\r\nX-B: $BLOCKED\r\n\r\n";
        assert_eq!(
            handler.substitute(input).unwrap_err(),
            ViolationAction::Block
        );
    }

    #[test]
    fn per_secret_passthrough_blocks_for_non_matching_host() {
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.on_violation = Some(ViolationAction::Passthrough(vec![HostPattern::Exact(
            "api.anthropic.com".into(),
        )]));
        let config = make_config(vec![secret]);
        let mut handler = SecretsHandler::new(&config, "evil.com", true);

        let input = b"GET / HTTP/1.1\r\nAuthorization: Bearer $KEY\r\n\r\n";
        assert_eq!(
            handler.substitute(input).unwrap_err(),
            ViolationAction::BlockAndLog
        );
    }

    #[test]
    fn global_passthrough_blocks_for_non_matching_host() {
        let mut config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        config.on_violation =
            ViolationAction::Passthrough(vec![HostPattern::Exact("api.anthropic.com".into())]);
        let mut handler = SecretsHandler::new(&config, "evil.com", true);

        let input = b"GET / HTTP/1.1\r\nAuthorization: Bearer $KEY\r\n\r\n";
        assert_eq!(
            handler.substitute(input).unwrap_err(),
            ViolationAction::BlockAndLog
        );
    }

    #[test]
    fn global_block_and_terminate_marks_violation_as_terminating() {
        let mut config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        config.on_violation = ViolationAction::BlockAndTerminate;
        let mut handler = SecretsHandler::new(&config, "evil.com", true);

        let input = b"GET / HTTP/1.1\r\nAuthorization: Bearer $KEY\r\n\r\n";
        assert_eq!(
            handler.substitute(input).unwrap_err(),
            ViolationAction::BlockAndTerminate
        );
    }

    #[test]
    fn per_secret_block_and_terminate_marks_violation_as_terminating() {
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.on_violation = Some(ViolationAction::BlockAndTerminate);
        let config = make_config(vec![secret]);
        let mut handler = SecretsHandler::new(&config, "evil.com", true);

        let input = b"GET / HTTP/1.1\r\nAuthorization: Bearer $KEY\r\n\r\n";
        assert_eq!(
            handler.substitute(input).unwrap_err(),
            ViolationAction::BlockAndTerminate
        );
    }

    #[test]
    fn body_injection_disabled_by_default() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let input = b"POST / HTTP/1.1\r\nContent-Length: 15\r\n\r\n{\"key\": \"$KEY\"}";
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
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let input = b"POST / HTTP/1.1\r\nContent-Length: 15\r\n\r\n{\"key\": \"$KEY\"}";
        let output = handler.substitute(input).unwrap();
        assert_eq!(
            String::from_utf8(output.into_owned()).unwrap(),
            "POST / HTTP/1.1\r\nContent-Length: 22\r\n\r\n{\"key\": \"real-secret\"}"
        );
    }

    #[test]
    fn body_injection_updates_content_length() {
        let mut secret = make_secret("$KEY", "a]longer]secret]value", "api.openai.com");
        secret.injection.body = true;
        let config = make_config(vec![secret]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

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
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

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
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let input =
            b"GET / HTTP/1.1\r\nAuthorization: Bearer $KEY\r\nContent-Length: 5\r\n\r\nhello";
        let output = handler.substitute(input).unwrap();
        let result = String::from_utf8(output.into_owned()).unwrap();
        // Body unchanged, Content-Length should stay 5.
        assert!(result.contains("Content-Length: 5"));
        assert!(result.ends_with("hello"));
    }

    #[test]
    fn eligible_secret_preserves_binary_body_without_placeholder() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let body = vec![0x1f, 0x8b, 0x08, 0x00, 0xff, 0x00, 0x80, 0xfe];
        let mut input = format!(
            "POST /git-upload-pack HTTP/1.1\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        input.extend_from_slice(&body);

        let output = handler.substitute(&input).unwrap();
        assert_eq!(&*output, input.as_slice());
    }

    #[test]
    fn eligible_secret_preserves_binary_chunk_without_placeholder() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let input = [0x1f, 0x8b, 0x08, 0x00, 0xff, 0x00, 0x80, 0xfe];
        let output = handler.substitute(&input).unwrap();
        assert_eq!(&*output, input.as_slice());
    }

    #[test]
    fn body_injection_preserves_non_utf8_bytes() {
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.injection.body = true;
        let config = make_config(vec![secret]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let body = [0xff, b'$', b'K', b'E', b'Y', 0xfe];
        let mut input =
            format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        input.extend_from_slice(&body);

        let output = handler.substitute(&input).unwrap().into_owned();
        let expected_body = [b"\xffreal-secret".as_slice(), &[0xfe]].concat();
        let expected = [
            format!(
                "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
                expected_body.len()
            )
            .as_bytes(),
            expected_body.as_slice(),
        ]
        .concat();

        assert_eq!(output, expected);
    }

    #[test]
    fn no_secrets_passthrough() {
        let config = make_config(vec![]);
        let mut handler = SecretsHandler::new(&config, "anything.com", true);

        let input = b"GET / HTTP/1.1\r\n\r\n";
        let output = handler.substitute(input).unwrap();
        assert_eq!(&*output, input);
    }

    #[test]
    fn require_tls_identity_blocks_on_non_intercepted() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        // tls_intercepted = false — secret requires TLS identity
        let mut handler = SecretsHandler::new(&config, "api.openai.com", false);

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
    fn basic_auth_only_does_not_substitute_other_schemes() {
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.injection = basic_auth_only();
        let config = make_config(vec![secret]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        // basic_auth only handles Basic credentials; Bearer needs inject_headers.
        let input = b"GET / HTTP/1.1\r\nAuthorization: Bearer $KEY\r\nX-Custom: $KEY\r\n\r\n";
        let output = handler.substitute(input).unwrap();
        let result = String::from_utf8(output.into_owned()).unwrap();
        assert!(result.contains("Authorization: Bearer $KEY"));
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
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

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
        let mut handler = SecretsHandler::new(&config, "evil.com", true);

        let encoded = BASE64.encode(b"user:$MSB_PASSWORD");
        let input = format!("GET / HTTP/1.1\r\nAuthorization: Basic {encoded}\r\n\r\n");

        assert_eq!(
            handler.substitute(input.as_bytes()).unwrap_err(),
            ViolationAction::Block
        );
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
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

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
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let input = b"GET /api?key=$KEY HTTP/1.1\r\nHost: api.openai.com\r\n\r\n";
        let output = handler.substitute(input).unwrap();
        let result = String::from_utf8(output.into_owned()).unwrap();
        // Request line should be substituted.
        assert!(result.contains("GET /api?key=real-secret HTTP/1.1"));
        // Other headers should NOT be substituted.
    }

    #[test]
    fn url_encoded_placeholder_in_query_blocks_for_wrong_host() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler = SecretsHandler::new(&config, "evil.com", true);

        // `%24KEY` is the URL-encoded form of `$KEY`.
        let input = b"GET /api?token=%24KEY HTTP/1.1\r\nHost: evil.com\r\n\r\n";
        assert_eq!(
            handler.substitute(input).unwrap_err(),
            ViolationAction::Block
        );
    }

    #[test]
    fn url_encoded_placeholder_in_body_blocks_for_wrong_host() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler = SecretsHandler::new(&config, "evil.com", true);

        let input = b"POST / HTTP/1.1\r\nContent-Length: 13\r\n\r\nkey=%24KEY&x=1";
        assert_eq!(
            handler.substitute(input).unwrap_err(),
            ViolationAction::Block
        );
    }

    #[test]
    fn json_escaped_placeholder_in_body_blocks_for_wrong_host() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler = SecretsHandler::new(&config, "evil.com", true);

        // `$KEY` is the JSON unicode-escape form of `$KEY`.
        let input =
            b"POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"k\":\"\\u0024KEY\"}";
        assert_eq!(
            handler.substitute(input).unwrap_err(),
            ViolationAction::Block
        );
    }

    #[test]
    fn placeholder_split_across_writes_blocks_for_wrong_host() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler = SecretsHandler::new(&config, "evil.com", true);

        // Send the placeholder bytes across two separate substitute() calls.
        let first = b"GET / HTTP/1.1\r\nX-Token: $K";
        let second = b"EY\r\nHost: evil.com\r\n\r\n";

        // The first chunk doesn't contain the full placeholder, so it forwards.
        assert!(handler.substitute(first).is_ok());
        // The second chunk completes the placeholder when stitched with the tail.
        assert_eq!(
            handler.substitute(second).unwrap_err(),
            ViolationAction::Block
        );
    }

    #[test]
    fn url_decoded_contains_basic() {
        assert!(url_decoded_contains(b"foo%24KEYbar", b"$KEY"));
        assert!(!url_decoded_contains(b"fooKEYbar", b"$KEY"));
        // Invalid escapes pass through unchanged.
        assert!(url_decoded_contains(b"%2", b"%2"));
    }

    #[test]
    fn json_escaped_contains_basic() {
        assert!(json_escaped_contains(b"\"\\u0024KEY\"", b"$KEY"));
        assert!(json_escaped_contains(
            b"\\u0024\\u004B\\u0045\\u0059",
            b"$KEY"
        ));
        assert!(!json_escaped_contains(b"KEY", b"$KEY"));
    }

    #[test]
    fn body_in_separate_chunk_preserves_non_utf8_bytes() {
        // substitute() is called once per chunk from the TLS stream. A
        // single HTTP request can arrive as (headers) then (body) in
        // separate calls; the second call carries body bytes with no
        // `\r\n\r\n` boundary and must be recognised as body continuation,
        // not parsed as a fresh request.
        //
        // The body embeds a literal `$KEY` between non-UTF-8 bytes. Without
        // framing state the continuation chunk is parsed as headers,
        // `may_substitute_in_headers` finds the placeholder, the chunk is
        // lossy-decoded (mangling the surrounding bytes), and the
        // header-only secret leaks into the body.
        let config = make_config(vec![make_secret("$KEY", "real-secret", "example.com")]);
        let mut handler = SecretsHandler::new(&config, "example.com", true);

        // Chunk 1: headers only; Content-Length announces 13 body bytes.
        let chunk1 = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 13\r\n\r\n";
        handler.substitute(chunk1).unwrap();

        // Chunk 2: 13 body bytes, no boundary marker. `$KEY` sits between
        // 0xff / 0xfe bytes so misclassification corrupts both.
        let mut body: Vec<u8> = vec![0x00, 0x80, 0xc0, 0xff, 0xfe];
        body.extend_from_slice(b"$KEY");
        body.extend_from_slice(&[0x81, 0xc1, 0xee, 0xef]);
        assert_eq!(body.len(), 13);

        let out = handler.substitute(&body).unwrap();
        assert_eq!(out.as_ref(), body.as_slice());
    }

    #[test]
    fn body_split_across_two_chunks_round_trips() {
        // Body bytes arrive across two substitute() calls: the first chunk
        // carries headers + the first slice of body, the second chunk
        // carries the remainder. Both halves must pass through byte-for-byte
        // (the state machine decrements `remaining` correctly).
        //
        // The second chunk embeds a literal `$KEY` between non-UTF-8 bytes,
        // so a regression where continuation chunks fall back to the header
        // path both leaks the secret and clobbers the surrounding bytes.
        let config = make_config(vec![make_secret("$KEY", "real-secret", "example.com")]);
        let mut handler = SecretsHandler::new(&config, "example.com", true);

        let mut body: Vec<u8> = vec![0x00, 0x80, 0xc0, 0xff, 0xfe, 0xfd, 0xfc];
        body.extend_from_slice(b"$KEY");
        body.extend_from_slice(&[0x81, 0xc1, 0xee, 0xef]);
        assert_eq!(body.len(), 15);

        let mut chunk1 =
            b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 15\r\n\r\n".to_vec();
        chunk1.extend_from_slice(&body[..5]);

        let out1 = handler.substitute(&chunk1).unwrap();
        let boundary = out1
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|p| p + 4)
            .unwrap();
        assert_eq!(&out1[boundary..], &body[..5]);

        let out2 = handler.substitute(&body[5..]).unwrap();
        assert_eq!(out2.as_ref(), &body[5..]);
    }

    #[test]
    fn framing_state_resets_after_request_completes() {
        // Once a body has been fully forwarded, the next chunk must be
        // parsed as a fresh request — not continued as body. A regression
        // here would silently treat the next request line as body bytes.
        let config = make_config(vec![make_secret("$KEY", "real-secret", "example.com")]);
        let mut handler = SecretsHandler::new(&config, "example.com", true);

        let body: Vec<u8> = vec![0x00, 0x80, 0xc0, 0xff, 0xfe];
        let mut chunk1 =
            b"POST /a HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\n".to_vec();
        chunk1.extend_from_slice(&body);
        handler.substitute(&chunk1).unwrap();

        // Second request on the same connection. With state correctly reset
        // to AwaitingHeaders, this is parsed normally and forwarded.
        let chunk2 = b"GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let out2 = handler.substitute(chunk2).unwrap();
        assert_eq!(out2.as_ref(), chunk2.as_slice());
    }

    #[test]
    fn violation_detected_in_body_continuation_chunk() {
        // Placeholder bytes for a host that is not allowed to receive the
        // real secret arrive in a body-continuation chunk. The body-only
        // path must still run violation detection.
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler = SecretsHandler::new(&config, "evil.com", true);

        let chunk1 = b"POST /a HTTP/1.1\r\nHost: evil.com\r\nContent-Length: 16\r\n\r\n";
        handler.substitute(chunk1).unwrap();

        let chunk2 = b"prefix:$KEY:suffix";
        assert_eq!(
            handler.substitute(chunk2).unwrap_err(),
            ViolationAction::Block
        );
    }

    #[test]
    fn header_only_secret_does_not_leak_into_body_continuation_chunk() {
        // Security regression: a secret with the default injection scopes
        // (inject_headers=true, inject_body=false) must NOT substitute its
        // placeholder when the placeholder appears in body bytes. Without
        // the framing fix, a body-continuation chunk was parsed as headers
        // and run through `substitute_in_headers`, which replaces the
        // placeholder on every line — leaking the real secret value into a
        // request body the user explicitly opted out of injecting into.
        let config = make_config(vec![make_secret("$KEY", "real-secret", "example.com")]);
        let mut handler = SecretsHandler::new(&config, "example.com", true);

        // Chunk 1: headers only. Content-Length announces 24 body bytes.
        let chunk1 = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 24\r\n\r\n";
        handler.substitute(chunk1).unwrap();

        // Chunk 2: ASCII body containing a literal `$KEY` token. The
        // placeholder must be forwarded verbatim, never replaced with the
        // secret value.
        let body = b"prefix:$KEY:more-padding";
        assert_eq!(body.len(), 24);
        let out = handler.substitute(body).unwrap();
        assert_eq!(out.as_ref(), body.as_slice());
    }

    #[test]
    fn pipelined_request_in_body_continuation_chunk_is_substituted() {
        // HTTP/1.1 pipelining: request 1's body ends partway through chunk
        // 2 and request 2's headers follow in the same chunk. Without
        // recursion into the spillover, request 2's bytes are forwarded
        // verbatim as body and its substitutable placeholder never
        // reaches the substitution loop.
        let config = make_config(vec![make_secret("$KEY", "real-secret", "example.com")]);
        let mut handler = SecretsHandler::new(&config, "example.com", true);

        // Chunk 1: request 1 headers + 4 of 5 body bytes.
        let mut chunk1 =
            b"POST /a HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\n".to_vec();
        chunk1.extend_from_slice(b"abcd");
        handler.substitute(&chunk1).unwrap();

        // Chunk 2: last body byte, then a complete pipelined request with
        // `$KEY` in a header.
        let mut chunk2 = b"e".to_vec();
        chunk2.extend_from_slice(b"GET /b HTTP/1.1\r\nHost: example.com\r\nAuth: $KEY\r\n\r\n");

        let out = handler.substitute(&chunk2).unwrap();

        let mut expected = b"e".to_vec();
        expected.extend_from_slice(
            b"GET /b HTTP/1.1\r\nHost: example.com\r\nAuth: real-secret\r\n\r\n",
        );
        assert_eq!(out.as_ref(), expected.as_slice());
    }

    #[test]
    fn pipelined_request_in_same_chunk_as_headers_is_substituted() {
        // Headers-path pipelining: a single chunk carries request 1's
        // headers + complete body + the start of request 2. The header
        // parser must scope the body to Content-Length and recurse on
        // the trailing bytes; otherwise request 2's headers get treated
        // as request 1's body and no substitution runs.
        let config = make_config(vec![make_secret("$KEY", "real-secret", "example.com")]);
        let mut handler = SecretsHandler::new(&config, "example.com", true);

        let mut chunk =
            b"POST /a HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\n".to_vec();
        chunk.extend_from_slice(b"abcde");
        chunk.extend_from_slice(b"GET /b HTTP/1.1\r\nHost: example.com\r\nAuth: $KEY\r\n\r\n");

        let out = handler.substitute(&chunk).unwrap();

        let mut expected =
            b"POST /a HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\n".to_vec();
        expected.extend_from_slice(b"abcde");
        expected.extend_from_slice(
            b"GET /b HTTP/1.1\r\nHost: example.com\r\nAuth: real-secret\r\n\r\n",
        );
        assert_eq!(out.as_ref(), expected.as_slice());
    }

    #[test]
    fn three_pipelined_requests_in_one_chunk_all_substitute() {
        // Three pipelined requests in one chunk. The recursion nests
        // twice. Each request has a substitutable placeholder in a
        // header that must be replaced.
        let config = make_config(vec![make_secret("$KEY", "real-secret", "example.com")]);
        let mut handler = SecretsHandler::new(&config, "example.com", true);

        let r1 =
            b"POST /a HTTP/1.1\r\nHost: example.com\r\nAuth: $KEY\r\nContent-Length: 3\r\n\r\nbod";
        let r2 =
            b"PUT /b HTTP/1.1\r\nHost: example.com\r\nAuth: $KEY\r\nContent-Length: 2\r\n\r\nXY";
        let r3 = b"GET /c HTTP/1.1\r\nHost: example.com\r\nAuth: $KEY\r\n\r\n";
        let mut chunk = Vec::new();
        chunk.extend_from_slice(r1);
        chunk.extend_from_slice(r2);
        chunk.extend_from_slice(r3);

        let out = handler.substitute(&chunk).unwrap();

        let r1_out = b"POST /a HTTP/1.1\r\nHost: example.com\r\nAuth: real-secret\r\nContent-Length: 3\r\n\r\nbod";
        let r2_out = b"PUT /b HTTP/1.1\r\nHost: example.com\r\nAuth: real-secret\r\nContent-Length: 2\r\n\r\nXY";
        let r3_out = b"GET /c HTTP/1.1\r\nHost: example.com\r\nAuth: real-secret\r\n\r\n";
        let mut expected = Vec::new();
        expected.extend_from_slice(r1_out);
        expected.extend_from_slice(r2_out);
        expected.extend_from_slice(r3_out);

        assert_eq!(out.as_ref(), expected.as_slice());
    }

    #[test]
    fn pipelined_spillover_without_substitution_stays_zero_copy() {
        // No eligible secret matches this host; the chunk just needs to
        // be forwarded. Even with a pipelined boundary inside the chunk,
        // the output should be the original borrowed slice (no allocation).
        let config = make_config(vec![make_secret("$KEY", "real-secret", "other.com")]);
        let mut handler = SecretsHandler::new(&config, "example.com", true);

        let r1 = b"POST /a HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nbod";
        let r2 = b"GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut chunk = Vec::new();
        chunk.extend_from_slice(r1);
        chunk.extend_from_slice(r2);

        let out = handler.substitute(&chunk).unwrap();
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out.as_ref(), chunk.as_slice());
    }

    #[test]
    fn violation_in_pipelined_next_request_basic_auth_is_detected() {
        // Request 1's body ends in this chunk and request 2's headers
        // follow. Request 2 carries `Authorization: Basic <b64>` whose
        // decoded credentials contain a placeholder for a host that is
        // NOT allowed to receive the real secret. The base64 form
        // has no literal `$KEY` bytes, so the body-path byte scan
        // cannot see it. Only the recursive header pass decodes the
        // credentials and detects the violation.
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler = SecretsHandler::new(&config, "evil.com", true);

        let chunk1 = b"POST /a HTTP/1.1\r\nHost: evil.com\r\nContent-Length: 3\r\n\r\n";
        handler.substitute(chunk1).unwrap();

        // base64("admin:$KEY") = "YWRtaW46JEtFWQ==" - no literal `$KEY` in the
        // encoded form, so byte-level scanning over the body chunk misses it.
        let mut chunk2 = b"foo".to_vec();
        chunk2.extend_from_slice(
            b"POST /b HTTP/1.1\r\nHost: evil.com\r\nAuthorization: Basic YWRtaW46JEtFWQ==\r\n\r\n",
        );
        assert_eq!(
            handler.substitute(&chunk2).unwrap_err(),
            ViolationAction::Block
        );
    }

    #[test]
    fn pipelined_get_without_content_length_recurses_into_next_request() {
        // Per RFC 9112 §6.3 case 6, a request with no Content-Length and no
        // Transfer-Encoding has a zero-length body. Any trailing bytes are
        // the start of the next pipelined request, not body of this one.
        // A regression that treats them as body misses substitution and
        // violation detection for the entire rest of the connection.
        let config = make_config(vec![make_secret("$KEY", "real-secret", "example.com")]);
        let mut handler = SecretsHandler::new(&config, "example.com", true);

        let mut chunk = b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        chunk.extend_from_slice(b"GET /b HTTP/1.1\r\nHost: example.com\r\nAuth: $KEY\r\n\r\n");

        let out = handler.substitute(&chunk).unwrap();

        let mut expected = b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        expected.extend_from_slice(
            b"GET /b HTTP/1.1\r\nHost: example.com\r\nAuth: real-secret\r\n\r\n",
        );
        assert_eq!(out.as_ref(), expected.as_slice());
    }

    #[test]
    fn substitution_resumes_after_chunked_request_body_terminator() {
        // A chunked-encoded request must not poison the connection state.
        // After the chunked body terminator (`0\r\n\r\n`), the next bytes
        // are the start of a fresh request whose headers must be parsed
        // and substituted. A regression that stays in `InBody { None }`
        // forever misses every subsequent keep-alive request's headers.
        let config = make_config(vec![make_secret("$KEY", "real-secret", "example.com")]);
        let mut handler = SecretsHandler::new(&config, "example.com", true);

        // Chunk 1: request 1 headers with `Transfer-Encoding: chunked`.
        let chunk1 = b"POST /a HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n";
        handler.substitute(chunk1).unwrap();

        // Chunk 2: a 5-byte chunk (`hello`), the chunked terminator, then
        // a pipelined request with `$KEY` in a header.
        let mut chunk2 = b"5\r\nhello\r\n0\r\n\r\n".to_vec();
        chunk2.extend_from_slice(b"GET /b HTTP/1.1\r\nHost: example.com\r\nAuth: $KEY\r\n\r\n");

        let out = handler.substitute(&chunk2).unwrap();

        let mut expected = b"5\r\nhello\r\n0\r\n\r\n".to_vec();
        expected.extend_from_slice(
            b"GET /b HTTP/1.1\r\nHost: example.com\r\nAuth: real-secret\r\n\r\n",
        );
        assert_eq!(out.as_ref(), expected.as_slice());
    }
}
