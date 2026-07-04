//! Secret substitution handler for the TLS proxy.
//!
//! Scans decrypted plaintext for placeholder strings and replaces them
//! with real secret values, but only when the destination host is allowed.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use httlib_hpack::{Decoder as HpackDecoder, Encoder as HpackEncoder};
use percent_encoding::percent_decode;

use super::config::{
    HostPattern, MAX_SECRET_PLACEHOLDER_BYTES, SecretEntry, SecretsConfig, ViolationAction,
};
use crate::shared::SharedState;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum bytes to buffer while waiting for HTTP request headers.
const MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;

/// Maximum fixed-length HTTP body to buffer for body substitution.
const MAX_HTTP_BODY_BUFFER_BYTES: usize = 16 * 1024 * 1024;

/// HTTP/2 client connection preface.
const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Maximum HTTP/2 frame payload the handler buffers at once.
/// This is the largest value representable in the protocol's 24-bit
/// frame-length field.
const MAX_HTTP2_FRAME_PAYLOAD_BYTES: usize = 0x00ff_ffff;

/// Maximum accumulated HTTP/2 HPACK header block.
const MAX_HTTP2_HEADER_BLOCK_BYTES: usize = 64 * 1024;

/// Maximum decoded HTTP/2 header bytes accepted after HPACK expansion.
const MAX_HTTP2_DECODED_HEADER_BYTES: usize = 64 * 1024;

/// Maximum decoded HTTP/2 header fields accepted in one HEADERS block.
const MAX_HTTP2_HEADER_FIELDS: usize = 1024;

/// Maximum concurrently open HTTP/2 request streams tracked by the secret handler.
const MAX_HTTP2_TRACKED_STREAMS: usize = 1024;

/// Conservative outbound HTTP/2 frame payload size. This is the protocol
/// default and is valid even before seeing the upstream peer's SETTINGS.
const HTTP2_OUTBOUND_FRAME_PAYLOAD_BYTES: usize = 16 * 1024;

const HTTP2_FRAME_DATA: u8 = 0x0;
const HTTP2_FRAME_HEADERS: u8 = 0x1;
const HTTP2_FRAME_PUSH_PROMISE: u8 = 0x5;
const HTTP2_FRAME_CONTINUATION: u8 = 0x9;

const HTTP2_FLAG_END_STREAM: u8 = 0x1;
const HTTP2_FLAG_END_HEADERS: u8 = 0x4;
const HTTP2_FLAG_PADDED: u8 = 0x8;
const HTTP2_FLAG_PRIORITY: u8 = 0x20;

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
    /// TLS SNI this handler was created for.
    sni: String,
    /// Original guest destination for this connection.
    guest_dst: Option<SocketAddr>,
    /// Longest raw or encoded placeholder representation. Sizes the
    /// sliding-window tail used for cross-write violation detection.
    max_detection_window_len: usize,
    /// Longest active body-injection placeholder. Sizes the chunked body
    /// substitution carry window.
    max_body_placeholder_len: usize,
    /// True when any configured placeholder exceeds the supported bound.
    placeholder_limit_exceeded: bool,
    /// Trailing bytes carried over from the previous `substitute` call so a
    /// placeholder split across TCP writes still trips the violation check.
    /// Capped at `max_detection_window_len - 1` bytes.
    prev_tail: Vec<u8>,
    /// HTTP framing state for the request stream. Tracks whether the next
    /// chunk should be parsed as a request start (headers) or treated as a
    /// continuation of the current request's body.
    http_state: HttpState,
    /// SNI to require in HTTP/1 `Host` headers for DNS-pinned intercepted TLS.
    http_sni: Option<String>,
    /// Current HTTP/1 request metadata while processing body continuations.
    http1_request_summary: Option<RequestSummary>,
    /// Buffered HTTP bytes while waiting for complete headers or a complete
    /// body-rewriteable request.
    http_pending: Vec<u8>,
    /// Body-only tail for detecting eligible placeholders inside HTTP/1 bodies
    /// whose framing or encoding cannot be rewritten safely.
    unsupported_body_tail: Vec<u8>,
    /// HTTP/2 parser/rewriter state once an HTTP/2 preface is observed.
    http2_state: Option<Http2State>,
}

/// HTTP request framing state for the guest→server byte stream.
#[derive(Debug, Clone)]
enum HttpState {
    /// Scanning for the start of a request. The next `\r\n\r\n` ends headers.
    AwaitingHeaders,
    /// Inside a fixed-length request body. `remaining` is the number of body
    /// bytes left per Content-Length.
    InBody { remaining: usize },
    /// Inside a chunked request body.
    InChunkedBody { state: ChunkedBodyState },
    /// Inside a chunked request body that is being decoded and re-encoded so
    /// body placeholders can be substituted safely.
    InChunkedRewriteBody { state: ChunkedRewriteState },
    /// Buffering a fixed-length body so body substitution can update
    /// `Content-Length` against the complete rewritten request.
    BufferingBody { remaining: usize },
}

/// Stateful chunked transfer parser for request bodies.
#[derive(Debug, Clone, Default)]
struct ChunkedBodyState {
    phase: ChunkedPhase,
    line: Vec<u8>,
    decoded_tail: Vec<u8>,
}

/// Stateful chunked transfer rewriter for request bodies.
#[derive(Debug, Clone, Default)]
struct ChunkedRewriteState {
    parser: ChunkedBodyState,
    substitution_tail: Vec<u8>,
}

/// Stateful HTTP/2 client-to-server frame parser.
struct Http2State {
    preface_seen: bool,
    buffer: Vec<u8>,
    header_block: Option<Http2HeaderBlock>,
    open_request_streams: HashSet<u32>,
    data_tails: HashMap<u32, Vec<u8>>,
    request_summaries: HashMap<u32, RequestSummary>,
    decoder: HpackDecoder<'static>,
    encoder: HpackEncoder<'static>,
}

/// Accumulated HEADERS/CONTINUATION block for one stream.
struct Http2HeaderBlock {
    stream_id: u32,
    end_stream: bool,
    block: Vec<u8>,
}

/// Parsed HTTP/2 frame view.
struct Http2Frame<'a> {
    kind: u8,
    flags: u8,
    stream_id: u32,
    payload: &'a [u8],
    raw: &'a [u8],
}

type Http2Headers = Vec<(Vec<u8>, Vec<u8>)>;

/// Current chunked-body parser phase.
#[derive(Debug, Clone, Default)]
enum ChunkedPhase {
    /// Reading a chunk-size line.
    #[default]
    SizeLine,
    /// Reading exactly `remaining` chunk-data bytes.
    Data { remaining: usize },
    /// Reading the CRLF after chunk data.
    DataCrlf { seen_cr: bool },
    /// Reading trailer lines until the empty line.
    TrailerLine,
}

/// DNS-pinned destination identity for a proxied connection.
struct SecretHostIdentity<'a> {
    guest_ip: IpAddr,
    shared: &'a SharedState,
}

/// Parsed HTTP/1 request metadata needed for validation and framing.
struct HttpRequestMetadata {
    host_headers: Vec<String>,
}

/// HTTP request framing decision for a complete header block.
struct RequestFraming {
    state: HttpState,
    body_in_request: usize,
    body_substitution_allowed: bool,
}

/// Output from processing one chunked-body plaintext fragment.
struct ChunkedRewriteResult {
    output: Vec<u8>,
    body_end: Option<usize>,
}

/// Event emitted by the chunked transfer parser.
enum ChunkedBodyEvent<'a> {
    Payload(&'a [u8]),
    ZeroChunk,
    TrailerLine(&'a [u8]),
}

/// A secret that passed host matching for this connection.
struct EligibleSecret {
    placeholder: String,
    /// Resolved plaintext, wiped on drop so per-connection copies do not
    /// linger in freed memory.
    value: zeroize::Zeroizing<String>,
    inject_headers: bool,
    inject_basic_auth: bool,
    inject_query_params: bool,
    inject_body: bool,
    require_tls_identity: bool,
}

/// A secret that did not pass substitution or passthrough host matching.
struct IneligibleSecret {
    env_var: String,
    placeholder: String,
    action: BlockingAction,
}

/// Details about a blocked secret placeholder.
struct SecretViolationReport {
    action: BlockingAction,
    env_var: String,
    placeholder: String,
    protocol: RequestProtocol,
    location: RequestLocation,
    match_form: PlaceholderMatchForm,
    method: Option<String>,
    path: Option<String>,
    host: Option<String>,
    http2_stream_id: Option<u32>,
}

/// Minimal request metadata safe to include in violation logs.
#[derive(Clone, Default)]
struct RequestSummary {
    method: Option<String>,
    path: Option<String>,
    host: Option<String>,
}

/// Blocking action to take when an ineligible placeholder is detected.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum BlockingAction {
    Block,
    #[default]
    BlockAndLog,
    BlockAndTerminate,
}

/// Request protocol where a violation was detected.
#[derive(Debug, Clone, Copy)]
enum RequestProtocol {
    Http1,
    Http2,
}

/// Request location where a placeholder matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestLocation {
    Header,
    Query,
    BasicAuth,
    Body,
    Unknown,
}

/// Representation that matched the configured placeholder.
#[derive(Debug, Clone, Copy)]
enum PlaceholderMatchForm {
    Raw,
    PercentDecoded,
    JsonUnescaped,
    BasicAuthDecoded,
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
        if is_request_line {
            return self
                .inject_query_params
                .then(|| substitute_query_in_request_line(line, &self.placeholder, &self.value))
                .flatten();
        }

        if self.inject_basic_auth
            && is_authorization_header(line)
            && let Some(replaced) = self.substitute_basic_auth_header(line)
        {
            return Some(replaced);
        }
        if self.inject_headers {
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

impl fmt::Display for BlockingAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Block => "block",
            Self::BlockAndLog => "block-and-log",
            Self::BlockAndTerminate => "block-and-terminate",
        };
        f.write_str(value)
    }
}

impl fmt::Display for RequestProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Http1 => "http/1.1",
            Self::Http2 => "http/2",
        };
        f.write_str(value)
    }
}

impl fmt::Display for RequestLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Header => "header",
            Self::Query => "query",
            Self::BasicAuth => "authorization_basic",
            Self::Body => "body",
            Self::Unknown => "unknown",
        };
        f.write_str(value)
    }
}

impl fmt::Display for PlaceholderMatchForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Raw => "raw",
            Self::PercentDecoded => "percent_decoded",
            Self::JsonUnescaped => "json_unescaped",
            Self::BasicAuthDecoded => "basic_auth_decoded",
        };
        f.write_str(value)
    }
}

impl Default for Http2State {
    fn default() -> Self {
        Self {
            preface_seen: false,
            buffer: Vec::new(),
            header_block: None,
            open_request_streams: HashSet::new(),
            data_tails: HashMap::new(),
            request_summaries: HashMap::new(),
            decoder: HpackDecoder::with_dynamic_size(4096),
            encoder: HpackEncoder::with_dynamic_size(4096),
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
        Self::new_inner(config, sni, tls_intercepted, None, false, false)
    }

    /// Create a handler for a TLS-intercepted connection.
    ///
    /// Host-scoped secrets require both an SNI match and a DNS cache binding
    /// from the original guest destination IP to the allowed host.
    pub fn new_tls_intercepted(
        config: &SecretsConfig,
        sni: &str,
        guest_ip: IpAddr,
        shared: &SharedState,
    ) -> Self {
        Self::new_inner(
            config,
            sni,
            true,
            Some(SecretHostIdentity { guest_ip, shared }),
            true,
            false,
        )
    }

    /// TLS-intercepted handler for connections tunnelled via HTTP CONNECT.
    ///
    /// The SNI is authoritative: the proxy already verified it against the
    /// CONNECT authority, so no DNS-cache pin is required.
    pub(crate) fn new_tls_intercepted_via_connect(config: &SecretsConfig, sni: &str) -> Self {
        Self::new_inner(config, sni, true, None, true, false)
    }

    /// Create a handler for a plain-HTTP (non-TLS) connection.
    ///
    /// Only substitutes secrets that have opted in with `require_tls_identity(false)`.
    /// Host matching and DNS-cache binding are still enforced.
    pub fn new_plain_http(
        config: &SecretsConfig,
        host: &str,
        guest_ip: IpAddr,
        shared: &SharedState,
    ) -> Self {
        Self::new_inner(
            config,
            host,
            false,
            Some(SecretHostIdentity { guest_ip, shared }),
            true,
            false,
        )
    }

    /// Handler for a plain-HTTP connection with no usable Host header.
    ///
    /// The host can't be proven, so secrets are blocked unless every one is
    /// host-agnostic (`HostPattern::Any`) — only then is substitution safe.
    pub fn new_plain_http_invalid_host(config: &SecretsConfig) -> Self {
        let host_scoped = config
            .secrets
            .iter()
            .any(|secret| secret.allowed_hosts.iter().any(|h| *h != HostPattern::Any));

        Self::new_inner(config, "", false, None, false, host_scoped)
    }

    /// Handler for HTTP metadata that must never receive substituted secrets.
    ///
    /// This is used for proxy-owned CONNECT headers. Placeholders there are
    /// treated as violations according to their configured action unless a
    /// passthrough policy explicitly allows forwarding the placeholder.
    pub(crate) fn new_plain_http_untrusted_metadata(config: &SecretsConfig) -> Self {
        Self::new_inner(config, "", false, None, false, true)
    }

    fn new_inner(
        config: &SecretsConfig,
        sni: &str,
        tls_intercepted: bool,
        identity: Option<SecretHostIdentity<'_>>,
        enforce_http_authority: bool,
        force_ineligible: bool,
    ) -> Self {
        let mut eligible_for_substitution = Vec::new();
        let mut ineligible_for_substitution = Vec::new();
        let mut max_detection_window_len = 0;
        let mut max_body_placeholder_len = 0;
        let mut placeholder_limit_exceeded = false;

        for secret in &config.secrets {
            if secret.placeholder.len() > MAX_SECRET_PLACEHOLDER_BYTES {
                placeholder_limit_exceeded = true;
            }
            max_detection_window_len = max_detection_window_len.max(max_placeholder_detection_len(
                secret.placeholder.len().min(MAX_SECRET_PLACEHOLDER_BYTES),
            ));

            let host_allowed =
                !force_ineligible && secret_host_allowed(secret, sni, identity.as_ref());

            // If the SNI matches an allowed host for this secret, add it to the
            // eligible list for substitution, and skip violation checks for this secret.
            if host_allowed {
                if secret.injection.body {
                    max_body_placeholder_len = max_body_placeholder_len
                        .max(secret.placeholder.len().min(MAX_SECRET_PLACEHOLDER_BYTES));
                }
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

            let action = effective_violation_action(secret, config, sni, identity.as_ref());

            // Passthrough means the placeholder can be forwarded unchanged to this SNI.
            if let ViolationAction::Passthrough(hosts) = action
                && hosts
                    .iter()
                    .any(|p| host_pattern_allowed(p, sni, identity.as_ref()))
            {
                continue;
            }

            // Non-matching passthrough policies fall back to the default blocking action.
            ineligible_for_substitution.push(IneligibleSecret {
                env_var: secret.env_var.clone(),
                placeholder: secret.placeholder.clone(),
                action: BlockingAction::from_violation_action(action).unwrap_or_default(),
            });
        }

        Self {
            eligible_for_substitution,
            ineligible_for_substitution,
            tls_intercepted,
            sni: sni.to_string(),
            guest_dst: None,
            max_detection_window_len,
            max_body_placeholder_len,
            placeholder_limit_exceeded,
            prev_tail: Vec::new(),
            http_state: HttpState::AwaitingHeaders,
            http_sni: enforce_http_authority.then(|| sni.to_string()),
            http1_request_summary: None,
            http_pending: Vec::new(),
            unsupported_body_tail: Vec::new(),
            http2_state: None,
        }
    }

    /// Attach the original guest destination for structured violation logs.
    pub fn with_guest_dst(mut self, guest_dst: SocketAddr) -> Self {
        self.guest_dst = Some(guest_dst);
        self
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
        if self.placeholder_limit_exceeded {
            tracing::error!(
                "secret configuration rejected: placeholder exceeds {} bytes",
                MAX_SECRET_PLACEHOLDER_BYTES
            );
            return Err(ViolationAction::Block);
        }

        if self.http2_state.is_some() {
            return self.substitute_http2(data);
        }

        if self.http_pending.is_empty() {
            if has_complete_http2_preface(data) {
                self.http2_state = Some(Http2State::default());
                return self.substitute_http2(data);
            }
            if is_http2_preface_prefix(data) {
                self.http_pending.extend_from_slice(data);
                return Ok(Cow::Owned(Vec::new()));
            }
        } else {
            let mut pending_prefix = Vec::with_capacity(self.http_pending.len() + data.len());
            pending_prefix.extend_from_slice(&self.http_pending);
            pending_prefix.extend_from_slice(data);
            if has_complete_http2_preface(&pending_prefix) {
                self.http_pending.clear();
                self.http2_state = Some(Http2State::default());
                return self.substitute_http2(&pending_prefix);
            }
            if is_http2_preface_prefix(&pending_prefix) {
                self.http_pending = pending_prefix;
                return Ok(Cow::Owned(Vec::new()));
            }
        }

        match std::mem::replace(&mut self.http_state, HttpState::AwaitingHeaders) {
            HttpState::BufferingBody { remaining } => {
                return self.substitute_buffered_body(data, remaining);
            }
            HttpState::InBody { remaining } => {
                return self.substitute_body_chunk(data, remaining);
            }
            HttpState::InChunkedBody { state } => {
                return self.substitute_chunked_body_chunk(data, state);
            }
            HttpState::InChunkedRewriteBody { state } => {
                return self.substitute_chunked_rewrite_body_chunk(data, state);
            }
            HttpState::AwaitingHeaders => {}
        }

        if !self.http_pending.is_empty() {
            self.http_pending.extend_from_slice(data);
            if self.http_pending.len() > MAX_HTTP_HEADER_BYTES {
                return Err(ViolationAction::Block);
            }
            if find_header_boundary(&self.http_pending).is_none() {
                if first_line_is_not_http_request(&self.http_pending)
                    || !looks_like_http_request_prefix(&self.http_pending)
                {
                    let pending = std::mem::take(&mut self.http_pending);
                    let output = self.substitute_ready(&pending)?.into_owned();
                    return Ok(Cow::Owned(output));
                }
                return Ok(Cow::Owned(Vec::new()));
            }

            let pending = std::mem::take(&mut self.http_pending);
            let output = self.substitute_ready(&pending)?.into_owned();
            return Ok(Cow::Owned(output));
        }

        if find_header_boundary(data).is_none()
            && looks_like_http_request_prefix(data)
            && !first_line_is_not_http_request(data)
        {
            if data.len() > MAX_HTTP_HEADER_BYTES {
                return Err(ViolationAction::Block);
            }
            self.http_pending.extend_from_slice(data);
            return Ok(Cow::Owned(Vec::new()));
        }

        self.substitute_ready(data)
    }

    fn substitute_http2<'a>(&mut self, data: &[u8]) -> Result<Cow<'a, [u8]>, ViolationAction> {
        let mut state = self.http2_state.take().unwrap_or_default();
        let output = state.process(self, data)?;
        self.http2_state = Some(state);
        Ok(Cow::Owned(output))
    }

    fn substitute_ready<'a>(&mut self, data: &'a [u8]) -> Result<Cow<'a, [u8]>, ViolationAction> {
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
        let mut body_substitution_allowed = false;
        let (body_bytes, spillover) = if boundary.is_some() {
            let header_text = String::from_utf8_lossy(header_bytes);
            let request_summary = http1_request_summary(header_text.as_ref());
            if let Some(sni) = self.http_sni.as_deref()
                && let Some(metadata) = parse_http_request_metadata(header_bytes)?
                && !metadata
                    .host_headers
                    .iter()
                    .all(|host| authority_matches_sni(host, sni))
            {
                return Err(ViolationAction::Block);
            }

            if is_transfer_chunked(header_text.as_ref()) {
                return self.substitute_chunked_ready(
                    data,
                    header_bytes,
                    after_headers,
                    header_text.as_ref(),
                );
            }

            let framing = next_state_after_headers(header_text.as_ref(), after_headers)?;
            if self.needs_body_injection()
                && framing.body_substitution_allowed
                && content_length_exceeds_buffer_limit(header_text.as_ref())?
            {
                return Err(ViolationAction::Block);
            }
            if self.needs_body_injection()
                && framing.body_substitution_allowed
                && let HttpState::InBody { remaining } = &framing.state
            {
                self.http_pending.extend_from_slice(data);
                self.http1_request_summary = Some(request_summary);
                self.http_state = HttpState::BufferingBody {
                    remaining: *remaining,
                };
                return Ok(Cow::Owned(Vec::new()));
            }

            body_substitution_allowed = framing.body_substitution_allowed;
            self.http_state = framing.state;
            self.http1_request_summary = if matches!(self.http_state, HttpState::InBody { .. }) {
                Some(request_summary)
            } else {
                None
            };
            after_headers.split_at(framing.body_in_request)
        } else {
            (after_headers, &[] as &[u8])
        };

        // Everything from `data` belonging to this request, headers and body.
        let this_request = &data[..header_bytes.len() + body_bytes.len()];

        // Check for disallowed placeholders before forwarding or substituting data.
        self.apply_blocking_action(self.detect_blocking_action(
            this_request,
            String::from_utf8_lossy(header_bytes).as_ref(),
            RequestLocation::Unknown,
        ))?;
        if !body_substitution_allowed {
            self.block_unsupported_body_placeholder(&self.unsupported_body_tail, body_bytes)?;
            if matches!(self.http_state, HttpState::InBody { .. }) {
                update_tail_buffer(
                    &mut self.unsupported_body_tail,
                    body_bytes,
                    self.max_body_placeholder_len.saturating_sub(1),
                );
            } else {
                self.unsupported_body_tail.clear();
            }
        } else {
            self.unsupported_body_tail.clear();
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
            if body_substitution_allowed && secret.inject_body {
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

    fn substitute_buffered_body<'a>(
        &mut self,
        data: &'a [u8],
        remaining: usize,
    ) -> Result<Cow<'a, [u8]>, ViolationAction> {
        let take = remaining.min(data.len());
        self.http_pending.extend_from_slice(&data[..take]);

        if take < remaining {
            self.http_state = HttpState::BufferingBody {
                remaining: remaining - take,
            };
            return Ok(Cow::Owned(Vec::new()));
        }

        self.http_state = HttpState::AwaitingHeaders;
        let request = std::mem::take(&mut self.http_pending);
        let mut output = self.substitute_ready(&request)?.into_owned();

        if data.len() > take {
            let spillover = self.substitute(&data[take..])?;
            output.extend_from_slice(spillover.as_ref());
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

    /// Handle a chunked request whose headers are complete in `parent`.
    fn substitute_chunked_ready<'a>(
        &mut self,
        parent: &'a [u8],
        header_bytes: &'a [u8],
        after_headers: &'a [u8],
        headers: &str,
    ) -> Result<Cow<'a, [u8]>, ViolationAction> {
        if self.needs_body_injection() && !has_non_identity_content_encoding(headers) {
            return self.substitute_chunked_rewrite_ready(
                parent,
                header_bytes,
                after_headers,
                headers,
            );
        }

        let mut state = ChunkedBodyState::default();
        let body_end =
            self.consume_chunked_body_with_violation_detection(&mut state, after_headers)?;
        let (body_part, spillover) = match body_end {
            Some(end) => after_headers.split_at(end),
            None => (after_headers, &[] as &[u8]),
        };
        let this_request = &parent[..header_bytes.len() + body_part.len()];

        self.apply_blocking_action(self.detect_blocking_action(
            this_request,
            headers,
            RequestLocation::Unknown,
        ))?;
        self.update_tail(this_request);

        self.http_state = if body_end.is_some() {
            self.http1_request_summary = None;
            HttpState::AwaitingHeaders
        } else {
            self.http1_request_summary = Some(http1_request_summary(headers));
            HttpState::InChunkedBody { state }
        };

        if let Some(headers) = self.substitute_header_bytes(header_bytes) {
            let mut output = Vec::with_capacity(headers.len() + body_part.len() + spillover.len());
            output.extend_from_slice(headers.as_bytes());
            output.extend_from_slice(body_part);
            if !spillover.is_empty() {
                let next_out = self.substitute(spillover)?;
                output.extend_from_slice(next_out.as_ref());
            }
            return Ok(Cow::Owned(output));
        }

        self.append_pipelined_spillover(parent, this_request, spillover)
    }

    /// Handle a chunked request that needs body substitution.
    fn substitute_chunked_rewrite_ready<'a>(
        &mut self,
        parent: &'a [u8],
        header_bytes: &'a [u8],
        after_headers: &'a [u8],
        headers: &str,
    ) -> Result<Cow<'a, [u8]>, ViolationAction> {
        let mut state = ChunkedRewriteState::default();
        let rewrite = self.rewrite_chunked_body_part(&mut state, after_headers)?;
        let (body_part, spillover) = match rewrite.body_end {
            Some(end) => after_headers.split_at(end),
            None => (after_headers, &[] as &[u8]),
        };
        let this_request = &parent[..header_bytes.len() + body_part.len()];

        self.apply_blocking_action(self.detect_blocking_action(
            this_request,
            headers,
            RequestLocation::Unknown,
        ))?;
        self.update_tail(this_request);

        self.http_state = if rewrite.body_end.is_some() {
            self.http1_request_summary = None;
            HttpState::AwaitingHeaders
        } else {
            self.http1_request_summary = Some(http1_request_summary(headers));
            HttpState::InChunkedRewriteBody { state }
        };

        let header_len = header_bytes.len();
        let header_out = self.substitute_header_bytes(header_bytes);
        let mut output = Vec::with_capacity(
            header_out
                .as_ref()
                .map_or(header_len, |headers| headers.len())
                + rewrite.output.len()
                + spillover.len(),
        );
        if let Some(headers) = header_out {
            output.extend_from_slice(headers.as_bytes());
        } else {
            output.extend_from_slice(header_bytes);
        }
        output.extend_from_slice(&rewrite.output);

        if !spillover.is_empty() {
            let next_out = self.substitute(spillover)?;
            output.extend_from_slice(next_out.as_ref());
        }

        Ok(Cow::Owned(output))
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
        remaining: usize,
    ) -> Result<Cow<'a, [u8]>, ViolationAction> {
        // Determine where this request's body ends inside the chunk.
        //
        // Content-Length framing splits at `remaining`. Trailing bytes are a
        // pipelined next request.
        let body_end = (data.len() >= remaining).then_some(remaining);
        let (body_part, spillover) = match body_end {
            Some(end) => data.split_at(end),
            None => (data, &[] as &[u8]),
        };

        self.block_unsupported_body_placeholder(&self.unsupported_body_tail, body_part)?;
        self.apply_blocking_action(self.detect_blocking_action(
            body_part,
            "",
            RequestLocation::Body,
        ))?;
        self.update_tail(body_part);

        // Advance framing state. If the body completes within this chunk,
        // the spillover below is the start of a fresh request.
        self.http_state = match body_end {
            Some(_) => {
                self.http1_request_summary = None;
                self.unsupported_body_tail.clear();
                HttpState::AwaitingHeaders
            }
            None => {
                update_tail_buffer(
                    &mut self.unsupported_body_tail,
                    body_part,
                    self.max_body_placeholder_len.saturating_sub(1),
                );
                HttpState::InBody {
                    remaining: remaining - body_part.len(),
                }
            }
        };

        self.append_pipelined_spillover(data, body_part, spillover)
    }

    /// Handle continuation bytes for a chunked request body.
    fn substitute_chunked_body_chunk<'a>(
        &mut self,
        data: &'a [u8],
        mut state: ChunkedBodyState,
    ) -> Result<Cow<'a, [u8]>, ViolationAction> {
        let body_end = self.consume_chunked_body_with_violation_detection(&mut state, data)?;
        let (body_part, spillover) = match body_end {
            Some(end) => data.split_at(end),
            None => (data, &[] as &[u8]),
        };

        self.apply_blocking_action(self.detect_blocking_action(
            body_part,
            "",
            RequestLocation::Body,
        ))?;
        self.update_tail(body_part);

        self.http_state = if body_end.is_some() {
            self.http1_request_summary = None;
            HttpState::AwaitingHeaders
        } else {
            HttpState::InChunkedBody { state }
        };

        self.append_pipelined_spillover(data, body_part, spillover)
    }

    /// Handle continuation bytes for a chunked request body that is being
    /// decoded and re-encoded for body substitution.
    fn substitute_chunked_rewrite_body_chunk<'a>(
        &mut self,
        data: &'a [u8],
        mut state: ChunkedRewriteState,
    ) -> Result<Cow<'a, [u8]>, ViolationAction> {
        let rewrite = self.rewrite_chunked_body_part(&mut state, data)?;
        let (body_part, spillover) = match rewrite.body_end {
            Some(end) => data.split_at(end),
            None => (data, &[] as &[u8]),
        };

        self.apply_blocking_action(self.detect_blocking_action(
            body_part,
            "",
            RequestLocation::Body,
        ))?;
        self.update_tail(body_part);

        self.http_state = if rewrite.body_end.is_some() {
            self.http1_request_summary = None;
            HttpState::AwaitingHeaders
        } else {
            HttpState::InChunkedRewriteBody { state }
        };

        let mut output = rewrite.output;
        if !spillover.is_empty() {
            let next_out = self.substitute(spillover)?;
            output.extend_from_slice(next_out.as_ref());
        }

        Ok(Cow::Owned(output))
    }

    /// Returns true if this connection needs no secret substitution or violation detection.
    pub fn is_empty(&self) -> bool {
        self.http_sni.is_none()
            && self.http_pending.is_empty()
            && self.unsupported_body_tail.is_empty()
            && self.http1_request_summary.is_none()
            && self.http2_state.is_none()
            && matches!(self.http_state, HttpState::AwaitingHeaders)
            && self.eligible_for_substitution.is_empty()
            && self.ineligible_for_substitution.is_empty()
    }

    fn needs_body_injection(&self) -> bool {
        self.eligible_for_substitution.iter().any(|secret| {
            secret.inject_body && (!secret.require_tls_identity || self.tls_intercepted)
        })
    }

    fn block_unsupported_body_placeholder(
        &self,
        prev_tail: &[u8],
        data: &[u8],
    ) -> Result<(), ViolationAction> {
        if self.contains_eligible_body_placeholder(prev_tail, data) {
            tracing::warn!(
                "secret substitution in this request body is unsupported; blocking placeholder"
            );
            return Err(ViolationAction::Block);
        }
        Ok(())
    }

    fn contains_eligible_body_placeholder(&self, prev_tail: &[u8], data: &[u8]) -> bool {
        if !self.needs_body_injection() {
            return false;
        }

        let scan_buf: Cow<[u8]> = if prev_tail.is_empty() {
            Cow::Borrowed(data)
        } else {
            let mut stitched = Vec::with_capacity(prev_tail.len() + data.len());
            stitched.extend_from_slice(prev_tail);
            stitched.extend_from_slice(data);
            Cow::Owned(stitched)
        };
        let scan = scan_buf.as_ref();
        self.eligible_for_substitution.iter().any(|secret| {
            secret.inject_body
                && !secret.placeholder.is_empty()
                && (!secret.require_tls_identity || self.tls_intercepted)
                && contains_bytes(scan, secret.placeholder.as_bytes())
        })
    }

    fn substitute_http2_headers(&self, headers: &mut [(Vec<u8>, Vec<u8>)]) {
        for secret in &self.eligible_for_substitution {
            if secret.require_tls_identity && !self.tls_intercepted {
                continue;
            }

            for (name, value) in headers.iter_mut() {
                let is_pseudo = name.starts_with(b":");

                if name.eq_ignore_ascii_case(b":path")
                    && secret.inject_query_params
                    && let Ok(path) = std::str::from_utf8(value)
                    && let Some(replaced) =
                        substitute_query_in_target(path, &secret.placeholder, &secret.value)
                {
                    *value = replaced.into_bytes();
                }

                if !is_pseudo
                    && name.eq_ignore_ascii_case(b"authorization")
                    && secret.inject_basic_auth
                    && let Ok(header_value) = std::str::from_utf8(value)
                    && let Some(replaced) = substitute_basic_auth_value(
                        header_value,
                        &secret.placeholder,
                        &secret.value,
                    )
                {
                    *value = replaced.into_bytes();
                }

                if !is_pseudo
                    && secret.inject_headers
                    && contains_bytes(value, secret.placeholder.as_bytes())
                {
                    let replaced =
                        String::from_utf8_lossy(value).replace(&secret.placeholder, &secret.value);
                    *value = replaced.into_bytes();
                }
            }
        }
    }

    fn substitute_header_bytes(&self, header_bytes: &[u8]) -> Option<String> {
        let mut header_str: Option<String> = None;
        for secret in &self.eligible_for_substitution {
            if secret.require_tls_identity && !self.tls_intercepted {
                continue;
            }
            if secret.may_substitute_in_headers(header_bytes) {
                let current = header_str
                    .get_or_insert_with(|| String::from_utf8_lossy(header_bytes).into_owned());
                *current = secret.substitute_in_headers(current);
            }
        }

        header_str.filter(|headers| headers.as_bytes() != header_bytes)
    }

    fn consume_chunked_body_with_violation_detection(
        &self,
        state: &mut ChunkedBodyState,
        data: &[u8],
    ) -> Result<Option<usize>, ViolationAction> {
        let mut decoded_tail = std::mem::take(&mut state.decoded_tail);
        let body_end = process_chunked_body(state, data, |event| {
            let ChunkedBodyEvent::Payload(payload) = event else {
                return Ok(());
            };
            self.block_unsupported_body_placeholder(&decoded_tail, payload)?;
            self.apply_blocking_action(detect_blocking_action_with_tail(
                &self.ineligible_for_substitution,
                &decoded_tail,
                payload,
                "",
                RequestProtocol::Http1,
                RequestLocation::Body,
                None,
            ))?;
            update_tail_buffer(
                &mut decoded_tail,
                payload,
                self.max_detection_window_len.saturating_sub(1),
            );
            Ok(())
        });
        state.decoded_tail = decoded_tail;
        body_end
    }

    fn rewrite_chunked_body_part(
        &self,
        state: &mut ChunkedRewriteState,
        data: &[u8],
    ) -> Result<ChunkedRewriteResult, ViolationAction> {
        let mut output = Vec::new();
        let mut decoded_tail = std::mem::take(&mut state.parser.decoded_tail);
        let mut substitution_tail = std::mem::take(&mut state.substitution_tail);

        let body_end = process_chunked_body(&mut state.parser, data, |event| {
            match event {
                ChunkedBodyEvent::Payload(payload) => {
                    self.apply_blocking_action(detect_blocking_action_with_tail(
                        &self.ineligible_for_substitution,
                        &decoded_tail,
                        payload,
                        "",
                        RequestProtocol::Http1,
                        RequestLocation::Body,
                        None,
                    ))?;
                    update_tail_buffer(
                        &mut decoded_tail,
                        payload,
                        self.max_detection_window_len.saturating_sub(1),
                    );
                    self.append_rewritten_chunked_payload(
                        &mut substitution_tail,
                        payload,
                        &mut output,
                    );
                }
                ChunkedBodyEvent::ZeroChunk => {
                    self.flush_rewritten_chunked_payload(&mut substitution_tail, &mut output);
                    output.extend_from_slice(b"0\r\n");
                }
                ChunkedBodyEvent::TrailerLine(trailer_line) => {
                    output.extend_from_slice(trailer_line);
                }
            }
            Ok(())
        })?;

        state.parser.decoded_tail = decoded_tail;
        state.substitution_tail = substitution_tail;

        Ok(ChunkedRewriteResult { output, body_end })
    }

    fn append_rewritten_chunked_payload(
        &self,
        substitution_tail: &mut Vec<u8>,
        payload: &[u8],
        output: &mut Vec<u8>,
    ) {
        substitution_tail.extend_from_slice(payload);
        let carry_len = self.max_body_placeholder_len.saturating_sub(1);
        self.append_rewritten_chunked_prefix(substitution_tail, carry_len, output);
    }

    fn flush_rewritten_chunked_payload(
        &self,
        substitution_tail: &mut Vec<u8>,
        output: &mut Vec<u8>,
    ) {
        self.append_rewritten_chunked_prefix(substitution_tail, 0, output);
    }

    fn append_rewritten_chunked_prefix(
        &self,
        substitution_tail: &mut Vec<u8>,
        keep_len: usize,
        output: &mut Vec<u8>,
    ) {
        let safe_len = substitution_tail.len().saturating_sub(keep_len);
        if safe_len == 0 {
            return;
        }

        let mut cursor = 0;
        let mut chunk_payload = Vec::with_capacity(safe_len);
        while cursor < safe_len {
            if let Some(secret) = self.matching_body_secret_at(&substitution_tail[cursor..]) {
                chunk_payload.extend_from_slice(secret.value.as_bytes());
                cursor += secret.placeholder.len();
            } else {
                chunk_payload.push(substitution_tail[cursor]);
                cursor += 1;
            }
        }

        let kept = substitution_tail.split_off(cursor);
        *substitution_tail = kept;
        append_chunk(output, &chunk_payload);
    }

    fn matching_body_secret_at(&self, data: &[u8]) -> Option<&EligibleSecret> {
        self.eligible_for_substitution.iter().find(|secret| {
            secret.inject_body
                && !secret.placeholder.is_empty()
                && (!secret.require_tls_identity || self.tls_intercepted)
                && data.starts_with(secret.placeholder.as_bytes())
        })
    }

    fn apply_blocking_action(
        &self,
        report: Option<SecretViolationReport>,
    ) -> Result<(), ViolationAction> {
        let Some(report) = report else {
            return Ok(());
        };
        let action = report.action;
        self.log_violation(&report);
        Err(action.into_violation_action())
    }

    fn log_violation(&self, report: &SecretViolationReport) {
        if matches!(report.action, BlockingAction::Block) {
            return;
        }

        let host = report.host.as_deref().unwrap_or("");
        let method = report.method.as_deref().unwrap_or("");
        let path = report.path.as_deref().unwrap_or("");
        let guest_dst = self
            .guest_dst
            .map(|dst| dst.to_string())
            .unwrap_or_default();
        let http2_stream_id = report
            .http2_stream_id
            .map(|id| id.to_string())
            .unwrap_or_default();

        match report.action {
            BlockingAction::Block => {}
            BlockingAction::BlockAndLog => tracing::warn!(
                action = %report.action,
                secret_env_var = %report.env_var,
                placeholder = %report.placeholder,
                protocol = %report.protocol,
                sni = %self.sni,
                host = %host,
                method = %method,
                path = %path,
                location = %report.location,
                match_form = %report.match_form,
                guest_dst = %guest_dst,
                http2_stream_id = %http2_stream_id,
                "secret violation: placeholder detected for disallowed host"
            ),
            BlockingAction::BlockAndTerminate => tracing::error!(
                action = %report.action,
                secret_env_var = %report.env_var,
                placeholder = %report.placeholder,
                protocol = %report.protocol,
                sni = %self.sni,
                host = %host,
                method = %method,
                path = %path,
                location = %report.location,
                match_form = %report.match_form,
                guest_dst = %guest_dst,
                http2_stream_id = %http2_stream_id,
                "secret violation: placeholder detected for disallowed host - terminating"
            ),
        }
    }

    /// Returns the strongest blocking action for any placeholder appearing in data
    /// for a host that isn't allowed to receive either the real secret or the placeholder.
    ///
    /// Scans the raw bytes (stitched with the previous call's tail for
    /// cross-write detection), plus URL- and JSON-decoded variants for
    /// encoded-placeholder bypass attempts, plus base64-decoded Basic auth
    /// credentials.
    fn detect_blocking_action(
        &self,
        data: &[u8],
        headers: &str,
        location_hint: RequestLocation,
    ) -> Option<SecretViolationReport> {
        let mut report = detect_blocking_action_with_tail(
            &self.ineligible_for_substitution,
            &self.prev_tail,
            data,
            headers,
            RequestProtocol::Http1,
            location_hint,
            None,
        );
        if headers.is_empty()
            && let Some(report) = &mut report
            && let Some(summary) = &self.http1_request_summary
        {
            report.apply_request_summary(summary);
        }
        report
    }

    /// Update the sliding-window tail with the trailing bytes of `data`, so
    /// the next `substitute` call can detect placeholders split across the
    /// boundary.
    fn update_tail(&mut self, data: &[u8]) {
        update_tail_buffer(
            &mut self.prev_tail,
            data,
            self.max_detection_window_len.saturating_sub(1),
        );
    }
}

impl Http2State {
    fn process(
        &mut self,
        handler: &mut SecretsHandler,
        data: &[u8],
    ) -> Result<Vec<u8>, ViolationAction> {
        self.buffer.extend_from_slice(data);
        let mut output = Vec::new();

        if !self.preface_seen {
            if self.buffer.len() < HTTP2_PREFACE.len() {
                return Ok(output);
            }
            if !self.buffer.starts_with(HTTP2_PREFACE) {
                return Err(ViolationAction::Block);
            }
            output.extend_from_slice(HTTP2_PREFACE);
            self.buffer.drain(..HTTP2_PREFACE.len());
            self.preface_seen = true;
        }

        loop {
            if self.buffer.len() < 9 {
                break;
            }

            let frame_len = http2_frame_payload_len(&self.buffer[..9]);
            if frame_len > MAX_HTTP2_FRAME_PAYLOAD_BYTES {
                return Err(ViolationAction::Block);
            }
            let full_len = 9 + frame_len;
            if self.buffer.len() < full_len {
                break;
            }

            let frame = self.buffer[..full_len].to_vec();
            self.buffer.drain(..full_len);
            self.process_frame(handler, &frame, &mut output)?;
        }

        Ok(output)
    }

    fn process_frame(
        &mut self,
        handler: &mut SecretsHandler,
        raw: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<(), ViolationAction> {
        let frame = parse_http2_frame(raw)?;

        if self.header_block.is_some() && frame.kind != HTTP2_FRAME_CONTINUATION {
            return Err(ViolationAction::Block);
        }

        match frame.kind {
            HTTP2_FRAME_HEADERS => self.process_headers_frame(handler, frame, output),
            HTTP2_FRAME_CONTINUATION => self.process_continuation_frame(handler, frame, output),
            HTTP2_FRAME_DATA => self.process_data_frame(handler, frame, output),
            HTTP2_FRAME_PUSH_PROMISE => Err(ViolationAction::Block),
            _ => {
                output.extend_from_slice(frame.raw);
                Ok(())
            }
        }
    }

    fn process_headers_frame(
        &mut self,
        handler: &mut SecretsHandler,
        frame: Http2Frame<'_>,
        output: &mut Vec<u8>,
    ) -> Result<(), ViolationAction> {
        if frame.stream_id == 0 || frame.stream_id.is_multiple_of(2) || self.header_block.is_some()
        {
            return Err(ViolationAction::Block);
        }

        let fragment = http2_headers_fragment(frame.flags, frame.payload)?;
        if fragment.len() > MAX_HTTP2_HEADER_BLOCK_BYTES {
            return Err(ViolationAction::Block);
        }

        let block = Http2HeaderBlock {
            stream_id: frame.stream_id,
            end_stream: frame.flags & HTTP2_FLAG_END_STREAM != 0,
            block: fragment.to_vec(),
        };

        if frame.flags & HTTP2_FLAG_END_HEADERS != 0 {
            self.finish_header_block(handler, block, output)
        } else {
            self.header_block = Some(block);
            Ok(())
        }
    }

    fn process_continuation_frame(
        &mut self,
        handler: &mut SecretsHandler,
        frame: Http2Frame<'_>,
        output: &mut Vec<u8>,
    ) -> Result<(), ViolationAction> {
        let Some(mut block) = self.header_block.take() else {
            return Err(ViolationAction::Block);
        };
        if frame.stream_id == 0 || frame.stream_id != block.stream_id {
            return Err(ViolationAction::Block);
        }

        block.block.extend_from_slice(frame.payload);
        if block.block.len() > MAX_HTTP2_HEADER_BLOCK_BYTES {
            return Err(ViolationAction::Block);
        }

        if frame.flags & HTTP2_FLAG_END_HEADERS != 0 {
            self.finish_header_block(handler, block, output)
        } else {
            self.header_block = Some(block);
            Ok(())
        }
    }

    fn process_data_frame(
        &mut self,
        handler: &mut SecretsHandler,
        frame: Http2Frame<'_>,
        output: &mut Vec<u8>,
    ) -> Result<(), ViolationAction> {
        if frame.stream_id == 0 || !self.open_request_streams.contains(&frame.stream_id) {
            return Err(ViolationAction::Block);
        }

        let data = http2_data_payload(frame.flags, frame.payload)?;
        let tail = self.data_tails.entry(frame.stream_id).or_default();
        if handler.contains_eligible_body_placeholder(tail, data) {
            tracing::warn!(
                "secret substitution in HTTP/2 DATA frames is unsupported; blocking placeholder"
            );
            return Err(ViolationAction::Block);
        }
        let mut report = detect_blocking_action_with_tail(
            &handler.ineligible_for_substitution,
            tail,
            data,
            "",
            RequestProtocol::Http2,
            RequestLocation::Body,
            Some(frame.stream_id),
        );
        if let Some(report) = &mut report
            && let Some(summary) = self.request_summaries.get(&frame.stream_id)
        {
            report.apply_request_summary(summary);
        }
        handler.apply_blocking_action(report)?;
        update_tail_buffer(
            tail,
            data,
            handler.max_detection_window_len.saturating_sub(1),
        );
        if frame.flags & HTTP2_FLAG_END_STREAM != 0 {
            self.data_tails.remove(&frame.stream_id);
            self.open_request_streams.remove(&frame.stream_id);
            self.request_summaries.remove(&frame.stream_id);
        }
        output.extend_from_slice(frame.raw);
        Ok(())
    }

    fn finish_header_block(
        &mut self,
        handler: &mut SecretsHandler,
        block: Http2HeaderBlock,
        output: &mut Vec<u8>,
    ) -> Result<(), ViolationAction> {
        let mut headers = self.decode_headers(&block.block)?;
        let is_initial_request = !self.open_request_streams.contains(&block.stream_id);
        if is_initial_request {
            if self.open_request_streams.len() >= MAX_HTTP2_TRACKED_STREAMS {
                return Err(ViolationAction::Block);
            }
            self.open_request_streams.insert(block.stream_id);
        } else if !block.end_stream {
            return Err(ViolationAction::Block);
        }

        if let Some(sni) = handler.http_sni.as_deref() {
            validate_http2_authority(&headers, sni, is_initial_request)?;
        }

        let detection_bytes = http2_header_detection_bytes(&headers);
        let detection_text = String::from_utf8_lossy(&detection_bytes);
        let request_summary = http2_request_summary(detection_text.as_ref());
        handler.apply_blocking_action(detect_blocking_action_with_tail(
            &handler.ineligible_for_substitution,
            &[],
            &detection_bytes,
            detection_text.as_ref(),
            RequestProtocol::Http2,
            RequestLocation::Header,
            Some(block.stream_id),
        ))?;

        handler.substitute_http2_headers(&mut headers);
        let encoded = self.encode_headers(&headers)?;
        append_http2_header_frames(output, block.stream_id, block.end_stream, &encoded)?;
        if block.end_stream {
            self.data_tails.remove(&block.stream_id);
            self.open_request_streams.remove(&block.stream_id);
            self.request_summaries.remove(&block.stream_id);
        } else {
            self.request_summaries
                .insert(block.stream_id, request_summary);
        }
        Ok(())
    }

    fn decode_headers(&mut self, block: &[u8]) -> Result<Http2Headers, ViolationAction> {
        let mut block = block.to_vec();
        let mut headers = Vec::new();
        let mut decoded_bytes = 0usize;

        while !block.is_empty() {
            let before_len = block.len();
            let mut decoded = Vec::with_capacity(1);
            self.decoder
                .decode_exact(&mut block, &mut decoded)
                .map_err(|_| ViolationAction::Block)?;
            if decoded.is_empty() {
                if block.len() == before_len {
                    return Err(ViolationAction::Block);
                }
                continue;
            }

            if headers.len() >= MAX_HTTP2_HEADER_FIELDS {
                return Err(ViolationAction::Block);
            }
            let (name, value, _flags) = decoded.pop().expect("decoded one header");
            decoded_bytes = decoded_bytes
                .checked_add(name.len())
                .and_then(|len| len.checked_add(value.len()))
                .and_then(|len| len.checked_add(4))
                .ok_or(ViolationAction::Block)?;
            if decoded_bytes > MAX_HTTP2_DECODED_HEADER_BYTES {
                return Err(ViolationAction::Block);
            }

            headers.push((name, value));
        }

        Ok(headers)
    }

    fn encode_headers(
        &mut self,
        headers: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<Vec<u8>, ViolationAction> {
        let mut encoded = Vec::new();
        for (name, value) in headers {
            self.encoder
                .encode(
                    (name.clone(), value.clone(), HpackEncoder::NEVER_INDEXED),
                    &mut encoded,
                )
                .map_err(|_| ViolationAction::Block)?;
        }
        Ok(encoded)
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

fn is_http2_preface_prefix(data: &[u8]) -> bool {
    !data.is_empty()
        && if data.len() <= HTTP2_PREFACE.len() {
            HTTP2_PREFACE.starts_with(data)
        } else {
            data.starts_with(HTTP2_PREFACE)
        }
}

fn has_complete_http2_preface(data: &[u8]) -> bool {
    data.len() >= HTTP2_PREFACE.len() && data.starts_with(HTTP2_PREFACE)
}

fn http2_frame_payload_len(header: &[u8]) -> usize {
    ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize
}

fn parse_http2_frame(raw: &[u8]) -> Result<Http2Frame<'_>, ViolationAction> {
    if raw.len() < 9 {
        return Err(ViolationAction::Block);
    }
    let len = http2_frame_payload_len(raw);
    if raw.len() != 9 + len {
        return Err(ViolationAction::Block);
    }

    let stream_id = u32::from_be_bytes([raw[5], raw[6], raw[7], raw[8]]) & 0x7fff_ffff;
    Ok(Http2Frame {
        kind: raw[3],
        flags: raw[4],
        stream_id,
        payload: &raw[9..],
        raw,
    })
}

fn http2_headers_fragment(flags: u8, payload: &[u8]) -> Result<&[u8], ViolationAction> {
    let mut start = 0;
    let pad_len = if flags & HTTP2_FLAG_PADDED != 0 {
        let Some(pad_len) = payload.first() else {
            return Err(ViolationAction::Block);
        };
        start = 1;
        *pad_len as usize
    } else {
        0
    };

    if flags & HTTP2_FLAG_PRIORITY != 0 {
        start += 5;
    }
    if payload.len() < start + pad_len {
        return Err(ViolationAction::Block);
    }

    Ok(&payload[start..payload.len() - pad_len])
}

fn http2_data_payload(flags: u8, payload: &[u8]) -> Result<&[u8], ViolationAction> {
    if flags & HTTP2_FLAG_PADDED == 0 {
        return Ok(payload);
    }

    let Some(pad_len) = payload.first() else {
        return Err(ViolationAction::Block);
    };
    let pad_len = *pad_len as usize;
    if payload.len() < 1 + pad_len {
        return Err(ViolationAction::Block);
    }

    Ok(&payload[1..payload.len() - pad_len])
}

fn append_http2_header_frames(
    output: &mut Vec<u8>,
    stream_id: u32,
    end_stream: bool,
    block: &[u8],
) -> Result<(), ViolationAction> {
    let mut first = true;
    let mut offset = 0;

    while first || offset < block.len() {
        let remaining = block.len().saturating_sub(offset);
        let take = remaining.min(HTTP2_OUTBOUND_FRAME_PAYLOAD_BYTES);
        let payload = &block[offset..offset + take];
        offset += take;

        let kind = if first {
            HTTP2_FRAME_HEADERS
        } else {
            HTTP2_FRAME_CONTINUATION
        };
        let mut flags = 0;
        if offset == block.len() {
            flags |= HTTP2_FLAG_END_HEADERS;
        }
        if first && end_stream {
            flags |= HTTP2_FLAG_END_STREAM;
        }

        append_http2_frame(output, kind, flags, stream_id, payload)?;
        first = false;
    }

    Ok(())
}

fn append_http2_frame(
    output: &mut Vec<u8>,
    kind: u8,
    flags: u8,
    stream_id: u32,
    payload: &[u8],
) -> Result<(), ViolationAction> {
    if payload.len() > 0x00ff_ffff || stream_id & 0x8000_0000 != 0 {
        return Err(ViolationAction::Block);
    }

    output.push(((payload.len() >> 16) & 0xff) as u8);
    output.push(((payload.len() >> 8) & 0xff) as u8);
    output.push((payload.len() & 0xff) as u8);
    output.push(kind);
    output.push(flags);
    output.extend_from_slice(&stream_id.to_be_bytes());
    output.extend_from_slice(payload);
    Ok(())
}

fn validate_http2_authority(
    headers: &[(Vec<u8>, Vec<u8>)],
    sni: &str,
    require_authority: bool,
) -> Result<(), ViolationAction> {
    let mut authority_count = 0usize;

    for (name, value) in headers {
        if name.eq_ignore_ascii_case(b":authority") {
            authority_count += 1;
            let authority = String::from_utf8_lossy(value);
            if !authority_matches_sni(authority.as_ref(), sni) {
                return Err(ViolationAction::Block);
            }
        } else if name.eq_ignore_ascii_case(b"host") {
            let host = String::from_utf8_lossy(value);
            if !authority_matches_sni(host.as_ref(), sni) {
                return Err(ViolationAction::Block);
            }
        }
    }

    if require_authority && authority_count != 1 {
        return Err(ViolationAction::Block);
    }

    Ok(())
}

fn http2_header_detection_bytes(headers: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let len = headers
        .iter()
        .map(|(name, value)| name.len() + value.len() + 4)
        .sum();
    let mut out = Vec::with_capacity(len);
    for (name, value) in headers {
        out.extend_from_slice(name);
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
    out
}

fn parse_http_request_metadata(
    header_bytes: &[u8],
) -> Result<Option<HttpRequestMetadata>, ViolationAction> {
    let headers = String::from_utf8_lossy(header_bytes);
    let mut lines = headers.split("\r\n");
    let Some(request_line) = lines.next() else {
        return Ok(None);
    };
    if request_line.is_empty() {
        return Ok(None);
    }

    let Some(version) = http_request_version(request_line) else {
        return Ok(None);
    };
    if version == "HTTP/2.0" {
        return Err(ViolationAction::Block);
    }
    if !version.starts_with("HTTP/1.") {
        return Ok(None);
    }

    let mut host_headers = Vec::new();
    for line in lines.take_while(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();

        if name.eq_ignore_ascii_case("host") {
            host_headers.push(value.to_string());
        }
    }

    if host_headers.is_empty() {
        return Err(ViolationAction::Block);
    }

    Ok(Some(HttpRequestMetadata { host_headers }))
}

fn http_request_version(request_line: &str) -> Option<&str> {
    split_http_request_line(request_line).map(|(_, _, version)| version)
}

fn split_http_request_line(request_line: &str) -> Option<(&str, &str, &str)> {
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some() || !method.bytes().all(is_http_token_byte) {
        return None;
    }
    Some((method, target, version))
}

fn redacted_request_path(target: &str) -> String {
    let without_query = target.split_once('?').map_or(target, |(path, _)| path);
    if let Some(scheme_end) = without_query.find("://") {
        let after_scheme = &without_query[scheme_end + 3..];
        if let Some(path_start) = after_scheme.find('/') {
            return after_scheme[path_start..].to_string();
        }
        return "/".to_string();
    }
    without_query.to_string()
}

fn request_summary(headers: &str, protocol: RequestProtocol) -> RequestSummary {
    match protocol {
        RequestProtocol::Http1 => http1_request_summary(headers),
        RequestProtocol::Http2 => http2_request_summary(headers),
    }
}

fn http1_request_summary(headers: &str) -> RequestSummary {
    let mut lines = headers.split("\r\n");
    let Some(request_line) = lines.next() else {
        return RequestSummary::default();
    };
    let Some((method, target, _version)) = split_http_request_line(request_line) else {
        return RequestSummary::default();
    };

    let host = lines
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .find_map(|(name, value)| name.eq_ignore_ascii_case("host").then(|| value.trim()));

    RequestSummary {
        method: Some(method.to_string()),
        path: Some(redacted_request_path(target)),
        host: host.map(ToOwned::to_owned),
    }
}

fn http2_request_summary(headers: &str) -> RequestSummary {
    let mut summary = RequestSummary::default();
    for line in headers.split("\r\n").filter(|line| !line.is_empty()) {
        if let Some(value) = line.strip_prefix(":method: ") {
            summary.method = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix(":path: ") {
            summary.path = Some(redacted_request_path(value));
        } else if let Some(value) = line.strip_prefix(":authority: ") {
            summary.host = Some(value.trim().to_string());
        }
    }
    summary
}

pub(crate) fn looks_like_http_request_prefix(data: &[u8]) -> bool {
    if data.is_empty() || b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".starts_with(data) {
        return true;
    }

    let method_end = data.iter().position(|b| *b == b' ');
    let method = match method_end {
        Some(end) => &data[..end],
        None => data,
    };

    !method.is_empty() && method.iter().copied().all(is_http_token_byte)
}

pub(crate) fn first_line_is_not_http_request(data: &[u8]) -> bool {
    let Some(line_end) = data.windows(2).position(|window| window == b"\r\n") else {
        return false;
    };
    let line = String::from_utf8_lossy(&data[..line_end]);
    http_request_version(line.as_ref()).is_none()
}

fn is_http_token_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
            | b'0'..=b'9'
            | b'A'..=b'Z'
            | b'a'..=b'z'
    )
}

fn authority_matches_sni(authority: &str, sni: &str) -> bool {
    authority_hostname(authority)
        .is_some_and(|hostname| hostname.eq_ignore_ascii_case(sni.trim_end_matches('.')))
}

fn authority_hostname(authority: &str) -> Option<&str> {
    let authority = authority.trim().trim_end_matches('.');
    if authority.is_empty() {
        return None;
    }

    if let Some(rest) = authority.strip_prefix('[') {
        let (host, _port) = rest.split_once(']')?;
        return Some(host.trim_end_matches('.'));
    }

    match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && port.parse::<u16>().is_ok() => {
            Some(host.trim_end_matches('.'))
        }
        _ => Some(authority),
    }
}

fn secret_host_allowed(
    secret: &SecretEntry,
    sni: &str,
    identity: Option<&SecretHostIdentity<'_>>,
) -> bool {
    secret
        .allowed_hosts
        .iter()
        .any(|pattern| host_pattern_allowed(pattern, sni, identity))
}

fn host_pattern_allowed(
    pattern: &HostPattern,
    sni: &str,
    identity: Option<&SecretHostIdentity<'_>>,
) -> bool {
    if !pattern.matches(sni) {
        return false;
    }
    if matches!(pattern, HostPattern::Any) {
        return true;
    }
    let Some(identity) = identity else {
        return true;
    };

    host_alias_matches(pattern, sni, identity)
        || identity
            .shared
            .any_resolved_hostname(identity.guest_ip, |hostname| pattern.matches(hostname))
}

fn host_alias_matches(pattern: &HostPattern, sni: &str, identity: &SecretHostIdentity<'_>) -> bool {
    if !sni.eq_ignore_ascii_case(crate::HOST_ALIAS) || !pattern.matches(crate::HOST_ALIAS) {
        return false;
    }

    identity
        .shared
        .gateway_ipv4()
        .is_some_and(|ip| identity.guest_ip == IpAddr::V4(ip))
        || identity
            .shared
            .gateway_ipv6()
            .is_some_and(|ip| identity.guest_ip == IpAddr::V6(ip))
}

fn effective_violation_action<'a>(
    secret: &'a SecretEntry,
    config: &'a SecretsConfig,
    sni: &str,
    identity: Option<&SecretHostIdentity<'_>>,
) -> &'a ViolationAction {
    match &secret.on_violation {
        Some(ViolationAction::Passthrough(hosts))
            if !hosts
                .iter()
                .any(|pattern| host_pattern_allowed(pattern, sni, identity)) =>
        {
            &config.on_violation
        }
        Some(action) => action,
        None => &config.on_violation,
    }
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

fn substitute_query_in_request_line(line: &str, placeholder: &str, value: &str) -> Option<String> {
    if placeholder.is_empty() {
        return None;
    }

    let method_end = line.find(' ')?;
    let target_start = method_end + 1;
    let version_start = line[target_start..].rfind(' ')? + target_start;
    if version_start <= target_start {
        return None;
    }

    let target = &line[target_start..version_start];
    let query_start = target.find('?')? + 1;
    let query = &target[query_start..];
    if !query.contains(placeholder) {
        return None;
    }

    let mut result = String::with_capacity(line.len());
    result.push_str(&line[..target_start + query_start]);
    result.push_str(&query.replace(placeholder, value));
    result.push_str(&line[version_start..]);
    Some(result)
}

fn substitute_query_in_target(target: &str, placeholder: &str, value: &str) -> Option<String> {
    if placeholder.is_empty() {
        return None;
    }

    let query_start = target.find('?')? + 1;
    let query = &target[query_start..];
    if !query.contains(placeholder) {
        return None;
    }

    let mut result = String::with_capacity(target.len());
    result.push_str(&target[..query_start]);
    result.push_str(&query.replace(placeholder, value));
    Some(result)
}

fn substitute_basic_auth_value(
    header_value: &str,
    placeholder: &str,
    value: &str,
) -> Option<String> {
    let (scheme, encoded) = split_auth_scheme(header_value.trim_start())?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let bytes = BASE64.decode(encoded.trim()).ok()?;
    let decoded = String::from_utf8(bytes).ok()?;
    if !decoded.contains(placeholder) {
        return None;
    }
    let replaced = decoded.replace(placeholder, value);
    Some(format!("Basic {}", BASE64.encode(replaced.as_bytes())))
}

/// Returns true if any `Authorization: Basic` line in `headers` decodes to
/// credentials containing `placeholder`.
fn basic_auth_decoded_contains(headers: &str, placeholder: &str) -> bool {
    decoded_basic_auth_credentials(headers)
        .iter()
        .any(|decoded| decoded.contains(placeholder))
}

/// Decode all Basic authorization credentials in an HTTP header block.
fn decoded_basic_auth_credentials(headers: &str) -> Vec<String> {
    headers
        .split("\r\n")
        .filter(|line| is_authorization_header(line))
        .filter_map(decode_basic_credentials)
        .collect()
}

/// Byte-slice substring check.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Longest representation the violation detector may need to carry across
/// write boundaries for a placeholder. Percent encoding can expand one byte
/// to `%XX`; JSON unicode escaping can expand one byte to `\u00XX`.
fn max_placeholder_detection_len(placeholder_len: usize) -> usize {
    placeholder_len.saturating_mul(6)
}

/// Compute the framing state for the next chunk and how many of the
/// post-boundary bytes belong to THIS request's body. `body_in_chunk` is
/// the number of bytes that followed `\r\n\r\n` in this chunk; the
/// returned `body_in_request` is at most `body_in_chunk`, and any
/// remaining bytes are spillover from a pipelined next request.
fn next_state_after_headers(
    headers: &str,
    body_bytes: &[u8],
) -> Result<RequestFraming, ViolationAction> {
    let body_in_chunk = body_bytes.len();
    let body_substitution_allowed = !has_non_identity_content_encoding(headers);
    if is_transfer_chunked(headers) {
        let mut chunked_state = ChunkedBodyState::default();
        let (state, body_in_request) = match consume_chunked_body(&mut chunked_state, body_bytes)? {
            Some(end) => (HttpState::AwaitingHeaders, end),
            _ => (
                HttpState::InChunkedBody {
                    state: chunked_state,
                },
                body_in_chunk,
            ),
        };
        return Ok(RequestFraming {
            state,
            body_in_request,
            body_substitution_allowed: false,
        });
    }
    match parse_content_length(headers)? {
        Some(cl) if body_in_chunk >= cl => Ok(RequestFraming {
            state: HttpState::AwaitingHeaders,
            body_in_request: cl,
            body_substitution_allowed,
        }),
        Some(cl) => Ok(RequestFraming {
            state: HttpState::InBody {
                remaining: cl - body_in_chunk,
            },
            body_in_request: body_in_chunk,
            body_substitution_allowed,
        }),
        // Per RFC 9112 §6.3 case 6, a request with neither `Content-Length`
        // nor `Transfer-Encoding` has a zero-length body. Any trailing
        // bytes are the start of a pipelined next request.
        None => Ok(RequestFraming {
            state: HttpState::AwaitingHeaders,
            body_in_request: 0,
            body_substitution_allowed: false,
        }),
    }
}

/// Parse a `Content-Length:` value from the headers block. Case-insensitive
/// header name match; rejects malformed or conflicting values.
fn parse_content_length(headers: &str) -> Result<Option<usize>, ViolationAction> {
    let mut content_length = None;
    for line in headers.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            let parsed = value
                .trim()
                .parse::<usize>()
                .map_err(|_| ViolationAction::Block)?;
            if content_length.is_some_and(|existing| existing != parsed) {
                return Err(ViolationAction::Block);
            }
            content_length = Some(parsed);
        }
    }
    Ok(content_length)
}

fn content_length_exceeds_buffer_limit(headers: &str) -> Result<bool, ViolationAction> {
    Ok(parse_content_length(headers)?.is_some_and(|len| len > MAX_HTTP_BODY_BUFFER_BYTES))
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

/// True when the request body is encoded and cannot be rewritten byte-for-byte.
fn has_non_identity_content_encoding(headers: &str) -> bool {
    for line in headers.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.eq_ignore_ascii_case("content-encoding") {
            continue;
        }
        if value
            .split(',')
            .any(|encoding| !encoding.trim().eq_ignore_ascii_case("identity"))
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
#[cfg(test)]
fn url_decoded_contains(haystack: &[u8], needle: &[u8]) -> bool {
    let decoded: Vec<u8> = percent_decode(haystack).collect();
    contains_bytes(&decoded, needle)
}

/// Returns true if `haystack`, after JSON `\uXXXX` decoding, contains `needle`.
/// Only `\uXXXX` escapes are expanded (sufficient to detect ASCII placeholders
/// hidden via unicode escapes); other JSON escapes pass through.
#[cfg(test)]
fn json_escaped_contains(haystack: &[u8], needle: &[u8]) -> bool {
    let decoded = json_unescape(haystack);
    contains_bytes(&decoded, needle)
}

/// Decode JSON `\uXXXX` escapes in a byte slice.
fn json_unescape(haystack: &[u8]) -> Vec<u8> {
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
    decoded
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

fn append_chunk(output: &mut Vec<u8>, payload: &[u8]) {
    if payload.is_empty() {
        return;
    }
    output.extend_from_slice(format!("{:X}\r\n", payload.len()).as_bytes());
    output.extend_from_slice(payload);
    output.extend_from_slice(b"\r\n");
}

fn detect_blocking_action_with_tail(
    ineligible_for_substitution: &[IneligibleSecret],
    prev_tail: &[u8],
    data: &[u8],
    headers: &str,
    protocol: RequestProtocol,
    location_hint: RequestLocation,
    http2_stream_id: Option<u32>,
) -> Option<SecretViolationReport> {
    if ineligible_for_substitution.is_empty() {
        return None;
    }

    let scan_buf: Cow<[u8]> = if prev_tail.is_empty() {
        Cow::Borrowed(data)
    } else {
        let mut stitched = Vec::with_capacity(prev_tail.len() + data.len());
        stitched.extend_from_slice(prev_tail);
        stitched.extend_from_slice(data);
        Cow::Owned(stitched)
    };
    let scan = scan_buf.as_ref();
    let url_decoded = scan
        .contains(&b'%')
        .then(|| percent_decode(scan).collect::<Vec<u8>>());
    let json_decoded = scan
        .windows(2)
        .any(|window| window == b"\\u")
        .then(|| json_unescape(scan));
    let basic_auth_credentials = decoded_basic_auth_credentials(headers);
    let request = request_summary(headers, protocol);

    let mut detected = None;
    for secret in ineligible_for_substitution {
        if let Some((location, match_form)) = detect_secret_match(
            secret,
            scan,
            url_decoded.as_deref(),
            json_decoded.as_deref(),
            &basic_auth_credentials,
            headers,
            location_hint,
        ) {
            let report = SecretViolationReport {
                action: secret.action,
                env_var: secret.env_var.clone(),
                placeholder: secret.placeholder.clone(),
                protocol,
                location,
                match_form,
                method: request.method.clone(),
                path: request.path.clone(),
                host: request.host.clone(),
                http2_stream_id,
            };
            detected = Some(strictest_violation_report(detected, report));
        }
    }

    detected
}

fn detect_secret_match(
    secret: &IneligibleSecret,
    scan: &[u8],
    url_decoded: Option<&[u8]>,
    json_decoded: Option<&[u8]>,
    basic_auth_credentials: &[String],
    headers: &str,
    location_hint: RequestLocation,
) -> Option<(RequestLocation, PlaceholderMatchForm)> {
    let needle = secret.placeholder.as_bytes();
    if basic_auth_credentials
        .iter()
        .any(|decoded| decoded.contains(&secret.placeholder))
    {
        return Some((
            RequestLocation::BasicAuth,
            PlaceholderMatchForm::BasicAuthDecoded,
        ));
    }
    if contains_bytes(scan, needle) {
        return Some((
            classify_match_location(scan, headers, &secret.placeholder, location_hint),
            PlaceholderMatchForm::Raw,
        ));
    }
    if let Some(decoded) = url_decoded
        && contains_bytes(decoded, needle)
    {
        return Some((
            classify_decoded_match_location(headers, &secret.placeholder, location_hint),
            PlaceholderMatchForm::PercentDecoded,
        ));
    }
    if let Some(decoded) = json_decoded
        && contains_bytes(decoded, needle)
    {
        return Some((
            classify_decoded_match_location(headers, &secret.placeholder, location_hint),
            PlaceholderMatchForm::JsonUnescaped,
        ));
    }
    None
}

fn classify_match_location(
    scan: &[u8],
    headers: &str,
    placeholder: &str,
    location_hint: RequestLocation,
) -> RequestLocation {
    if location_hint != RequestLocation::Unknown && headers.is_empty() {
        return location_hint;
    }
    if !headers.is_empty() && headers.contains(placeholder) {
        return classify_header_match_location(headers, placeholder);
    }
    if !headers.is_empty() && !contains_bytes(headers.as_bytes(), placeholder.as_bytes()) {
        return RequestLocation::Body;
    }
    if location_hint != RequestLocation::Unknown {
        return location_hint;
    }
    if contains_bytes(scan, placeholder.as_bytes()) {
        return RequestLocation::Unknown;
    }
    RequestLocation::Unknown
}

fn classify_decoded_match_location(
    headers: &str,
    placeholder: &str,
    location_hint: RequestLocation,
) -> RequestLocation {
    if location_hint != RequestLocation::Unknown && headers.is_empty() {
        return location_hint;
    }
    if !headers.is_empty() {
        let url_decoded_headers = headers
            .as_bytes()
            .contains(&b'%')
            .then(|| percent_decode(headers.as_bytes()).collect::<Vec<u8>>());
        if url_decoded_headers
            .as_deref()
            .is_some_and(|decoded| contains_bytes(decoded, placeholder.as_bytes()))
        {
            return classify_header_match_location(
                String::from_utf8_lossy(url_decoded_headers.as_deref().unwrap()).as_ref(),
                placeholder,
            );
        }

        let json_decoded_headers = headers
            .as_bytes()
            .windows(2)
            .any(|window| window == b"\\u")
            .then(|| json_unescape(headers.as_bytes()));
        if json_decoded_headers
            .as_deref()
            .is_some_and(|decoded| contains_bytes(decoded, placeholder.as_bytes()))
        {
            return classify_header_match_location(
                String::from_utf8_lossy(json_decoded_headers.as_deref().unwrap()).as_ref(),
                placeholder,
            );
        }

        return RequestLocation::Body;
    }
    if location_hint != RequestLocation::Unknown {
        return location_hint;
    }
    RequestLocation::Unknown
}

fn classify_header_match_location(headers: &str, placeholder: &str) -> RequestLocation {
    let Some(request_line) = headers.split("\r\n").next() else {
        return RequestLocation::Header;
    };
    if let Some((_method, target, _version)) = split_http_request_line(request_line)
        && target
            .split_once('?')
            .is_some_and(|(_, query)| query.contains(placeholder))
    {
        return RequestLocation::Query;
    }
    RequestLocation::Header
}

fn update_tail_buffer(tail: &mut Vec<u8>, data: &[u8], tail_size: usize) {
    if tail_size == 0 {
        tail.clear();
        return;
    }
    if data.len() >= tail_size {
        tail.clear();
        tail.extend_from_slice(&data[data.len() - tail_size..]);
        return;
    }
    tail.extend_from_slice(data);
    let overflow = tail.len().saturating_sub(tail_size);
    if overflow > 0 {
        tail.drain(..overflow);
    }
}

/// Consume chunked body bytes and return the position after the body when the
/// terminating zero chunk and trailers are complete.
fn consume_chunked_body(
    state: &mut ChunkedBodyState,
    data: &[u8],
) -> Result<Option<usize>, ViolationAction> {
    process_chunked_body(state, data, |_| Ok(()))
}

/// Process chunked body bytes and call `on_payload` with decoded chunk payload
/// slices, `on_zero_chunk` when the terminating chunk is parsed, and
/// `on_trailer_line` with each complete trailer line including its CRLF.
fn process_chunked_body<E>(
    state: &mut ChunkedBodyState,
    data: &[u8],
    mut on_event: E,
) -> Result<Option<usize>, ViolationAction>
where
    E: FnMut(ChunkedBodyEvent<'_>) -> Result<(), ViolationAction>,
{
    let mut cursor = 0;
    while cursor < data.len() {
        let phase = std::mem::replace(&mut state.phase, ChunkedPhase::SizeLine);
        match phase {
            ChunkedPhase::SizeLine => {
                state.line.push(data[cursor]);
                cursor += 1;
                if state.line.len() > MAX_HTTP_HEADER_BYTES {
                    return Err(ViolationAction::Block);
                }
                if state.line.ends_with(b"\r\n") {
                    let line = &state.line[..state.line.len() - 2];
                    let size = parse_chunk_size(line)?;
                    state.line.clear();
                    state.phase = if size == 0 {
                        on_event(ChunkedBodyEvent::ZeroChunk)?;
                        ChunkedPhase::TrailerLine
                    } else {
                        ChunkedPhase::Data { remaining: size }
                    };
                } else {
                    state.phase = ChunkedPhase::SizeLine;
                }
            }
            ChunkedPhase::Data { mut remaining } => {
                let take = remaining.min(data.len() - cursor);
                on_event(ChunkedBodyEvent::Payload(&data[cursor..cursor + take]))?;
                cursor += take;
                remaining -= take;
                if remaining == 0 {
                    state.phase = ChunkedPhase::DataCrlf { seen_cr: false };
                } else {
                    state.phase = ChunkedPhase::Data { remaining };
                }
            }
            ChunkedPhase::DataCrlf { mut seen_cr } => {
                if !seen_cr {
                    if data[cursor] != b'\r' {
                        return Err(ViolationAction::Block);
                    }
                    seen_cr = true;
                    cursor += 1;
                    state.phase = ChunkedPhase::DataCrlf { seen_cr };
                } else {
                    if data[cursor] != b'\n' {
                        return Err(ViolationAction::Block);
                    }
                    state.phase = ChunkedPhase::SizeLine;
                    cursor += 1;
                }
            }
            ChunkedPhase::TrailerLine => {
                state.line.push(data[cursor]);
                cursor += 1;
                if state.line.len() > MAX_HTTP_HEADER_BYTES {
                    return Err(ViolationAction::Block);
                }
                if state.line.ends_with(b"\r\n") {
                    let is_empty = state.line.len() == 2;
                    on_event(ChunkedBodyEvent::TrailerLine(&state.line))?;
                    state.line.clear();
                    if is_empty {
                        return Ok(Some(cursor));
                    }
                    state.phase = ChunkedPhase::TrailerLine;
                } else {
                    state.phase = ChunkedPhase::TrailerLine;
                }
            }
        }
    }

    Ok(None)
}

fn parse_chunk_size(line: &[u8]) -> Result<usize, ViolationAction> {
    let size = line
        .split(|byte| *byte == b';')
        .next()
        .unwrap_or_default()
        .trim_ascii();
    if size.is_empty() {
        return Err(ViolationAction::Block);
    }
    let size = std::str::from_utf8(size).map_err(|_| ViolationAction::Block)?;
    usize::from_str_radix(size, 16).map_err(|_| ViolationAction::Block)
}

/// Returns the stricter of two blocking actions, where
/// `BlockAndTerminate` > `BlockAndLog` > `Block`.
fn strictest_violation_report(
    current: Option<SecretViolationReport>,
    candidate: SecretViolationReport,
) -> SecretViolationReport {
    let Some(current) = current else {
        return candidate;
    };
    if candidate.action.priority() > current.action.priority() {
        candidate
    } else {
        current
    }
}

impl BlockingAction {
    fn priority(self) -> u8 {
        match self {
            Self::Block => 0,
            Self::BlockAndLog => 1,
            Self::BlockAndTerminate => 2,
        }
    }
}

impl SecretViolationReport {
    fn apply_request_summary(&mut self, summary: &RequestSummary) {
        if self.method.is_none() {
            self.method = summary.method.clone();
        }
        if self.path.is_none() {
            self.path = summary.path.clone();
        }
        if self.host.is_none() {
            self.host = summary.host.clone();
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::config::*;
    use crate::shared::{ResolvedHostnameFamily, SharedState};

    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn make_config(secrets: Vec<SecretEntry>) -> SecretsConfig {
        SecretsConfig {
            secrets,
            on_violation: ViolationAction::Block,
        }
    }

    fn make_secret(placeholder: &str, value: &str, host: &str) -> SecretEntry {
        SecretEntry {
            env_var: "TEST_KEY".into(),
            value: zeroize::Zeroizing::new(value.into()),
            source: None,
            placeholder: placeholder.into(),
            allowed_hosts: vec![HostPattern::Exact(host.into())],
            injection: SecretInjection::default(),
            on_violation: None,
            require_tls_identity: true,
        }
    }

    fn cache_host(shared: &SharedState, host: &str, ip: Ipv4Addr) {
        shared.cache_resolved_hostname(
            host,
            ResolvedHostnameFamily::Ipv4,
            [IpAddr::V4(ip)],
            Duration::from_secs(60),
        );
    }

    fn basic_auth_only() -> SecretInjection {
        SecretInjection {
            headers: false,
            basic_auth: true,
            query_params: false,
            body: false,
        }
    }

    fn split_http_body(data: &[u8]) -> (&[u8], &[u8]) {
        let boundary = find_header_boundary(data).expect("HTTP header boundary");
        data.split_at(boundary)
    }

    fn decode_chunked_payload(data: &[u8]) -> (Vec<u8>, Vec<u8>, usize) {
        let mut cursor = 0;
        let mut decoded = Vec::new();
        let mut trailers = Vec::new();

        loop {
            let line_end = data[cursor..]
                .windows(2)
                .position(|window| window == b"\r\n")
                .map(|pos| cursor + pos)
                .expect("chunk size line");
            let size = parse_chunk_size(&data[cursor..line_end]).expect("valid chunk size");
            cursor = line_end + 2;

            if size == 0 {
                loop {
                    let trailer_end = data[cursor..]
                        .windows(2)
                        .position(|window| window == b"\r\n")
                        .map(|pos| cursor + pos + 2)
                        .expect("trailer line");
                    trailers.extend_from_slice(&data[cursor..trailer_end]);
                    let empty = trailer_end - cursor == 2;
                    cursor = trailer_end;
                    if empty {
                        return (decoded, trailers, cursor);
                    }
                }
            }

            decoded.extend_from_slice(&data[cursor..cursor + size]);
            cursor += size;
            assert_eq!(&data[cursor..cursor + 2], b"\r\n");
            cursor += 2;
        }
    }

    fn encode_h2_header_block(headers: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut encoder = HpackEncoder::with_dynamic_size(4096);
        let mut block = Vec::new();
        for (name, value) in headers {
            encoder
                .encode(
                    (name.to_vec(), value.to_vec(), HpackEncoder::NEVER_INDEXED),
                    &mut block,
                )
                .unwrap();
        }
        block
    }

    fn h2_request(headers: &[(&[u8], &[u8])], end_stream: bool) -> Vec<u8> {
        let encoded = encode_h2_header_block(headers);
        let mut out = HTTP2_PREFACE.to_vec();
        append_http2_frame(&mut out, 0x4, 0, 0, &[]).unwrap();
        append_http2_header_frames(&mut out, 1, end_stream, &encoded).unwrap();
        out
    }

    fn h2_request_with_split_headers(headers: &[(&[u8], &[u8])], split_at: usize) -> Vec<u8> {
        let encoded = encode_h2_header_block(headers);
        let split_at = split_at.min(encoded.len());
        let mut out = HTTP2_PREFACE.to_vec();
        append_http2_frame(&mut out, 0x4, 0, 0, &[]).unwrap();
        append_http2_frame(&mut out, HTTP2_FRAME_HEADERS, 0, 1, &encoded[..split_at]).unwrap();
        append_http2_frame(
            &mut out,
            HTTP2_FRAME_CONTINUATION,
            HTTP2_FLAG_END_HEADERS | HTTP2_FLAG_END_STREAM,
            1,
            &encoded[split_at..],
        )
        .unwrap();
        out
    }

    fn h2_request_with_data(headers: &[(&[u8], &[u8])], data: &[u8]) -> Vec<u8> {
        let mut out = h2_request(headers, false);
        append_http2_frame(&mut out, HTTP2_FRAME_DATA, HTTP2_FLAG_END_STREAM, 1, data).unwrap();
        out
    }

    fn append_h2_headers(
        out: &mut Vec<u8>,
        stream_id: u32,
        headers: &[(&[u8], &[u8])],
        end_stream: bool,
    ) {
        let encoded = encode_h2_header_block(headers);
        append_http2_header_frames(out, stream_id, end_stream, &encoded).unwrap();
    }

    fn decode_first_h2_headers(data: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        assert!(data.starts_with(HTTP2_PREFACE));
        let mut cursor = HTTP2_PREFACE.len();
        let mut decoder = HpackDecoder::with_dynamic_size(4096);
        let mut header_block = Vec::new();
        let mut in_headers = false;

        while cursor + 9 <= data.len() {
            let len = http2_frame_payload_len(&data[cursor..cursor + 9]);
            let raw = &data[cursor..cursor + 9 + len];
            cursor += 9 + len;
            let frame = parse_http2_frame(raw).unwrap();
            match frame.kind {
                HTTP2_FRAME_HEADERS => {
                    header_block.extend_from_slice(
                        http2_headers_fragment(frame.flags, frame.payload).unwrap(),
                    );
                    if frame.flags & HTTP2_FLAG_END_HEADERS != 0 {
                        break;
                    }
                    in_headers = true;
                }
                HTTP2_FRAME_CONTINUATION if in_headers => {
                    header_block.extend_from_slice(frame.payload);
                    if frame.flags & HTTP2_FLAG_END_HEADERS != 0 {
                        break;
                    }
                }
                _ => {}
            }
        }

        let mut encoded = header_block;
        let mut headers = Vec::new();
        decoder.decode(&mut encoded, &mut headers).unwrap();
        headers
            .into_iter()
            .map(|(name, value, _flags)| (name, value))
            .collect()
    }

    fn h2_header_value(headers: &[(Vec<u8>, Vec<u8>)], name: &[u8]) -> String {
        let value = headers
            .iter()
            .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_slice())
            .expect("header present");
        String::from_utf8(value.to_vec()).unwrap()
    }

    #[test]
    fn violation_report_includes_secret_and_basic_auth_context() {
        let secret = IneligibleSecret {
            env_var: "OPENAI_API_KEY".into(),
            placeholder: "$KEY".into(),
            action: BlockingAction::BlockAndLog,
        };
        let encoded = BASE64.encode(b"user:$KEY");
        let headers = format!(
            "POST /v1/chat/completions?token=redacted HTTP/1.1\r\nHost: evil.example.com\r\nAuthorization: Basic {encoded}\r\n\r\n"
        );

        let report = detect_blocking_action_with_tail(
            &[secret],
            &[],
            headers.as_bytes(),
            &headers,
            RequestProtocol::Http1,
            RequestLocation::Unknown,
            None,
        )
        .expect("violation report");

        assert_eq!(report.action, BlockingAction::BlockAndLog);
        assert_eq!(report.env_var, "OPENAI_API_KEY");
        assert_eq!(report.placeholder, "$KEY");
        assert_eq!(report.location, RequestLocation::BasicAuth);
        assert!(matches!(
            report.match_form,
            PlaceholderMatchForm::BasicAuthDecoded
        ));
        assert_eq!(report.method.as_deref(), Some("POST"));
        assert_eq!(report.path.as_deref(), Some("/v1/chat/completions"));
        assert_eq!(report.host.as_deref(), Some("evil.example.com"));
    }

    #[test]
    fn violation_report_classifies_percent_decoded_query_match() {
        let secret = IneligibleSecret {
            env_var: "SERVICE_TOKEN".into(),
            placeholder: "abc/key".into(),
            action: BlockingAction::BlockAndLog,
        };
        let headers =
            "GET /leak?token=abc%2Fkey&other=redacted HTTP/1.1\r\nHost: evil.example.com\r\n\r\n";

        let report = detect_blocking_action_with_tail(
            &[secret],
            &[],
            headers.as_bytes(),
            headers,
            RequestProtocol::Http1,
            RequestLocation::Unknown,
            None,
        )
        .expect("violation report");

        assert_eq!(report.env_var, "SERVICE_TOKEN");
        assert_eq!(report.location, RequestLocation::Query);
        assert!(matches!(
            report.match_form,
            PlaceholderMatchForm::PercentDecoded
        ));
        assert_eq!(report.method.as_deref(), Some("GET"));
        assert_eq!(report.path.as_deref(), Some("/leak"));
        assert_eq!(report.host.as_deref(), Some("evil.example.com"));
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
    fn split_http1_post_is_not_misclassified_as_http2_preface() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        assert_eq!(handler.substitute(b"P").unwrap().as_ref(), b"");

        let output = handler
            .substitute(b"OST / HTTP/1.1\r\nAuthorization: Bearer $KEY\r\n\r\n")
            .unwrap();
        assert_eq!(
            String::from_utf8(output.into_owned()).unwrap(),
            "POST / HTTP/1.1\r\nAuthorization: Bearer real-secret\r\n\r\n"
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
            ViolationAction::Block
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
    fn body_injection_buffers_until_content_length_complete() {
        let mut secret = make_secret("$KEY", "longer-secret", "api.openai.com");
        secret.injection.body = true;
        let config = make_config(vec![secret]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let body = b"{\"key\":\"$KEY\"}";
        let mut chunk1 = format!(
            "POST / HTTP/1.1\r\nHost: api.openai.com\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        chunk1.extend_from_slice(&body[..5]);

        let out1 = handler.substitute(&chunk1).unwrap();
        assert!(out1.is_empty());

        let out2 = handler.substitute(&body[5..]).unwrap();
        let result = String::from_utf8(out2.into_owned()).unwrap();
        let expected_body = "{\"key\":\"longer-secret\"}";
        assert!(result.contains(expected_body));
        assert!(result.contains(&format!("Content-Length: {}", expected_body.len())));
    }

    #[test]
    fn body_injection_blocks_content_length_over_buffer_limit() {
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.injection.body = true;
        let config = make_config(vec![secret]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let input = format!(
            "POST / HTTP/1.1\r\nHost: api.openai.com\r\nContent-Length: {}\r\n\r\n",
            MAX_HTTP_BODY_BUFFER_BYTES + 1
        );

        assert_eq!(
            handler.substitute(input.as_bytes()).unwrap_err(),
            ViolationAction::Block
        );
    }

    #[test]
    fn invalid_content_length_is_blocked() {
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.injection.body = true;
        let config = make_config(vec![secret]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let input =
            b"POST / HTTP/1.1\r\nHost: api.openai.com\r\nContent-Length: nope\r\n\r\nxx$KEYyy";

        assert_eq!(
            handler.substitute(input).unwrap_err(),
            ViolationAction::Block
        );
    }

    #[test]
    fn conflicting_content_lengths_are_blocked() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let input = b"POST / HTTP/1.1\r\nHost: api.openai.com\r\nContent-Length: 8\r\nContent-Length: 9\r\n\r\nxx$KEYyy";

        assert_eq!(
            handler.substitute(input).unwrap_err(),
            ViolationAction::Block
        );
    }

    #[test]
    fn body_injection_no_content_length_header() {
        let mut secret = make_secret("$KEY", "longer-secret", "api.openai.com");
        secret.injection.body = true;
        let config = make_config(vec![secret]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        // Chunked requests do not carry Content-Length; body injection
        // decodes and re-encodes chunked framing instead.
        let input =
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nF\r\n{\"key\": \"$KEY\"}\r\n0\r\n\r\n";
        let output = handler.substitute(input).unwrap();
        let result = String::from_utf8(output.into_owned()).unwrap();
        assert!(!result.contains("$KEY"));
        assert!(result.contains("longer-secret"));
        assert!(!result.contains("Content-Length"));
    }

    #[test]
    fn chunked_body_injection_rewrites_split_placeholder_across_chunks() {
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.injection.body = true;
        let config = make_config(vec![secret]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let input = b"POST / HTTP/1.1\r\nHost: api.openai.com\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nxx$K\r\n2\r\nEY\r\n0\r\n\r\n";
        let output = handler.substitute(input).unwrap().into_owned();
        let (_, body) = split_http_body(&output);
        let (decoded, trailers, consumed) = decode_chunked_payload(body);

        assert_eq!(decoded, b"xxreal-secret");
        assert_eq!(trailers, b"\r\n");
        assert_eq!(consumed, body.len());
    }

    #[test]
    fn chunked_body_injection_rewrites_placeholder_split_across_tls_reads() {
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.injection.body = true;
        let config = make_config(vec![secret]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let chunk1 = b"POST / HTTP/1.1\r\nHost: api.openai.com\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nxx$K\r\n";
        let chunk2 = b"2\r\nEY\r\n0\r\n\r\n";

        let mut output = handler.substitute(chunk1).unwrap().into_owned();
        output.extend_from_slice(handler.substitute(chunk2).unwrap().as_ref());
        let (_, body) = split_http_body(&output);
        let (decoded, trailers, consumed) = decode_chunked_payload(body);

        assert_eq!(decoded, b"xxreal-secret");
        assert_eq!(trailers, b"\r\n");
        assert_eq!(consumed, body.len());
    }

    #[test]
    fn chunked_body_injection_preserves_trailers_and_recurses_to_next_request() {
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.injection.body = true;
        let config = make_config(vec![secret]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let mut input = b"POST /a HTTP/1.1\r\nHost: api.openai.com\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n$KEY\r\n0\r\nX-Trailer: yes\r\n\r\n".to_vec();
        input.extend_from_slice(b"GET /b HTTP/1.1\r\nHost: api.openai.com\r\nAuth: $KEY\r\n\r\n");

        let output = handler.substitute(&input).unwrap().into_owned();
        let (_, body_and_next) = split_http_body(&output);
        let (decoded, trailers, consumed) = decode_chunked_payload(body_and_next);
        let next_request = &body_and_next[consumed..];

        assert_eq!(decoded, b"real-secret");
        assert_eq!(trailers, b"X-Trailer: yes\r\n\r\n");
        assert_eq!(
            next_request,
            b"GET /b HTTP/1.1\r\nHost: api.openai.com\r\nAuth: real-secret\r\n\r\n"
        );
    }

    #[test]
    fn chunked_body_injection_blocks_content_encoded_placeholder() {
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.injection.body = true;
        let config = make_config(vec![secret]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let input = b"POST / HTTP/1.1\r\nHost: api.openai.com\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n4\r\n$KEY\r\n0\r\n\r\n";

        assert_eq!(
            handler.substitute(input).unwrap_err(),
            ViolationAction::Block
        );
    }

    #[test]
    fn split_chunked_body_payload_blocks_for_wrong_host() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler = SecretsHandler::new(&config, "evil.com", true);

        let input = b"POST / HTTP/1.1\r\nHost: evil.com\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n$K\r\n2\r\nEY\r\n0\r\n\r\n";

        assert_eq!(
            handler.substitute(input).unwrap_err(),
            ViolationAction::Block
        );
    }

    #[test]
    fn oversized_secret_placeholder_is_rejected() {
        let placeholder = "x".repeat(MAX_SECRET_PLACEHOLDER_BYTES + 1);
        let config = make_config(vec![make_secret(
            &placeholder,
            "real-secret",
            "api.openai.com",
        )]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        assert_eq!(
            handler.substitute(b"GET / HTTP/1.1\r\n\r\n").unwrap_err(),
            ViolationAction::Block
        );
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
    fn body_injection_blocks_content_encoded_placeholder() {
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.injection.body = true;
        let config = make_config(vec![secret]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let body = b"compressed-looking-$KEY-bytes";
        let mut input = format!(
            "POST /git-upload-pack HTTP/1.1\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        input.extend_from_slice(body);

        assert_eq!(
            handler.substitute(&input).unwrap_err(),
            ViolationAction::Block
        );
    }

    #[test]
    fn body_injection_blocks_split_content_encoded_placeholder() {
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.injection.body = true;
        let config = make_config(vec![secret]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let first = b"POST /git-upload-pack HTTP/1.1\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\n\r\n$K";

        let output = handler.substitute(first).unwrap();
        assert_eq!(&*output, first.as_slice());
        assert_eq!(
            handler.substitute(b"EY").unwrap_err(),
            ViolationAction::Block
        );
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
    fn new_plain_http_blocks_require_tls_identity_secrets() {
        // new_plain_http must NOT substitute require_tls_identity=true secrets
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let shared = SharedState::new(4);
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        cache_host(&shared, "api.openai.com", ip);
        let mut handler =
            SecretsHandler::new_plain_http(&config, "api.openai.com", IpAddr::V4(ip), &shared);

        let input = b"GET / HTTP/1.1\r\nAuthorization: Bearer $KEY\r\nHost: api.openai.com\r\n\r\n";
        let output = handler.substitute(input).unwrap();
        // require_tls_identity=true (default) — placeholder must NOT be substituted
        assert!(
            String::from_utf8(output.into_owned())
                .unwrap()
                .contains("$KEY")
        );
    }

    #[test]
    fn new_plain_http_substitutes_when_tls_identity_not_required() {
        // new_plain_http MUST substitute secrets with require_tls_identity=false
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.require_tls_identity = false;
        let config = make_config(vec![secret]);
        let shared = SharedState::new(4);
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        cache_host(&shared, "api.openai.com", ip);
        let mut handler =
            SecretsHandler::new_plain_http(&config, "api.openai.com", IpAddr::V4(ip), &shared);

        let input = b"GET / HTTP/1.1\r\nAuthorization: Bearer $KEY\r\nHost: api.openai.com\r\n\r\n";
        let output = handler.substitute(input).unwrap();
        assert!(
            String::from_utf8(output.into_owned())
                .unwrap()
                .contains("real-secret")
        );
    }

    #[test]
    fn new_plain_http_invalid_host_blocks_host_bound_secret() {
        // Host could not be proven: a host-bound secret must not be substituted,
        // and its placeholder must not leak unchanged to the server.
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.require_tls_identity = false;
        let config = make_config(vec![secret]);
        let mut handler = SecretsHandler::new_plain_http_invalid_host(&config);

        let input = b"GET / HTTP/1.1\r\nAuthorization: Bearer $KEY\r\n\r\n";
        // on_violation is Block, so the placeholder is blocked, not forwarded.
        assert!(handler.substitute(input).is_err());
    }

    #[test]
    fn new_plain_http_invalid_host_substitutes_when_all_secrets_any() {
        // When every secret allows HostPattern::Any the host is irrelevant, so
        // substitution is allowed even with no provable host.
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.require_tls_identity = false;
        secret.allowed_hosts = vec![HostPattern::Any];
        let config = make_config(vec![secret]);
        let mut handler = SecretsHandler::new_plain_http_invalid_host(&config);

        let input = b"GET / HTTP/1.1\r\nAuthorization: Bearer $KEY\r\n\r\n";
        let output = handler.substitute(input).unwrap();
        assert!(
            String::from_utf8(output.into_owned())
                .unwrap()
                .contains("real-secret")
        );
    }

    #[test]
    fn new_plain_http_invalid_host_blocks_any_secret_when_mixed() {
        // The all-Any exception is all-or-nothing: a single host-bound secret
        // alongside an Any secret makes every secret ineligible.
        let mut any_secret = make_secret("$ANY", "any-value", "api.openai.com");
        any_secret.require_tls_identity = false;
        any_secret.allowed_hosts = vec![HostPattern::Any];
        let mut bound_secret = make_secret("$BOUND", "bound-value", "api.openai.com");
        bound_secret.require_tls_identity = false;
        let config = make_config(vec![any_secret, bound_secret]);
        let mut handler = SecretsHandler::new_plain_http_invalid_host(&config);

        // Even the Any secret's placeholder is now blocked, not substituted.
        let input = b"GET / HTTP/1.1\r\nAuthorization: Bearer $ANY\r\n\r\n";
        assert!(handler.substitute(input).is_err());
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
    fn query_params_do_not_substitute_path() {
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.injection = SecretInjection {
            headers: false,
            basic_auth: false,
            query_params: true,
            body: false,
        };
        let config = make_config(vec![secret]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let input = b"GET /path/$KEY?token=$KEY HTTP/1.1\r\nHost: api.openai.com\r\n\r\n";
        let output = handler.substitute(input).unwrap();
        let result = String::from_utf8(output.into_owned()).unwrap();

        assert!(result.contains("GET /path/$KEY?token=real-secret HTTP/1.1"));
    }

    #[test]
    fn header_injection_does_not_substitute_request_line_query() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler = SecretsHandler::new(&config, "api.openai.com", true);

        let input = b"GET /api?key=$KEY HTTP/1.1\r\nHost: api.openai.com\r\n\r\n";
        let output = handler.substitute(input).unwrap();

        assert_eq!(output.as_ref(), input);
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
    fn split_url_encoded_placeholder_blocks_for_wrong_host() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler = SecretsHandler::new(&config, "evil.com", true);

        let chunk1 = b"POST / HTTP/1.1\r\nHost: evil.com\r\nContent-Length: 14\r\n\r\nkey=%24K";
        let chunk2 = b"EY&x=1";

        assert!(handler.substitute(chunk1).is_ok());
        assert_eq!(
            handler.substitute(chunk2).unwrap_err(),
            ViolationAction::Block
        );
    }

    #[test]
    fn split_json_escaped_placeholder_blocks_for_wrong_host() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler = SecretsHandler::new(&config, "evil.com", true);

        let chunk1 =
            b"POST / HTTP/1.1\r\nHost: evil.com\r\nContent-Length: 17\r\n\r\n{\"k\":\"\\u0024K";
        let chunk2 = b"EY\"}";

        assert!(handler.substitute(chunk1).is_ok());
        assert_eq!(
            handler.substitute(chunk2).unwrap_err(),
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
    fn split_headers_do_not_leak_header_secret_into_body() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "example.com")]);
        let mut handler = SecretsHandler::new(&config, "example.com", true);

        let chunk1 = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 8\r\n";
        let out1 = handler.substitute(chunk1).unwrap();
        assert!(out1.is_empty());

        let chunk2 = b"\r\nxx$KEYyy";
        let out2 = handler.substitute(chunk2).unwrap();
        let result = String::from_utf8(out2.into_owned()).unwrap();

        assert!(result.contains("xx$KEYyy"));
        assert!(!result.contains("real-secret"));
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

    #[test]
    fn exact_host_requires_dns_pin_for_tls_intercepted_secret() {
        let ip = Ipv4Addr::new(203, 0, 113, 10);
        let shared = SharedState::new(16);
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler =
            SecretsHandler::new_tls_intercepted(&config, "api.openai.com", IpAddr::V4(ip), &shared);

        let input = b"GET / HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer $KEY\r\n\r\n";
        assert_eq!(
            handler.substitute(input).unwrap_err(),
            ViolationAction::Block
        );

        cache_host(&shared, "api.openai.com", ip);
        let mut handler =
            SecretsHandler::new_tls_intercepted(&config, "api.openai.com", IpAddr::V4(ip), &shared);
        let output = handler.substitute(input).unwrap();

        assert!(
            String::from_utf8(output.into_owned())
                .unwrap()
                .contains("real-secret")
        );
    }

    #[test]
    fn any_host_bypasses_dns_pin_for_tls_intercepted_secret() {
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.allowed_hosts = vec![HostPattern::Any];
        let config = make_config(vec![secret]);
        let shared = SharedState::new(16);
        let mut handler = SecretsHandler::new_tls_intercepted(
            &config,
            "unresolved.example",
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20)),
            &shared,
        );

        let input =
            b"GET / HTTP/1.1\r\nHost: unresolved.example\r\nAuthorization: Bearer $KEY\r\n\r\n";
        let output = handler.substitute(input).unwrap();

        assert!(
            String::from_utf8(output.into_owned())
                .unwrap()
                .contains("real-secret")
        );
    }

    #[test]
    fn host_alias_matches_gateway_without_dns_pin() {
        let gateway = Ipv4Addr::new(192, 0, 2, 1);
        let shared = SharedState::new(16);
        shared.set_gateway_ips(Some(gateway), None);

        let config = make_config(vec![make_secret("$KEY", "real-secret", crate::HOST_ALIAS)]);
        let mut handler = SecretsHandler::new_tls_intercepted(
            &config,
            crate::HOST_ALIAS,
            IpAddr::V4(gateway),
            &shared,
        );

        let input = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer $KEY\r\n\r\n",
            crate::HOST_ALIAS
        );
        let output = handler.substitute(input.as_bytes()).unwrap();

        assert!(
            String::from_utf8(output.into_owned())
                .unwrap()
                .contains("real-secret")
        );
    }

    #[test]
    fn tls_intercepted_http_host_must_match_sni() {
        let ip = Ipv4Addr::new(203, 0, 113, 30);
        let shared = SharedState::new(16);
        cache_host(&shared, "api.openai.com", ip);
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler =
            SecretsHandler::new_tls_intercepted(&config, "api.openai.com", IpAddr::V4(ip), &shared);

        let input = b"GET / HTTP/1.1\r\nHost: evil.com\r\nAuthorization: Bearer $KEY\r\n\r\n";
        assert_eq!(
            handler.substitute(input).unwrap_err(),
            ViolationAction::Block
        );
    }

    #[test]
    fn connect_tls_intercepted_http_host_must_match_sni() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler =
            SecretsHandler::new_tls_intercepted_via_connect(&config, "api.openai.com");

        let input = b"GET / HTTP/1.1\r\nHost: evil.com\r\nAuthorization: Bearer $KEY\r\n\r\n";
        assert_eq!(
            handler.substitute(input).unwrap_err(),
            ViolationAction::Block
        );
    }

    #[test]
    fn tls_intercepted_http_host_validation_buffers_split_headers() {
        let ip = Ipv4Addr::new(203, 0, 113, 31);
        let shared = SharedState::new(16);
        cache_host(&shared, "api.openai.com", ip);
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler =
            SecretsHandler::new_tls_intercepted(&config, "api.openai.com", IpAddr::V4(ip), &shared);

        let out1 = handler
            .substitute(b"GET / HTTP/1.1\r\nHost: evil.com\r\n")
            .unwrap();
        assert!(out1.is_empty());
        assert_eq!(
            handler
                .substitute(b"Authorization: Bearer $KEY\r\n\r\n")
                .unwrap_err(),
            ViolationAction::Block
        );
    }

    #[test]
    fn tls_intercepted_http_host_validation_survives_leading_empty_block() {
        let ip = Ipv4Addr::new(203, 0, 113, 32);
        let shared = SharedState::new(16);
        cache_host(&shared, "api.openai.com", ip);
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler =
            SecretsHandler::new_tls_intercepted(&config, "api.openai.com", IpAddr::V4(ip), &shared);

        assert_eq!(
            handler.substitute(b"\r\n\r\n").unwrap().as_ref(),
            b"\r\n\r\n"
        );
        assert_eq!(
            handler
                .substitute(b"GET / HTTP/1.1\r\nHost: evil.com\r\nAuth: $KEY\r\n\r\n")
                .unwrap_err(),
            ViolationAction::Block
        );
    }

    #[test]
    fn tls_intercepted_http2_authority_must_match_sni() {
        let ip = Ipv4Addr::new(203, 0, 113, 33);
        let shared = SharedState::new(16);
        cache_host(&shared, "api.openai.com", ip);
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler =
            SecretsHandler::new_tls_intercepted(&config, "api.openai.com", IpAddr::V4(ip), &shared);

        let request = h2_request(
            &[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"evil.com"),
                (b":path", b"/"),
                (b"authorization", b"Bearer $KEY"),
            ],
            true,
        );

        assert_eq!(
            handler.substitute(&request).unwrap_err(),
            ViolationAction::Block
        );
    }

    #[test]
    fn connect_tls_intercepted_http2_authority_must_match_sni() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler =
            SecretsHandler::new_tls_intercepted_via_connect(&config, "api.openai.com");

        let request = h2_request(
            &[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"evil.com"),
                (b":path", b"/"),
                (b"authorization", b"Bearer $KEY"),
            ],
            true,
        );

        assert_eq!(
            handler.substitute(&request).unwrap_err(),
            ViolationAction::Block
        );
    }

    #[test]
    fn tls_intercepted_http2_substitutes_header_secret() {
        let ip = Ipv4Addr::new(203, 0, 113, 34);
        let shared = SharedState::new(16);
        cache_host(&shared, "api.openai.com", ip);
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler =
            SecretsHandler::new_tls_intercepted(&config, "api.openai.com", IpAddr::V4(ip), &shared);

        let request = h2_request(
            &[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"api.openai.com"),
                (b":path", b"/"),
                (b"authorization", b"Bearer $KEY"),
            ],
            true,
        );

        let output = handler.substitute(&request).unwrap().into_owned();
        let headers = decode_first_h2_headers(&output);
        assert_eq!(
            h2_header_value(&headers, b"authorization"),
            "Bearer real-secret"
        );
    }

    #[test]
    fn tls_intercepted_http2_preface_can_span_tls_reads() {
        let ip = Ipv4Addr::new(203, 0, 113, 38);
        let shared = SharedState::new(16);
        cache_host(&shared, "api.openai.com", ip);
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler =
            SecretsHandler::new_tls_intercepted(&config, "api.openai.com", IpAddr::V4(ip), &shared);

        let request = h2_request(
            &[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"api.openai.com"),
                (b":path", b"/"),
                (b"authorization", b"Bearer $KEY"),
            ],
            true,
        );

        assert_eq!(handler.substitute(&request[..1]).unwrap().as_ref(), b"");

        let output = handler.substitute(&request[1..]).unwrap().into_owned();
        let headers = decode_first_h2_headers(&output);
        assert_eq!(
            h2_header_value(&headers, b"authorization"),
            "Bearer real-secret"
        );
    }

    #[test]
    fn tls_intercepted_http2_substitutes_query_and_basic_auth() {
        let ip = Ipv4Addr::new(203, 0, 113, 35);
        let shared = SharedState::new(16);
        cache_host(&shared, "api.openai.com", ip);
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.injection = SecretInjection {
            headers: false,
            basic_auth: true,
            query_params: true,
            body: false,
        };
        let config = make_config(vec![secret]);
        let mut handler =
            SecretsHandler::new_tls_intercepted(&config, "api.openai.com", IpAddr::V4(ip), &shared);
        let auth = format!("Basic {}", BASE64.encode(b"user:$KEY"));

        let request = h2_request(
            &[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"api.openai.com"),
                (b":path", b"/v1/$KEY?token=$KEY"),
                (b"authorization", auth.as_bytes()),
            ],
            true,
        );

        let output = handler.substitute(&request).unwrap().into_owned();
        let headers = decode_first_h2_headers(&output);
        assert_eq!(
            h2_header_value(&headers, b":path"),
            "/v1/$KEY?token=real-secret"
        );
        let auth = h2_header_value(&headers, b"authorization");
        let decoded = split_auth_scheme(&auth)
            .and_then(|(_, encoded)| BASE64.decode(encoded).ok())
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .unwrap();
        assert_eq!(decoded, "user:real-secret");
    }

    #[test]
    fn tls_intercepted_http2_split_header_block_is_validated() {
        let ip = Ipv4Addr::new(203, 0, 113, 36);
        let shared = SharedState::new(16);
        cache_host(&shared, "api.openai.com", ip);
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler =
            SecretsHandler::new_tls_intercepted(&config, "api.openai.com", IpAddr::V4(ip), &shared);

        let request = h2_request_with_split_headers(
            &[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"evil.com"),
                (b":path", b"/"),
                (b"authorization", b"Bearer $KEY"),
            ],
            8,
        );

        assert_eq!(
            handler.substitute(&request).unwrap_err(),
            ViolationAction::Block
        );
    }

    #[test]
    fn tls_intercepted_http2_body_placeholder_blocks_until_body_rewrite_exists() {
        let ip = Ipv4Addr::new(203, 0, 113, 37);
        let shared = SharedState::new(16);
        cache_host(&shared, "api.openai.com", ip);
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.injection.body = true;
        let config = make_config(vec![secret]);
        let mut handler =
            SecretsHandler::new_tls_intercepted(&config, "api.openai.com", IpAddr::V4(ip), &shared);

        let request = h2_request_with_data(
            &[
                (b":method", b"POST"),
                (b":scheme", b"https"),
                (b":authority", b"api.openai.com"),
                (b":path", b"/"),
            ],
            b"{\"key\":\"$KEY\"}",
        );

        assert_eq!(
            handler.substitute(&request).unwrap_err(),
            ViolationAction::Block
        );
    }

    #[test]
    fn tls_intercepted_http2_body_placeholder_split_across_data_frames_blocks() {
        let ip = Ipv4Addr::new(203, 0, 113, 39);
        let shared = SharedState::new(16);
        cache_host(&shared, "api.openai.com", ip);
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.injection.body = true;
        let config = make_config(vec![secret]);
        let mut handler =
            SecretsHandler::new_tls_intercepted(&config, "api.openai.com", IpAddr::V4(ip), &shared);

        let mut request = HTTP2_PREFACE.to_vec();
        append_http2_frame(&mut request, 0x4, 0, 0, &[]).unwrap();
        append_h2_headers(
            &mut request,
            1,
            &[
                (b":method", b"POST"),
                (b":scheme", b"https"),
                (b":authority", b"api.openai.com"),
                (b":path", b"/"),
            ],
            false,
        );
        append_http2_frame(&mut request, HTTP2_FRAME_DATA, 0, 1, b"$KE").unwrap();
        append_http2_frame(
            &mut request,
            HTTP2_FRAME_DATA,
            HTTP2_FLAG_END_STREAM,
            1,
            b"Y",
        )
        .unwrap();

        assert_eq!(
            handler.substitute(&request).unwrap_err(),
            ViolationAction::Block
        );
    }

    #[test]
    fn tls_intercepted_http2_data_tails_are_tracked_per_stream() {
        let ip = Ipv4Addr::new(203, 0, 113, 40);
        let shared = SharedState::new(16);
        cache_host(&shared, "api.openai.com", ip);
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.injection.body = true;
        let config = make_config(vec![secret]);
        let mut handler =
            SecretsHandler::new_tls_intercepted(&config, "api.openai.com", IpAddr::V4(ip), &shared);

        let mut request = HTTP2_PREFACE.to_vec();
        append_http2_frame(&mut request, 0x4, 0, 0, &[]).unwrap();
        for stream_id in [1, 3] {
            append_h2_headers(
                &mut request,
                stream_id,
                &[
                    (b":method", b"POST"),
                    (b":scheme", b"https"),
                    (b":authority", b"api.openai.com"),
                    (b":path", b"/"),
                ],
                false,
            );
        }
        append_http2_frame(&mut request, HTTP2_FRAME_DATA, 0, 1, b"$KE").unwrap();
        append_http2_frame(
            &mut request,
            HTTP2_FRAME_DATA,
            HTTP2_FLAG_END_STREAM,
            3,
            b"Y",
        )
        .unwrap();

        assert!(handler.substitute(&request).is_ok());
    }

    #[test]
    fn tls_intercepted_http2_large_data_frame_without_placeholder_passes() {
        let ip = Ipv4Addr::new(203, 0, 113, 41);
        let shared = SharedState::new(16);
        cache_host(&shared, "api.openai.com", ip);
        let mut secret = make_secret("$KEY", "real-secret", "api.openai.com");
        secret.injection.body = true;
        let config = make_config(vec![secret]);
        let mut handler =
            SecretsHandler::new_tls_intercepted(&config, "api.openai.com", IpAddr::V4(ip), &shared);
        let payload = vec![b'a'; 1024 * 1024];

        let request = h2_request_with_data(
            &[
                (b":method", b"POST"),
                (b":scheme", b"https"),
                (b":authority", b"api.openai.com"),
                (b":path", b"/"),
            ],
            &payload,
        );

        let output = handler.substitute(&request).unwrap().into_owned();
        assert!(output.ends_with(&payload));
    }

    #[test]
    fn tls_intercepted_http2_data_before_headers_is_blocked() {
        let ip = Ipv4Addr::new(203, 0, 113, 42);
        let shared = SharedState::new(16);
        cache_host(&shared, "api.openai.com", ip);
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler =
            SecretsHandler::new_tls_intercepted(&config, "api.openai.com", IpAddr::V4(ip), &shared);

        let mut request = HTTP2_PREFACE.to_vec();
        append_http2_frame(&mut request, 0x4, 0, 0, &[]).unwrap();
        append_http2_frame(
            &mut request,
            HTTP2_FRAME_DATA,
            HTTP2_FLAG_END_STREAM,
            1,
            b"body",
        )
        .unwrap();

        assert_eq!(
            handler.substitute(&request).unwrap_err(),
            ViolationAction::Block
        );
    }

    #[test]
    fn tls_intercepted_http2_decoded_header_list_size_is_bounded() {
        let ip = Ipv4Addr::new(203, 0, 113, 43);
        let shared = SharedState::new(16);
        cache_host(&shared, "api.openai.com", ip);
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler =
            SecretsHandler::new_tls_intercepted(&config, "api.openai.com", IpAddr::V4(ip), &shared);
        let mut encoder = HpackEncoder::with_dynamic_size(4096);

        let mut first_block = Vec::new();
        for (name, value) in [
            (b":method".as_slice(), b"GET".as_slice()),
            (b":scheme".as_slice(), b"https".as_slice()),
            (b":authority".as_slice(), b"api.openai.com".as_slice()),
            (b":path".as_slice(), b"/".as_slice()),
        ] {
            encoder
                .encode(
                    (name.to_vec(), value.to_vec(), HpackEncoder::NEVER_INDEXED),
                    &mut first_block,
                )
                .unwrap();
        }
        encoder
            .encode(
                (
                    b"x-fill".to_vec(),
                    vec![b'a'; 4000],
                    HpackEncoder::WITH_INDEXING,
                ),
                &mut first_block,
            )
            .unwrap();

        let mut second_block = Vec::new();
        for (name, value) in [
            (b":method".as_slice(), b"GET".as_slice()),
            (b":scheme".as_slice(), b"https".as_slice()),
            (b":authority".as_slice(), b"api.openai.com".as_slice()),
            (b":path".as_slice(), b"/".as_slice()),
        ] {
            encoder
                .encode(
                    (name.to_vec(), value.to_vec(), HpackEncoder::NEVER_INDEXED),
                    &mut second_block,
                )
                .unwrap();
        }
        for _ in 0..20 {
            encoder.encode(62u32, &mut second_block).unwrap();
        }

        let mut request = HTTP2_PREFACE.to_vec();
        append_http2_frame(&mut request, 0x4, 0, 0, &[]).unwrap();
        append_http2_header_frames(&mut request, 1, true, &first_block).unwrap();
        append_http2_header_frames(&mut request, 3, true, &second_block).unwrap();

        assert_eq!(
            handler.substitute(&request).unwrap_err(),
            ViolationAction::Block
        );
    }

    #[test]
    fn tls_intercepted_http2_limits_concurrent_open_streams() {
        let ip = Ipv4Addr::new(203, 0, 113, 44);
        let shared = SharedState::new(16);
        cache_host(&shared, "api.openai.com", ip);
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler =
            SecretsHandler::new_tls_intercepted(&config, "api.openai.com", IpAddr::V4(ip), &shared);

        let mut request = HTTP2_PREFACE.to_vec();
        append_http2_frame(&mut request, 0x4, 0, 0, &[]).unwrap();
        for i in 0..=MAX_HTTP2_TRACKED_STREAMS {
            append_h2_headers(
                &mut request,
                1 + (i as u32 * 2),
                &[
                    (b":method", b"POST"),
                    (b":scheme", b"https"),
                    (b":authority", b"api.openai.com"),
                    (b":path", b"/"),
                ],
                false,
            );
        }

        assert_eq!(
            handler.substitute(&request).unwrap_err(),
            ViolationAction::Block
        );
    }

    #[test]
    fn tls_intercepted_http2_closed_streams_release_tracking_state() {
        let ip = Ipv4Addr::new(203, 0, 113, 45);
        let shared = SharedState::new(16);
        cache_host(&shared, "api.openai.com", ip);
        let config = make_config(vec![make_secret("$KEY", "real-secret", "api.openai.com")]);
        let mut handler =
            SecretsHandler::new_tls_intercepted(&config, "api.openai.com", IpAddr::V4(ip), &shared);

        let mut request = HTTP2_PREFACE.to_vec();
        append_http2_frame(&mut request, 0x4, 0, 0, &[]).unwrap();
        for i in 0..=MAX_HTTP2_TRACKED_STREAMS {
            append_h2_headers(
                &mut request,
                1 + (i as u32 * 2),
                &[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", b"api.openai.com"),
                    (b":path", b"/"),
                ],
                true,
            );
        }

        assert!(handler.substitute(&request).is_ok());
    }

    #[test]
    fn chunked_body_internal_terminator_bytes_do_not_end_request() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "example.com")]);
        let mut handler = SecretsHandler::new(&config, "example.com", true);

        let chunk1 = b"POST /a HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n";
        handler.substitute(chunk1).unwrap();

        let mut chunk2 = b"B\r\nAA\r\n0\r\n\r\nBB\r\n0\r\n\r\n".to_vec();
        chunk2.extend_from_slice(b"GET /b HTTP/1.1\r\nHost: example.com\r\nAuth: $KEY\r\n\r\n");

        let out = handler.substitute(&chunk2).unwrap();

        let mut expected = b"B\r\nAA\r\n0\r\n\r\nBB\r\n0\r\n\r\n".to_vec();
        expected.extend_from_slice(
            b"GET /b HTTP/1.1\r\nHost: example.com\r\nAuth: real-secret\r\n\r\n",
        );
        assert_eq!(out.as_ref(), expected.as_slice());
    }

    #[test]
    fn split_chunked_terminator_resumes_next_request() {
        let config = make_config(vec![make_secret("$KEY", "real-secret", "example.com")]);
        let mut handler = SecretsHandler::new(&config, "example.com", true);

        let chunk1 = b"POST /a HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n";
        handler.substitute(chunk1).unwrap();

        let chunk2 = b"5\r\nhello\r\n0\r";
        let out2 = handler.substitute(chunk2).unwrap();
        assert_eq!(out2.as_ref(), chunk2.as_slice());

        let mut chunk3 = b"\n\r\n".to_vec();
        chunk3.extend_from_slice(b"GET /b HTTP/1.1\r\nHost: example.com\r\nAuth: $KEY\r\n\r\n");

        let out3 = handler.substitute(&chunk3).unwrap();

        let mut expected = b"\n\r\n".to_vec();
        expected.extend_from_slice(
            b"GET /b HTTP/1.1\r\nHost: example.com\r\nAuth: real-secret\r\n\r\n",
        );
        assert_eq!(out3.as_ref(), expected.as_slice());
    }
}
