//! Ambient host HTTP CONNECT proxy discovery from the launching environment.
//!
//! This module is runtime-only. It reads `https_proxy`/`http_proxy`/`all_proxy`
//! (lowercase wins over uppercase) plus `no_proxy` once per network-engine
//! startup, builds the generic [`ResolvedOutboundProxy::HttpConnectEndpoint`]
//! leaf with this origin's outer budget, and never serializes the result.
//! Discovery failure is not a routing failure: unusable settings are ignored
//! with a credential-free warning and direct routing stays available.

use std::{
    mem,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use ipnetwork::IpNetwork;
use microsandbox_types::SecretValue;
use zeroize::Zeroizing;

use super::http_connect::{ConnectAddress, ConnectBudget};
use super::{ResolvedHttpConnectCredentials, ResolvedHttpConnectEndpoint, ResolvedOutboundProxy};
use crate::engine::netstack::shared::SharedState;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const HTTPS_PROXY: &str = "HTTPS_PROXY";
const HTTP_PROXY: &str = "HTTP_PROXY";
const ALL_PROXY: &str = "ALL_PROXY";
const NO_PROXY: &str = "NO_PROXY";

/// Message emitted once when proxy settings exist but none of them are usable.
const UNUSABLE_SETTINGS_WARNING: &str =
    "ignoring unusable host HTTP proxy settings; guest egress will connect directly";

/// Total budget for one discovered CONNECT exchange: host DNS, TCP connect,
/// request write/flush and response negotiation.
const AMBIENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Message reported when a discovered CONNECT exchange exceeds its budget.
const AMBIENT_CONNECT_TIMEOUT_MESSAGE: &str =
    "ambient host HTTP proxy connection did not complete within 30 seconds";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// An HTTP CONNECT proxy discovered from the launching host environment.
///
/// Holds one leaf transport per destination class plus the parsed `NO_PROXY`
/// rules. Every field is runtime-only, so the aggregate is neither serializable
/// nor debuggable through the values it holds.
#[doc(hidden)]
#[derive(Clone)]
pub struct AmbientHttpProxy {
    http: Arc<ResolvedOutboundProxy>,
    https: Arc<ResolvedOutboundProxy>,
    no_proxy: NoProxy,
}

/// Winning raw value for each proxy-related host environment variable.
///
/// Case precedence is already applied: each field holds the trimmed lowercase
/// value or, when that is absent, the trimmed uppercase spelling. All raw values
/// use the shared redacting, zeroizing secret wrapper: proxy URLs may carry
/// credentials, and `NO_PROXY` rules may reveal internal hostnames. Derived
/// `Debug` therefore reports presence without exposing these values.
#[derive(Debug, Default)]
struct ProxyEnvironment {
    https: Option<SecretValue>,
    http: Option<SecretValue>,
    all: Option<SecretValue>,
    no_proxy: Option<SecretValue>,
}

/// Parsed `NO_PROXY` rules.
///
/// A rule is either the `*` wildcard, an IP/network, or a domain name that
/// matches itself and its dot-delimited subdomains.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct NoProxy {
    wildcard: bool,
    names: Vec<String>,
    networks: Vec<IpNetwork>,
}

/// Result of one discovery pass, including the credential-free warning messages.
///
/// Each destination class is a shared leaf so fallback selection clones the
/// `Arc` rather than the endpoint credentials.
struct DiscoveredProxy {
    http: Option<Arc<ResolvedOutboundProxy>>,
    https: Option<Arc<ResolvedOutboundProxy>>,
    no_proxy: NoProxy,
    warnings: Vec<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AmbientHttpProxy {
    /// Discover the ambient proxy from the current process environment.
    ///
    /// Reads the environment exactly once. Returns `None` when no usable endpoint
    /// is configured, which keeps guest egress direct.
    pub(crate) fn from_env() -> Option<Self> {
        Self::from_values(ProxyEnvironment::from_env())
    }

    /// Return whether this destination must connect directly instead of proxied.
    ///
    /// The guest destination IP is authoritative for IP/CIDR/wildcard rules.
    /// Domain rules need a live DNS-index name for that IP because the engine
    /// dials at the guest SYN, before any SNI or host header exists. With no
    /// known name, domain-only exceptions cannot apply.
    pub(crate) fn bypasses(
        &self,
        guest_dst: SocketAddr,
        host_dst: SocketAddr,
        shared: &SharedState,
    ) -> bool {
        if is_local_dial_address(host_dst.ip()) {
            return true;
        }

        let guest_ip = guest_dst.ip();
        if self.no_proxy.matches_ip(guest_ip) {
            return true;
        }
        if self.no_proxy.names.is_empty() {
            return false;
        }

        shared.any_resolved_hostname(guest_ip, |name| self.no_proxy.matches_name(name))
    }

    /// Select the TLS or ordinary-TCP leaf transport.
    pub(crate) fn endpoint(&self, tls: bool) -> Arc<ResolvedOutboundProxy> {
        if tls {
            Arc::clone(&self.https)
        } else {
            Arc::clone(&self.http)
        }
    }
}

impl ProxyEnvironment {
    /// Read the winning value of every proxy and `NO_PROXY` variable.
    fn from_env() -> Self {
        Self::capture(environment_value)
    }

    /// Capture each variable's winner through an injectable lookup.
    ///
    /// Precedence is decided here, before any endpoint parsing, so a nonempty
    /// but unusable lowercase value still suppresses the uppercase spelling.
    fn capture(mut lookup: impl FnMut(&str) -> Option<Zeroizing<String>>) -> Self {
        Self {
            https: capture_variable(&mut lookup, "https_proxy", HTTPS_PROXY)
                .map(|mut value| SecretValue(mem::take(&mut *value))),
            http: capture_variable(&mut lookup, "http_proxy", HTTP_PROXY)
                .map(|mut value| SecretValue(mem::take(&mut *value))),
            all: capture_variable(&mut lookup, "all_proxy", ALL_PROXY)
                .map(|mut value| SecretValue(mem::take(&mut *value))),
            no_proxy: capture_variable(&mut lookup, "no_proxy", NO_PROXY)
                .map(|mut value| SecretValue(mem::take(&mut *value))),
        }
    }
}

impl AmbientHttpProxy {
    /// Resolve discovered values into the two destination-class leaves.
    ///
    /// Discovery reports both classes together or neither, so preference stays in
    /// one place: `discover` already applied the per-scheme fallback order.
    fn from_values(values: ProxyEnvironment) -> Option<Self> {
        let discovered = discover(values);
        for warning in &discovered.warnings {
            tracing::warn!("{warning}");
        }

        Some(Self {
            http: discovered.http?,
            https: discovered.https?,
            no_proxy: discovered.no_proxy,
        })
    }
}

impl NoProxy {
    /// Parse comma- or ASCII-whitespace-separated rules.
    fn parse(value: &str) -> Self {
        let mut no_proxy = Self::default();

        for token in value
            .split(|character: char| character == ',' || character.is_ascii_whitespace())
            .map(str::trim)
            .filter(|token| !token.is_empty())
        {
            if token == "*" {
                no_proxy.wildcard = true;
                continue;
            }

            // Numeric ports are not restrictions in this syntax, so they are dropped.
            let token = strip_no_proxy_port(token);
            if let Some(network) = parse_network(token) {
                no_proxy.networks.push(network);
                continue;
            }

            let name = token.trim_matches('.').to_ascii_lowercase();
            if !name.is_empty() {
                no_proxy.names.push(name);
            }
        }

        no_proxy
    }

    /// Match a known server name and the guest destination IP against these rules.
    ///
    /// This is the pure matcher the runtime bypass decision is built from; it takes
    /// the name explicitly so tests can exercise every rule shape without a DNS index.
    #[cfg(test)]
    fn matches(&self, server_name: Option<&str>, guest_ip: IpAddr) -> bool {
        if self.wildcard || self.matches_ip(guest_ip) {
            return true;
        }

        server_name.is_some_and(|server_name| self.matches_name(server_name))
    }

    /// Match IP, CIDR and wildcard rules against the guest destination IP.
    fn matches_ip(&self, guest_ip: IpAddr) -> bool {
        if self.wildcard {
            return true;
        }

        let guest_ip = normalize_ip(guest_ip);
        self.networks
            .iter()
            .any(|network| network.contains(guest_ip))
    }

    /// Match an exact or dot-delimited subdomain rule name.
    fn matches_name(&self, server_name: &str) -> bool {
        let server_name = server_name.trim_end_matches('.').to_ascii_lowercase();
        self.names.iter().any(|name| {
            server_name == *name
                || server_name
                    .strip_suffix(name)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Split discovery from warning emission so tests can inspect both outcomes.
fn discover(values: ProxyEnvironment) -> DiscoveredProxy {
    let ProxyEnvironment {
        https,
        http,
        all,
        no_proxy,
    } = values;

    let mut warnings = Vec::new();
    let had_proxy_value = https.is_some() || http.is_some() || all.is_some();

    // Parse every selected variable, including one a preferred endpoint makes
    // unused: an unusable value is still reported for its own variable.
    let mut parse = |name: &str, value: Option<&SecretValue>| match value {
        None => None,
        Some(value) => match parse_endpoint(value.0.as_str()) {
            Ok(endpoint) => Some(Arc::new(ResolvedOutboundProxy::HttpConnectEndpoint {
                endpoint,
            })),
            Err(reason) => {
                warnings.push(format!("ignoring unusable {name}: {reason}"));
                None
            }
        },
    };

    let https = parse(HTTPS_PROXY, https.as_ref());
    let http = parse(HTTP_PROXY, http.as_ref());
    let all = parse(ALL_PROXY, all.as_ref());

    let no_proxy = NoProxy::parse(
        no_proxy
            .as_ref()
            .map(|value| value.0.as_str())
            .unwrap_or_default(),
    );

    // TLS destinations prefer HTTPS, then ALL, then HTTP; ordinary TCP prefers
    // HTTP, then ALL, then HTTPS. The cross-fallback only uses parsed endpoints.
    let https_endpoint = https
        .clone()
        .or_else(|| all.clone())
        .or_else(|| http.clone());
    let http_endpoint = http.or_else(|| all.clone()).or_else(|| https.clone());

    if (https_endpoint.is_none() || http_endpoint.is_none()) && had_proxy_value {
        warnings.push(UNUSABLE_SETTINGS_WARNING.to_string());
    }

    DiscoveredProxy {
        http: http_endpoint,
        https: https_endpoint,
        no_proxy,
        warnings,
    }
}

/// Select one variable's winner, reading the uppercase spelling only when the
/// lowercase value is absent or blank.
fn capture_variable(
    lookup: &mut impl FnMut(&str) -> Option<Zeroizing<String>>,
    lowercase: &str,
    uppercase: &str,
) -> Option<Zeroizing<String>> {
    lookup(lowercase)
        .and_then(trimmed_value)
        .or_else(|| lookup(uppercase).and_then(trimmed_value))
}

fn trimmed_value(value: Zeroizing<String>) -> Option<Zeroizing<String>> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| Zeroizing::new(trimmed.to_owned()))
}

fn environment_value(name: &str) -> Option<Zeroizing<String>> {
    // Missing or non-Unicode values are treated as absent, matching host tooling
    // that ignores malformed proxy variables.
    let value = std::env::var_os(name)?.into_string().ok()?;
    Some(Zeroizing::new(value))
}

/// Parse one proxy URL into a runtime-only endpoint.
///
/// Only `http://` (or a scheme-less value) is supported. Path, query and
/// fragment components are discarded; the last `@` separates URL userinfo. The
/// endpoint dials the host name through the host resolver and carries this
/// origin's 30-second outer budget; neither choice is inferred from the address
/// form.
fn parse_endpoint(raw: &str) -> Result<ResolvedHttpConnectEndpoint, &'static str> {
    let raw = raw.trim();
    let (scheme, remainder) = match raw.split_once("://") {
        Some((scheme, remainder)) => (Some(scheme), remainder),
        None => (None, raw),
    };
    if scheme.is_some_and(|scheme| !scheme.eq_ignore_ascii_case("http")) {
        return Err("unsupported proxy scheme (only http:// is supported)");
    }

    let authority = remainder
        .split(['/', '?', '#'])
        .next()
        .ok_or("missing proxy host")?;
    let (userinfo, host_port) = authority
        .rsplit_once('@')
        .map_or((None, authority), |parts| (Some(parts.0), parts.1));
    let (host, port) = parse_host_port(host_port).ok_or("invalid proxy host or port")?;
    let credentials = userinfo.map(basic_credentials);

    Ok(ResolvedHttpConnectEndpoint::new(
        ConnectAddress::Host { name: host, port },
        credentials,
        Some(ConnectBudget {
            total: AMBIENT_CONNECT_TIMEOUT,
            timeout_message: AMBIENT_CONNECT_TIMEOUT_MESSAGE,
        }),
    ))
}

/// Parse a proxy `host[:port]` authority with a default port of 80.
fn parse_host_port(value: &str) -> Option<(String, u16)> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    if let Some(value) = value.strip_prefix('[') {
        let (host, suffix) = value.split_once(']')?;
        let host = host.parse::<Ipv6Addr>().ok()?.to_string();
        let port = match suffix {
            "" => 80,
            _ => suffix.strip_prefix(':')?.parse().ok()?,
        };
        return (port != 0).then_some((host, port));
    }

    if value.matches(':').count() > 1 {
        let host = value.parse::<Ipv6Addr>().ok()?.to_string();
        return Some((host, 80));
    }

    let (host, port) = match value.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => (host, port.parse().ok()?),
        Some(_) => return None,
        None => (value, 80),
    };
    if host
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || port == 0
    {
        return None;
    }

    Some((host.to_ascii_lowercase(), port))
}

/// Decode one URL userinfo component into zeroized UTF-8.
///
/// Decoded bytes never exceed the encoded length, so that buffer is sized once. The lossy
/// UTF-8 conversion also preallocates its worst case (three bytes per decoded byte, one
/// U+FFFD per invalid byte) and is filled without ever growing: a growing `String` frees
/// the smaller block, which already holds the valid prefix of the secret, before
/// `Zeroizing` can wipe it. The decoded bytes stay protected until the final string exists.
fn decode_userinfo_component(value: &str) -> Zeroizing<String> {
    let mut decoded = Zeroizing::new(Vec::with_capacity(value.len()));
    decoded.extend(percent_encoding::percent_decode_str(value));

    let mut lossy = Zeroizing::new(String::with_capacity(decoded.len() * 3));
    for chunk in decoded.utf8_chunks() {
        lossy.push_str(chunk.valid());
        if !chunk.invalid().is_empty() {
            lossy.push('\u{FFFD}');
        }
    }
    lossy
}

/// Decode URL userinfo into Basic authentication credentials.
///
/// Empty username or password components are preserved, so `http://@proxy`
/// produces the `:` credential pair. Temporary decoding buffers are zeroized.
fn basic_credentials(userinfo: &str) -> ResolvedHttpConnectCredentials {
    let (username, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
    let mut username = decode_userinfo_component(username);
    let mut password = decode_userinfo_component(password);

    ResolvedHttpConnectCredentials::new(mem::take(&mut *username), mem::take(&mut *password))
}

/// Remove a trailing numeric `:port` from a `NO_PROXY` token.
///
/// Ports are not restrictions in this syntax, so they never affect matching.
fn strip_no_proxy_port(token: &str) -> &str {
    if let Some(bracketed) = token.strip_prefix('[') {
        if let Some((host, suffix)) = bracketed.split_once(']')
            && (suffix.is_empty() || suffix.strip_prefix(':').is_some())
        {
            return host;
        }
        return token;
    }

    match token.rsplit_once(':') {
        Some((host, port))
            if !host.contains(':') && port.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            host
        }
        _ => token,
    }
}

fn parse_network(token: &str) -> Option<IpNetwork> {
    // `IpNetwork` already accepts a bare address and applies its host prefix.
    let network = token.parse::<IpNetwork>().ok()?;
    Some(normalize_network(network))
}

/// Map IPv4-mapped IPv6 networks with a prefix of at least 96 onto IPv4.
///
/// Normalization always preserves the input when no mapping applies.
fn normalize_network(network: IpNetwork) -> IpNetwork {
    let IpNetwork::V6(v6) = network else {
        return network;
    };
    let Some(mapped) = v6.network().to_ipv4_mapped() else {
        return network;
    };
    if v6.prefix() < 96 {
        return network;
    }

    IpNetwork::new(IpAddr::V4(mapped), v6.prefix() - 96).unwrap_or(network)
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        IpAddr::V4(_) => ip,
    }
}

/// Host dial targets that must stay direct regardless of `NO_PROXY`.
fn is_local_dial_address(ip: IpAddr) -> bool {
    let ip = normalize_ip(ip);
    ip.is_loopback() || ip.is_unspecified() || is_link_local(ip)
}

fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_link_local(),
        IpAddr::V6(ip) => (ip.segments()[0] & 0xffc0) == 0xfe80,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
impl AmbientHttpProxy {
    /// Build an ambient proxy from explicit values for crate tests.
    ///
    /// Never reads the process environment, so tests stay deterministic and
    /// parallel-safe.
    pub(crate) fn from_test_values(url: &str, no_proxy: Option<&str>) -> Option<Self> {
        Self::from_test_values_split(url, None, no_proxy)
    }

    /// Build an ambient proxy from distinct ordinary/TLS URLs for crate tests.
    pub(crate) fn from_test_values_split(
        http: &str,
        https: Option<&str>,
        no_proxy: Option<&str>,
    ) -> Option<Self> {
        Self::from_values(ProxyEnvironment {
            http: Some(SecretValue(http.to_string())),
            https: https.map(|url| SecretValue(url.to_string())),
            no_proxy: no_proxy.map(|rules| SecretValue(rules.to_string())),
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        sync::Arc,
    };

    use ipnetwork::IpNetwork;
    use microsandbox_types::SecretValue;
    use zeroize::Zeroizing;

    use crate::proxy::{ResolvedHttpConnectCredentials, ResolvedOutboundProxy};

    use super::{
        ALL_PROXY, AMBIENT_CONNECT_TIMEOUT, AMBIENT_CONNECT_TIMEOUT_MESSAGE, AmbientHttpProxy,
        HTTP_PROXY, HTTPS_PROXY, NoProxy, ProxyEnvironment, ResolvedHttpConnectEndpoint,
        UNUSABLE_SETTINGS_WARNING, decode_userinfo_component, discover, parse_endpoint,
        parse_host_port, parse_network, strip_no_proxy_port,
    };
    use crate::proxy::http_connect::ConnectAddress;

    /// Capture a snapshot through the real lowercase-before-uppercase precedence path.
    fn captured(pairs: &[(&str, &str)]) -> ProxyEnvironment {
        ProxyEnvironment::capture(|name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| zeroized(value))
        })
    }

    /// Capture a snapshot that sets only `http_proxy`.
    fn http_only(value: &str) -> ProxyEnvironment {
        captured(&[("http_proxy", value)])
    }

    /// Read back one variable's captured winner, keyed by its lowercase spelling.
    fn captured_value<'a>(environment: &'a ProxyEnvironment, lowercase: &str) -> Option<&'a str> {
        match lowercase {
            "https_proxy" => environment.https.as_ref().map(|value| value.0.as_str()),
            "http_proxy" => environment.http.as_ref().map(|value| value.0.as_str()),
            "all_proxy" => environment.all.as_ref().map(|value| value.0.as_str()),
            "no_proxy" => environment.no_proxy.as_ref().map(|value| value.0.as_str()),
            _ => panic!("unknown variable {lowercase}"),
        }
    }

    fn zeroized(value: &str) -> Zeroizing<String> {
        Zeroizing::new(value.to_string())
    }

    #[test]
    fn capture_selects_lowercase_then_uppercase_for_every_variable() {
        // Every variable follows the same table: both spellings absent, uppercase-only,
        // a blank lowercase value that still falls back, and a nonempty lowercase value
        // that wins raw and is trimmed.
        for (lowercase, uppercase) in [
            ("https_proxy", HTTPS_PROXY),
            ("http_proxy", HTTP_PROXY),
            ("all_proxy", ALL_PROXY),
            ("no_proxy", "NO_PROXY"),
        ] {
            for (lower, upper, expected) in [
                (None, None, None),
                (None, Some("upper"), Some("upper")),
                (Some("  \t "), Some("upper"), Some("upper")),
                (Some("  lower  "), Some("upper"), Some("lower")),
            ] {
                let mut pairs = Vec::with_capacity(2);
                pairs.extend(lower.map(|value| (lowercase, value)));
                pairs.extend(upper.map(|value| (uppercase, value)));
                assert_eq!(
                    captured_value(&captured(&pairs), lowercase),
                    expected,
                    "{lowercase}: lower={lower:?}, upper={upper:?}"
                );
            }
        }
    }

    #[test]
    fn capture_reads_each_spelling_at_most_once() {
        let mut reads = Vec::new();
        let environment = ProxyEnvironment::capture(|name| {
            reads.push(name.to_string());
            match name {
                "http_proxy" => Some(zeroized("http://lower.test:3128")),
                HTTPS_PROXY => Some(zeroized("http://upper.test:3128")),
                _ => None,
            }
        });

        // A winning lowercase value skips its uppercase read; a missing one reads it.
        assert_eq!(
            reads,
            [
                "https_proxy",
                HTTPS_PROXY,
                "http_proxy",
                "all_proxy",
                ALL_PROXY,
                "no_proxy",
                "NO_PROXY",
            ],
            "each spelling must be read at most once"
        );
        assert_eq!(
            captured_value(&environment, "http_proxy"),
            Some("http://lower.test:3128")
        );
        assert_eq!(
            captured_value(&environment, "https_proxy"),
            Some("http://upper.test:3128")
        );
        assert!(environment.all.is_none() && environment.no_proxy.is_none());
    }

    #[test]
    fn invalid_utf8_userinfo_decodes_lossily_without_reallocating() {
        // `%FF` never becomes valid UTF-8. The decoded bytes stay in the zeroizing buffer
        // and reach the credential only through the lossy conversion.
        let endpoint = parse_endpoint("http://us%FFer:secret%FF@proxy.test").unwrap();
        assert_eq!(
            endpoint.credentials,
            Some(ResolvedHttpConnectCredentials::new(
                "us\u{FFFD}er",
                "secret\u{FFFD}"
            ))
        );

        // The conversion allocates its worst case (three bytes per decoded byte) once and
        // never grows: a grown `String` frees the smaller block holding the valid secret
        // prefix before it can be wiped. Exact capacity proves the one allocation sufficed.
        for (encoded, expected) in [
            ("p%40ss%FF", "p@ss\u{FFFD}"),
            ("a%FFb%FEc%80d", "a\u{FFFD}b\u{FFFD}c\u{FFFD}d"),
        ] {
            let decoded_bytes = percent_encoding::percent_decode_str(encoded).count();
            let decoded: Zeroizing<String> = decode_userinfo_component(encoded);
            assert_eq!(decoded.as_str(), expected);
            assert_eq!(decoded.capacity(), decoded_bytes * 3);
        }
    }

    fn endpoint_host(endpoint: &ResolvedHttpConnectEndpoint) -> String {
        match &endpoint.address {
            ConnectAddress::Host { name, port } => format!("{name}:{port}"),
            ConnectAddress::Socket(address) => address.to_string(),
        }
    }

    fn leaf_endpoint(leaf: &ResolvedOutboundProxy) -> &ResolvedHttpConnectEndpoint {
        let ResolvedOutboundProxy::HttpConnectEndpoint { endpoint } = leaf else {
            panic!("discovered proxy must be a runtime HTTP CONNECT leaf");
        };
        endpoint
    }

    /// Host and port of one discovered destination class.
    fn discovered_host(endpoint: Option<&Arc<ResolvedOutboundProxy>>) -> String {
        let leaf = endpoint.expect("expected a discovered proxy leaf");
        endpoint_host(leaf_endpoint(leaf))
    }

    fn selected(proxy: &AmbientHttpProxy, tls: bool) -> &ResolvedHttpConnectEndpoint {
        leaf_endpoint(if tls { &proxy.https } else { &proxy.http })
    }

    #[test]
    fn captured_proxy_settings_redact_credentials_and_internal_hostnames() {
        let environment = captured(&[
            (
                "https_proxy",
                "http://https-user-sentinel:https-pass-sentinel@proxy.test:1",
            ),
            (
                "http_proxy",
                "http://http-user-sentinel:http-pass-sentinel@proxy.test:2",
            ),
            (
                "all_proxy",
                "http://all-user-sentinel:all-pass-sentinel@proxy.test:3",
            ),
            ("no_proxy", ".no-proxy-sentinel.test"),
        ]);

        // Typing each captured URL as `&SecretValue` proves the three raw values
        // use the shared redacting, zeroizing wrapper before any parsing.
        let urls: [(&SecretValue, &str); 3] = [
            (
                environment.https.as_ref().expect("https winner"),
                "https-user-sentinel",
            ),
            (
                environment.http.as_ref().expect("http winner"),
                "http-user-sentinel",
            ),
            (
                environment.all.as_ref().expect("all winner"),
                "all-user-sentinel",
            ),
        ];
        for (value, sentinel) in urls {
            let debug = format!("{value:?}");
            assert_eq!(debug, "[redacted]");
            assert!(!debug.contains(sentinel), "{sentinel} leaked: {debug}");
        }

        // Rules may reveal internal hostnames, so they use the same redacting wrapper.
        let rules: &SecretValue = environment.no_proxy.as_ref().expect("no_proxy winner");
        assert_eq!(rules.0, ".no-proxy-sentinel.test");
        assert_eq!(format!("{rules:?}"), "[redacted]");

        assert_eq!(
            format!("{environment:?}"),
            "ProxyEnvironment { https: Some([redacted]), http: Some([redacted]), all: Some([redacted]), no_proxy: Some([redacted]) }"
        );
        assert_eq!(
            format!("{:?}", ProxyEnvironment::default()),
            "ProxyEnvironment { https: None, http: None, all: None, no_proxy: None }"
        );

        // An unsupported raw URL is retained and redacted the same way while its
        // warning stays credential-free.
        let unsupported =
            http_only("socks5://socks-user-sentinel:socks-pass-sentinel@proxy.test:1080");
        let raw: &SecretValue = unsupported.http.as_ref().expect("captured raw value");
        let debug = format!("{raw:?}");
        assert_eq!(debug, "[redacted]");
        assert!(!debug.contains("socks-user-sentinel"), "{debug}");

        let discovered = discover(unsupported);
        assert!(discovered.http.is_none());
        let joined = discovered.warnings.join("\n");
        assert!(
            !joined.contains("socks-user-sentinel") && !joined.contains("socks-pass-sentinel"),
            "{joined}"
        );
    }

    #[test]
    fn lowercase_wins_and_empty_falls_back() {
        let env = captured(&[
            ("http_proxy", "http://lower.test:3128"),
            ("HTTP_PROXY", "http://upper.test:3128"),
        ]);
        let discovered = discover(env);
        assert_eq!(discovered_host(discovered.http.as_ref()), "lower.test:3128");

        let env = captured(&[
            ("http_proxy", "   "),
            ("HTTP_PROXY", "http://upper.test:8080"),
        ]);
        assert_eq!(
            discovered_host(discover(env).http.as_ref()),
            "upper.test:8080"
        );

        // A nonempty malformed lowercase value suppresses a usable uppercase one.
        let env = captured(&[
            ("http_proxy", "socks5://lower.test:1080"),
            ("HTTP_PROXY", "http://upper.test:3128"),
        ]);
        let discovered = discover(env);
        assert!(discovered.http.is_none());
        assert_eq!(discovered.warnings.len(), 2, "{:?}", discovered.warnings);
        assert!(discovered.warnings[0].contains(HTTP_PROXY));
        assert!(discovered.warnings[0].contains("unsupported proxy scheme"));
        assert!(
            discovered
                .warnings
                .contains(&UNUSABLE_SETTINGS_WARNING.to_string())
        );
    }

    #[test]
    fn per_scheme_and_cross_scheme_preferences_apply_to_parsed_values() {
        let env = || {
            captured(&[
                ("http_proxy", "http://h.test:1"),
                ("https_proxy", "http://s.test:2"),
                ("all_proxy", "http://a.test:3"),
            ])
        };

        let proxy = AmbientHttpProxy::from_values(env()).unwrap();
        assert_eq!(endpoint_host(selected(&proxy, true)), "s.test:2");
        assert_eq!(endpoint_host(selected(&proxy, false)), "h.test:1");

        // Unsupported specific value falls back to ALL, then to the opposite variable.
        let env = || {
            captured(&[
                ("http_proxy", "http://h.test:1"),
                ("https_proxy", "socks4://bad:9"),
                ("all_proxy", "http://a.test:3"),
            ])
        };
        let discovered = discover(env());
        assert_eq!(discovered.warnings.len(), 1, "{:?}", discovered.warnings);
        assert!(discovered.warnings[0].contains(HTTPS_PROXY));
        let proxy = AmbientHttpProxy::from_values(env()).unwrap();
        assert_eq!(endpoint_host(selected(&proxy, true)), "a.test:3");
        assert_eq!(endpoint_host(selected(&proxy, false)), "h.test:1");

        let env = || {
            captured(&[
                ("https_proxy", "socks4://bad:9"),
                ("all_proxy", "http://a.test:3"),
            ])
        };
        let proxy = AmbientHttpProxy::from_values(env()).unwrap();
        assert_eq!(endpoint_host(selected(&proxy, true)), "a.test:3");
        assert_eq!(endpoint_host(selected(&proxy, false)), "a.test:3");

        let env = || captured(&[("all_proxy", "http://a.test:3")]);
        let proxy = AmbientHttpProxy::from_values(env()).unwrap();
        assert_eq!(endpoint_host(selected(&proxy, true)), "a.test:3");
        assert_eq!(endpoint_host(selected(&proxy, false)), "a.test:3");
    }

    #[test]
    fn unusable_settings_warn_without_echoing_values() {
        for raw in [
            "socks5://user:secret@proxy.test:1080",
            "http://proxy.test:0",
            "http://",
        ] {
            let discovered = discover(http_only(raw));
            assert!(discovered.http.is_none());
            for warning in &discovered.warnings {
                assert!(!warning.contains("secret"), "{warning}");
                assert!(!warning.contains("user"), "{warning}");
                assert!(!warning.contains(raw), "{warning}");
            }
            assert!(
                discovered
                    .warnings
                    .contains(&UNUSABLE_SETTINGS_WARNING.to_string())
            );
        }

        // No settings means direct routing and no warning at all.
        let discovered = discover(captured(&[]));
        assert!(discovered.http.is_none() && discovered.https.is_none());
        assert!(discovered.warnings.is_empty());

        // An unused-but-set ALL_PROXY that cannot parse is still reported when a
        // usable specific value wins.
        let discovered = discover(captured(&[
            ("http_proxy", "http://proxy.test:3128"),
            ("all_proxy", "unsupported://proxy.test:1080"),
        ]));
        assert!(discovered.http.is_some());
        assert_eq!(discovered.warnings.len(), 1, "{:?}", discovered.warnings);
        assert!(discovered.warnings[0].contains(ALL_PROXY));
        assert!(
            !discovered
                .warnings
                .iter()
                .any(|w| w == UNUSABLE_SETTINGS_WARNING)
        );
    }

    #[test]
    fn endpoint_parsing_follows_fork_semantics() {
        for (raw, host, port) in [
            ("http://proxy.test:3128", "proxy.test", 3128),
            ("HTTP://Proxy.Test:3128", "proxy.test", 3128),
            ("proxy.test", "proxy.test", 80),
            ("PROXY.test:8080", "proxy.test", 8080),
            ("http://[2001:db8::1]:3128", "2001:db8::1", 3128),
            ("http://[2001:DB8::1]", "2001:db8::1", 80),
            ("2001:db8::1", "2001:db8::1", 80),
            ("http://proxy.test/path?query#frag", "proxy.test", 80),
            ("http://user:pass@proxy.test:3128", "proxy.test", 3128),
            ("http://one@two@proxy.test:3128", "proxy.test", 3128),
        ] {
            let endpoint = parse_endpoint(raw).unwrap_or_else(|reason| panic!("{raw}: {reason}"));
            assert_eq!(endpoint_host(&endpoint), format!("{host}:{port}"), "{raw}");
        }

        for raw in [
            "socks5://proxy.test:1080",
            "https://proxy.test:3128",
            "socks4://proxy.test:1080",
            "http://proxy.test:0",
            "http://proxy.test:65536",
            "http://proxy.test:not-a-port",
            "http://:3128",
            "http://[2001:db8::1",
            "http://proxy .test:3128",
            "http://",
            "",
        ] {
            assert!(parse_endpoint(raw).is_err(), "{raw} must be rejected");
        }

        for (value, expected) in [
            ("proxy.test:3128", Some(("proxy.test".to_string(), 3128))),
            ("proxy.test", Some(("proxy.test".to_string(), 80))),
            ("[::1]:3128", Some(("::1".to_string(), 3128))),
            ("[::1]", Some(("::1".to_string(), 80))),
            ("", None),
            (":3128", None),
        ] {
            assert_eq!(parse_host_port(value), expected, "{value}");
        }
    }

    #[test]
    fn discovery_builds_a_host_address_with_the_thirty_second_budget() {
        let endpoint = parse_endpoint("http://proxy.test:3128").unwrap();
        let ConnectAddress::Host { name, port } = &endpoint.address else {
            panic!("discovered endpoints dial a host name");
        };
        assert_eq!(name, "proxy.test");
        assert_eq!(*port, 3128);

        let budget = endpoint
            .budget
            .expect("discovery attaches its outer budget");
        assert_eq!(budget.total, std::time::Duration::from_secs(30));
        assert_eq!(budget.total, AMBIENT_CONNECT_TIMEOUT);
        assert_eq!(budget.timeout_message, AMBIENT_CONNECT_TIMEOUT_MESSAGE);
    }

    #[test]
    fn endpoint_credentials_preserve_fork_userinfo_behavior() {
        let endpoint = parse_endpoint("http://user:p%40ss@proxy.test").unwrap();
        assert_eq!(
            endpoint.credentials,
            Some(ResolvedHttpConnectCredentials::new("user", "p@ss"))
        );

        // A user-only userinfo is a username with an empty password.
        let endpoint = parse_endpoint("http://user@proxy.test").unwrap();
        assert_eq!(
            endpoint.credentials,
            Some(ResolvedHttpConnectCredentials::new("user", ""))
        );

        // `http://@proxy` keeps the empty pair, which Basic-encodes to `Og==`.
        let endpoint = parse_endpoint("http://@proxy.test").unwrap();
        assert_eq!(
            endpoint.credentials,
            Some(ResolvedHttpConnectCredentials::new("", ""))
        );

        let endpoint = parse_endpoint("http://proxy.test").unwrap();
        assert!(endpoint.credentials.is_none());

        // Percent-encoded non-ASCII userinfo decodes lossily to UTF-8.
        let endpoint = parse_endpoint("http://caf%C3%A9:p%C3%A4ss@proxy.test").unwrap();
        assert_eq!(
            endpoint.credentials,
            Some(ResolvedHttpConnectCredentials::new("café", "päss"))
        );
    }

    #[test]
    fn credentials_never_render_in_debug_or_warnings() {
        let user = "sentinel-user-9f1";
        let password = "sentinel-password-7a3";
        let endpoint =
            parse_endpoint(&format!("http://{user}:{password}@proxy.test:3128")).unwrap();
        let debug = format!("{endpoint:?}");
        assert!(debug.contains("[REDACTED]"), "{debug}");
        for sentinel in [user, password, "c2VudGluZWw="] {
            assert!(!debug.contains(sentinel), "{sentinel} leaked: {debug}");
        }

        let credentials = endpoint.credentials.clone().unwrap();
        let debug = format!("{credentials:?}");
        for sentinel in [user, password] {
            assert!(!debug.contains(sentinel), "{sentinel} leaked: {debug}");
        }

        // The warning path only names variables and reasons.
        let discovered = discover(captured(&[(
            "http_proxy",
            "socks5://sentinel-user-9f1:sentinel-password-7a3@proxy.test:1080",
        )]));
        let joined = discovered.warnings.join("\n");
        assert!(
            !joined.contains(user) && !joined.contains(password),
            "{joined}"
        );
    }

    #[test]
    fn no_proxy_rules_match_every_documented_shape() {
        let guest = |ip: &str| ip.parse::<IpAddr>().unwrap();
        let v4 = guest("203.0.113.9");
        let v6 = guest("2001:db8::9");

        // Wildcard bypasses everything, with or without a name.
        let rules = NoProxy::parse("*");
        assert!(rules.matches(None, v4));
        assert!(rules.matches(Some("anything.test"), v6));

        // Bare names, dot variations, mixed case and trailing dots.
        let rules = NoProxy::parse(".example.test");
        assert!(rules.matches(Some("example.test"), v4));
        assert!(rules.matches(Some("EXAMPLE.TEST"), v4));
        assert!(rules.matches(Some("example.test."), v4));
        assert!(rules.matches(Some("api.example.test"), v4));
        assert!(rules.matches(Some("deep.api.example.test"), v4));
        assert!(!rules.matches(Some("notexample.test"), v4));
        assert!(!rules.matches(Some("example.testing"), v4));
        assert!(!rules.matches(None, v4));

        // Hyphens are ordinary label characters; `*` is not a glob.
        let rules = NoProxy::parse("api-1.example.test");
        assert!(rules.matches(Some("api-1.example.test"), v4));
        assert!(!rules.matches(Some("api-2.example.test"), v4));
        let rules = NoProxy::parse("*.example.test");
        assert!(!rules.matches(Some("api.example.test"), v4));

        // Commas, tabs and newlines separate rules.
        let rules = NoProxy::parse("one.test,\ttwo.test\nthree.test   ");
        assert_eq!(rules.names.len(), 3, "{rules:?}");

        // IPv4, IPv6, bare and bracketed forms; ports are ignored.
        let rules = NoProxy::parse("203.0.113.9,2001:db8::9,[2001:db8::10]:443,127.0.0.1:8080");
        assert!(rules.matches(None, v4));
        assert!(rules.matches(None, v6));
        assert!(rules.matches(None, guest("2001:db8::10")));
        assert!(rules.matches(None, guest("127.0.0.1")));
        assert!(!rules.matches(None, guest("127.0.0.2")));

        // CIDR rules normalize host bits and IPv4-mapped forms.
        let rules = NoProxy::parse("203.0.113.77/24");
        assert!(rules.matches(None, v4));
        assert!(!rules.matches(None, guest("203.0.114.1")));

        let rules = NoProxy::parse("::ffff:203.0.113.0/120");
        assert!(rules.matches(None, v4));
        assert!(rules.matches(None, guest("::ffff:203.0.113.9")));

        // IPv4-mapped guest addresses match plain IPv4 rules.
        let rules = NoProxy::parse("203.0.113.9");
        assert!(rules.matches(None, guest("::ffff:203.0.113.9")));

        // IPv6 local ranges and the link-local boundary.
        let rules = NoProxy::parse("fe80::/10");
        assert!(rules.matches(None, guest("fe80::1")));
        assert!(rules.matches(None, guest("febf::1")));
        assert!(!rules.matches(None, guest("fec0::1")));

        // No rules and no hostname.
        assert!(!NoProxy::default().matches(None, v4));
        assert!(!NoProxy::default().matches(Some("example.test"), v4));
    }

    #[test]
    fn parse_network_accepts_bare_addresses_and_normalizes_mapped_networks() {
        for (token, expected) in [
            ("203.0.113.9", "203.0.113.9/32"),
            ("2001:db8::9", "2001:db8::9/128"),
            ("203.0.113.77/24", "203.0.113.77/24"),
        ] {
            let network = parse_network(token).unwrap_or_else(|| panic!("{token} must parse"));
            assert_eq!(
                network,
                expected.parse::<IpNetwork>().unwrap(),
                "{token} must keep its host prefix and normalized host bits"
            );
        }

        // A bare IPv4-mapped IPv6 address collapses onto its IPv4 form.
        assert_eq!(
            parse_network("::ffff:203.0.113.9").unwrap(),
            "203.0.113.9/32".parse::<IpNetwork>().unwrap()
        );

        // A /96 mapped network becomes the equivalent all-IPv4 network, and the
        // boundary holds: prefixes at or above /96 map, /95 keeps the IPv6 form.
        assert_eq!(
            parse_network("::ffff:203.0.113.0/96").unwrap(),
            "0.0.0.0/0".parse::<IpNetwork>().unwrap()
        );
        let wide = parse_network("::ffff:203.0.113.0/95").unwrap();
        let IpNetwork::V6(wide) = wide else {
            panic!("a /95 mapped network must stay IPv6");
        };
        assert_eq!(wide.prefix(), 95);

        for token in ["not-a-network", "203.0.113.9/33", "2001:db8::/129", ""] {
            assert!(parse_network(token).is_none(), "{token} must not parse");
        }
    }

    #[test]
    fn strip_no_proxy_port_keeps_the_host() {
        for (token, expected) in [
            ("example.test", "example.test"),
            ("example.test:443", "example.test"),
            ("example.test:not-a-port", "example.test:not-a-port"),
            ("[2001:db8::1]", "2001:db8::1"),
            ("[2001:db8::1]:443", "2001:db8::1"),
            ("[2001:db8::1]", "2001:db8::1"),
            ("2001:db8::1", "2001:db8::1"),
            ("[unterminated", "[unterminated"),
        ] {
            assert_eq!(strip_no_proxy_port(token), expected, "{token}");
        }
    }

    #[test]
    fn bypass_uses_ip_rules_and_local_dial_addresses() {
        use crate::engine::netstack::shared::SharedState;

        let shared = SharedState::new(4);
        let origin = SocketAddr::new(Ipv4Addr::new(203, 0, 113, 9).into(), 443);
        let local_origin = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443);

        let proxy = AmbientHttpProxy::from_values(http_only("http://proxy.test:3128")).unwrap();
        assert!(!proxy.bypasses(origin, origin, &shared));
        // Loopback, unspecified, and link-local host dial addresses stay direct.
        assert!(proxy.bypasses(local_origin, local_origin, &shared));
        assert!(proxy.bypasses(
            origin,
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 1),
            &shared
        ));
        assert!(proxy.bypasses(
            origin,
            SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 1),
            &shared
        ));
        assert!(proxy.bypasses(
            origin,
            SocketAddr::new(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).into(), 1),
            &shared
        ));
        // IPv4-mapped loopback normalizes to loopback.
        assert!(proxy.bypasses(
            origin,
            SocketAddr::new("::ffff:127.0.0.1".parse().unwrap(), 1),
            &shared
        ));

        let proxy = AmbientHttpProxy::from_values(captured(&[
            ("http_proxy", "http://proxy.test:3128"),
            ("no_proxy", "203.0.113.0/24"),
        ]))
        .unwrap();
        assert!(proxy.bypasses(origin, origin, &shared));
    }

    #[test]
    fn bypass_requires_a_live_name_for_domain_rules() {
        use std::time::Duration;

        use crate::engine::netstack::shared::{ResolvedHostnameFamily, SharedState};

        let shared = SharedState::new(4);
        let origin = SocketAddr::new(Ipv4Addr::new(203, 0, 113, 9).into(), 443);

        let env = captured(&[
            ("http_proxy", "http://proxy.test:3128"),
            ("no_proxy", ".example.test"),
        ]);
        let proxy = AmbientHttpProxy::from_values(env).unwrap();

        // No known name: domain-only exceptions cannot apply.
        assert!(!proxy.bypasses(origin, origin, &shared));

        shared.cache_resolved_hostname(
            "api.example.test",
            ResolvedHostnameFamily::Ipv4,
            [origin.ip()],
            Duration::from_secs(60),
        );
        assert!(proxy.bypasses(origin, origin, &shared));

        // Any live name for the IP may satisfy a domain rule.
        shared.cache_resolved_hostname(
            "other.test",
            ResolvedHostnameFamily::Ipv4,
            [origin.ip()],
            Duration::from_secs(60),
        );
        assert!(proxy.bypasses(origin, origin, &shared));

        // Expired names do not bypass.
        shared.clear_resolved_hostname("api.example.test", ResolvedHostnameFamily::Ipv4);
        shared.clear_resolved_hostname("other.test", ResolvedHostnameFamily::Ipv4);
        assert!(!proxy.bypasses(origin, origin, &shared));

        // Wildcard and IP rules work without any name.
        let env = captured(&[("http_proxy", "http://proxy.test:3128"), ("no_proxy", "*")]);
        let proxy = AmbientHttpProxy::from_values(env).unwrap();
        assert!(proxy.bypasses(origin, origin, &shared));

        let env = captured(&[
            ("http_proxy", "http://proxy.test:3128"),
            ("no_proxy", "203.0.113.9"),
        ]);
        let proxy = AmbientHttpProxy::from_values(env).unwrap();
        assert!(proxy.bypasses(origin, origin, &shared));
    }

    #[test]
    fn no_proxy_variable_prefers_lowercase() {
        let env = captured(&[
            ("http_proxy", "http://proxy.test:3128"),
            ("no_proxy", ".lower.test"),
            ("NO_PROXY", ".upper.test"),
        ]);
        let proxy = AmbientHttpProxy::from_values(env).unwrap();
        assert!(proxy.no_proxy.matches_name("lower.test"));
        assert!(!proxy.no_proxy.matches_name("upper.test"));
    }
}
