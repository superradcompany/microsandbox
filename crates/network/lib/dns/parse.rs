//! User-facing nameserver type and parsing.
//!
//! A nameserver can be configured by IP or hostname, with an optional port.
//! Hostnames are resolved at interceptor startup using the host's own
//! resolver — never the interceptor itself — so there is no bootstrap loop.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Default DNS port (used when a spec omits `:PORT`).
const DEFAULT_DNS_PORT: u16 = 53;

/// A nameserver — either a literal address or a hostname to resolve later.
///
/// Serializes as a single string (`"1.1.1.1"`, `"1.1.1.1:53"`,
/// `"dns.google"`, `"dns.google:53"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nameserver {
    /// A literal socket address, ready to use.
    Addr(SocketAddr),
    /// A hostname + port to be resolved at startup via the host's resolver.
    Host {
        /// DNS name to resolve.
        host: String,
        /// UDP/TCP port to connect on.
        port: u16,
    },
}

impl Nameserver {
    /// Resolve to a concrete `SocketAddr`. `Addr` returns immediately;
    /// `Host` performs a lookup via the host's OS resolver (not this
    /// interceptor — avoids bootstrap recursion) and returns the first
    /// address.
    pub async fn resolve(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Addr(sa) => Ok(*sa),
            Self::Host { host, port } => tokio::net::lookup_host((host.as_str(), *port))
                .await?
                .next()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("no addresses resolved for {host}:{port}"),
                    )
                }),
        }
    }
}

impl fmt::Display for Nameserver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Addr(sa) => write!(f, "{sa}"),
            Self::Host { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

/// Error returned when a user-supplied nameserver string can't be parsed.
#[derive(Debug, thiserror::Error)]
#[error("invalid nameserver {0:?}; expected IP, IP:PORT, HOST, or HOST:PORT")]
pub struct ParseNameserverError(pub String);

/// Parse a user-supplied nameserver string.
///
/// Accepted forms:
/// - `1.1.1.1` — IPv4, port defaults to 53
/// - `1.1.1.1:5353` — IPv4 with explicit port
/// - `2606:4700:4700::1111` — IPv6 (bare)
/// - `[2606:4700:4700::1111]:53` — IPv6 with port (brackets required)
/// - `dns.google` — hostname, port defaults to 53
/// - `dns.google:53` — hostname with port
impl FromStr for Nameserver {
    type Err = ParseNameserverError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let s = input.trim();
        if s.is_empty() {
            return Err(ParseNameserverError(input.to_owned()));
        }

        // IP:PORT or [IPv6]:PORT.
        if let Ok(sa) = s.parse::<SocketAddr>() {
            return Ok(Self::Addr(sa));
        }

        // Bare IPv4 / IPv6.
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(Self::Addr(SocketAddr::new(ip, DEFAULT_DNS_PORT)));
        }

        // HOST:PORT. `rsplit_once` so we don't get confused by port-less IPv6
        // forms (those are handled above). Reject when the host segment would
        // itself parse as an IPv6 address — that means the user wrote a bare
        // v6 literal without brackets and the `:` is an IPv6 separator.
        if let Some((host, port)) = s.rsplit_once(':')
            && !host.is_empty()
            && !host.contains(':')
            && host.parse::<IpAddr>().is_err()
            && let Ok(port) = port.parse::<u16>()
        {
            return Ok(Self::Host {
                host: host.to_owned(),
                port,
            });
        }

        // Bare hostname. Reject anything with whitespace or characters that
        // couldn't form a DNS label.
        if !s.contains(char::is_whitespace) && !s.contains(':') {
            return Ok(Self::Host {
                host: s.to_owned(),
                port: DEFAULT_DNS_PORT,
            });
        }

        Err(ParseNameserverError(input.to_owned()))
    }
}

// Serialize as a single string ("1.1.1.1:53" or "dns.google:53") so
// config files stay flat and readable.
impl Serialize for Nameserver {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Nameserver {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

// Ergonomic conversions for Rust builder callers.
impl From<SocketAddr> for Nameserver {
    fn from(sa: SocketAddr) -> Self {
        Self::Addr(sa)
    }
}

impl From<IpAddr> for Nameserver {
    fn from(ip: IpAddr) -> Self {
        Self::Addr(SocketAddr::new(ip, DEFAULT_DNS_PORT))
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Nameserver, ParseNameserverError> {
        s.parse()
    }

    fn addr(s: &str) -> Nameserver {
        Nameserver::Addr(s.parse().unwrap())
    }

    fn host(host: &str, port: u16) -> Nameserver {
        Nameserver::Host {
            host: host.to_owned(),
            port,
        }
    }

    #[test]
    fn parses_ipv4_bare() {
        assert_eq!(parse("1.1.1.1").unwrap(), addr("1.1.1.1:53"));
    }

    #[test]
    fn parses_ipv4_with_port() {
        assert_eq!(parse("8.8.8.8:5353").unwrap(), addr("8.8.8.8:5353"));
    }

    #[test]
    fn parses_ipv6_bare() {
        assert_eq!(
            parse("2606:4700:4700::1111").unwrap(),
            addr("[2606:4700:4700::1111]:53")
        );
    }

    #[test]
    fn parses_ipv6_bracketed_with_port() {
        assert_eq!(
            parse("[2606:4700:4700::1111]:53").unwrap(),
            addr("[2606:4700:4700::1111]:53")
        );
    }

    #[test]
    fn parses_hostname_bare() {
        assert_eq!(parse("dns.google").unwrap(), host("dns.google", 53));
    }

    #[test]
    fn parses_hostname_with_port() {
        assert_eq!(parse("dns.google:53").unwrap(), host("dns.google", 53));
        assert_eq!(
            parse("my-dns.corp.internal:5353").unwrap(),
            host("my-dns.corp.internal", 5353)
        );
    }

    #[test]
    fn trims_whitespace() {
        assert_eq!(parse("  1.1.1.1  ").unwrap(), addr("1.1.1.1:53"));
    }

    #[test]
    fn rejects_empty() {
        assert!(parse("").is_err());
        assert!(parse("   ").is_err());
    }

    #[test]
    fn rejects_embedded_whitespace() {
        assert!(parse("dns google").is_err());
    }

    #[test]
    fn rejects_bad_port() {
        assert!(parse("dns.google:notaport").is_err());
        assert!(parse("1.1.1.1:99999").is_err());
    }

    #[test]
    fn display_roundtrip() {
        for s in ["1.1.1.1:53", "[2606:4700:4700::1111]:53", "dns.google:53"] {
            let spec = parse(s).unwrap();
            assert_eq!(spec.to_string(), s);
        }
    }

    #[test]
    fn display_feeds_back_into_parse() {
        for s in ["1.1.1.1", "dns.google", "dns.google:53"] {
            let spec = parse(s).unwrap();
            // Display output round-trips to the same spec via parse.
            let reparsed = parse(&spec.to_string()).unwrap();
            assert_eq!(spec, reparsed);
        }
    }
}
