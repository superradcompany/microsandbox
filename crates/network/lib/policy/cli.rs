//! Parser for the `--net-rule` token grammar.
//!
//! See `PLAN-network-policy.md` §CLI Surface. The grammar is:
//!
//! ```text
//! <TOKEN>     := <action>[:<direction>]@<target>[:<proto>[:<ports>]]
//! <action>    := allow | deny
//! <direction> := egress | ingress | any                    (default: egress)
//! <target>    := any | <group> | <ip> | <cidr> | <domain> | domain=<name> | suffix=<domain>
//! <group>     := public | private | loopback | link-local | meta | multicast | host
//! <proto>     := any | tcp | udp | icmpv4 | icmpv6
//! <ports>     := any | <port> | <lo>-<hi>
//! ```
//!
//! Tokens are parsed eagerly. Levenshtein-2 typo suggestions are
//! emitted for unrecognized keywords.

use std::net::IpAddr;
use std::str::FromStr;

use ipnetwork::IpNetwork;

use super::{
    Action, Destination, DestinationGroup, Direction, DomainName, PortRange, Protocol, Rule,
};

//--------------------------------------------------------------------------------------------------
// Errors
//--------------------------------------------------------------------------------------------------

/// Errors surfaced by [`parse_rule_token`].
///
/// Messages include the original token and, where helpful, a
/// Levenshtein-2 suggestion for the closest reserved keyword.
#[derive(Debug, thiserror::Error)]
pub enum RuleParseError {
    /// The token is missing the mandatory `@` separator.
    #[error(
        "rule token `{token}` is missing `@`; expected `<action>[:<direction>]@<target>[:<proto>[:<ports>]]`"
    )]
    MissingAt { token: String },

    /// The action field (left of `@`, before any `:<direction>`) is
    /// not `allow` or `deny`.
    #[error("`{raw}` is not a recognized action. Expected `allow` or `deny`{suggestion}")]
    InvalidAction {
        raw: String,
        suggestion: SuggestionDisplay,
    },

    /// The direction modifier is not `egress`, `ingress`, or `any`.
    #[error(
        "`{raw}` is not a recognized direction. Expected `egress`, `ingress`, or `any`{suggestion}"
    )]
    InvalidDirection {
        raw: String,
        suggestion: SuggestionDisplay,
    },

    /// The target field is empty or doesn't match any recognized form.
    #[error(
        "`{raw}` is not a valid target. Expected: any, a group name (public, private, loopback, link-local, meta, multicast, host), an IP, a CIDR, a domain (with dot), domain=<name>, or suffix=<domain>{suggestion}"
    )]
    InvalidTarget {
        raw: String,
        suggestion: SuggestionDisplay,
    },

    /// A bare single-label token was provided. Use `domain=<name>`
    /// for single-label hostnames to disambiguate from group keywords.
    #[error(
        "`{raw}` is ambiguous (looks like a single-label hostname or a typoed keyword). Use `domain={raw}` to target a literal hostname{suggestion}"
    )]
    AmbiguousBareToken {
        raw: String,
        suggestion: SuggestionDisplay,
    },

    /// `domain=<name>` value didn't parse as a [`DomainName`].
    #[error("invalid domain `{raw}`: {source}")]
    InvalidDomain {
        raw: String,
        #[source]
        source: super::DomainNameError,
    },

    /// CIDR didn't parse.
    #[error("invalid CIDR `{raw}`")]
    InvalidCidr { raw: String },

    /// IP didn't parse.
    #[error("invalid IP address `{raw}`")]
    InvalidIp { raw: String },

    /// The protocol field is not `any`, `tcp`, `udp`, `icmpv4`, or `icmpv6`.
    #[error(
        "`{raw}` is not a recognized protocol. Expected `any`, `tcp`, `udp`, `icmpv4`, or `icmpv6`{suggestion}"
    )]
    InvalidProtocol {
        raw: String,
        suggestion: SuggestionDisplay,
    },

    /// The ports field is not `any`, `<port>`, or `<lo>-<hi>`.
    #[error("`{raw}` is not a valid ports value. Expected `any`, `<port>`, or `<lo>-<hi>`")]
    InvalidPorts { raw: String },

    /// `<lo>-<hi>` had `lo > hi`.
    #[error("invalid port range {lo}..{hi}; lo must be <= hi")]
    InvalidPortRange { lo: u16, hi: u16 },

    /// ICMP protocol used with a direction that has an ingress side
    /// (Ingress or Any). `publisher.rs` has no inbound ICMP path.
    #[error(
        "ingress and any-direction rules do not support ICMP; only TCP (and UDP when UDP publishing lands)"
    )]
    IngressDoesNotSupportIcmp,

    /// Token has trailing fields after `<ports>` (more than 2 colons
    /// on the right of `@`).
    #[error("rule token `{token}` has trailing junk after the ports field")]
    TrailingJunk { token: String },
}

/// Renders an optional Levenshtein-2 suggestion as `". Did you mean
/// 'public'?"` or empty. Used in error messages.
#[derive(Debug)]
pub struct SuggestionDisplay(Option<&'static str>);

impl std::fmt::Display for SuggestionDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(s) => write!(f, ". Did you mean `{s}`?"),
            None => Ok(()),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Public API
//--------------------------------------------------------------------------------------------------

/// Parse one `--net-rule` token into a [`Rule`].
///
/// Returns the first parse failure encountered. Successful tokens
/// produce a fully-formed [`Rule`] with `direction` defaulting to
/// `Egress` if the modifier is omitted, and empty `protocols` /
/// `ports` Vecs when those fields are absent or set to `any`.
pub fn parse_rule_token(token: &str) -> Result<Rule, RuleParseError> {
    let (left, right) = token
        .split_once('@')
        .ok_or_else(|| RuleParseError::MissingAt {
            token: token.to_string(),
        })?;

    let (action, direction) = parse_action_and_direction(left)?;

    let mut right_parts = right.splitn(4, ':');
    let target_raw = right_parts.next().unwrap_or("");
    let proto_raw = right_parts.next();
    let ports_raw = right_parts.next();
    if right_parts.next().is_some() {
        return Err(RuleParseError::TrailingJunk {
            token: token.to_string(),
        });
    }

    let destination = parse_target(target_raw)?;
    let protocols = match proto_raw {
        None => Vec::new(),
        Some(p) => parse_protocol(p)?,
    };
    let ports = match ports_raw {
        None => Vec::new(),
        Some(p) => parse_ports(p)?,
    };

    if matches!(direction, Direction::Ingress | Direction::Any)
        && protocols
            .iter()
            .any(|p| matches!(p, Protocol::Icmpv4 | Protocol::Icmpv6))
    {
        return Err(RuleParseError::IngressDoesNotSupportIcmp);
    }

    Ok(Rule {
        direction,
        destination,
        protocols,
        ports,
        action,
    })
}

/// Parse a comma-separated list of tokens into a Vec of rules. Argv
/// order is preserved (first token = first rule).
pub fn parse_rule_list(comma_separated: &str) -> Result<Vec<Rule>, RuleParseError> {
    comma_separated
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(parse_rule_token)
        .collect()
}

//--------------------------------------------------------------------------------------------------
// Field parsers
//--------------------------------------------------------------------------------------------------

const ACTION_KEYWORDS: &[&str] = &["allow", "deny"];
const DIRECTION_KEYWORDS: &[&str] = &["egress", "ingress", "any"];
const GROUP_KEYWORDS: &[&str] = &[
    "public",
    "private",
    "loopback",
    "link-local",
    "meta",
    "multicast",
    "host",
];
const PROTOCOL_KEYWORDS: &[&str] = &["any", "tcp", "udp", "icmpv4", "icmpv6"];

fn parse_action_and_direction(left: &str) -> Result<(Action, Direction), RuleParseError> {
    let (action_raw, direction_raw) = match left.split_once(':') {
        Some((a, d)) => (a, Some(d)),
        None => (left, None),
    };

    let action = match action_raw {
        "allow" => Action::Allow,
        "deny" => Action::Deny,
        other => {
            return Err(RuleParseError::InvalidAction {
                raw: other.to_string(),
                suggestion: SuggestionDisplay(suggest(other, ACTION_KEYWORDS)),
            });
        }
    };

    let direction = match direction_raw {
        None => Direction::Egress,
        Some("egress") => Direction::Egress,
        Some("ingress") => Direction::Ingress,
        Some("any") => Direction::Any,
        Some(other) => {
            return Err(RuleParseError::InvalidDirection {
                raw: other.to_string(),
                suggestion: SuggestionDisplay(suggest(other, DIRECTION_KEYWORDS)),
            });
        }
    };

    Ok((action, direction))
}

fn parse_target(raw: &str) -> Result<Destination, RuleParseError> {
    if raw.is_empty() {
        return Err(RuleParseError::InvalidTarget {
            raw: raw.to_string(),
            suggestion: SuggestionDisplay(None),
        });
    }

    // 1. `any`
    if raw == "any" {
        return Ok(Destination::Any);
    }

    // 2. Group name
    if let Some(group) = group_from_keyword(raw) {
        return Ok(Destination::Group(group));
    }

    // 5. `suffix=<name>`
    if let Some(rest) = raw.strip_prefix("suffix=") {
        let name = DomainName::from_str(rest).map_err(|source| RuleParseError::InvalidDomain {
            raw: rest.to_string(),
            source,
        })?;
        return Ok(Destination::DomainSuffix(name));
    }

    // 6. `domain=<name>` (escape hatch)
    if let Some(rest) = raw.strip_prefix("domain=") {
        let name = DomainName::from_str(rest).map_err(|source| RuleParseError::InvalidDomain {
            raw: rest.to_string(),
            source,
        })?;
        return Ok(Destination::Domain(name));
    }

    // 4. CIDR (presence of `/` is the discriminator)
    if raw.contains('/') {
        let net = IpNetwork::from_str(raw).map_err(|_| RuleParseError::InvalidCidr {
            raw: raw.to_string(),
        })?;
        return Ok(Destination::Cidr(net));
    }

    // 3. IP literal (strict — IPv6 colons would have triggered the
    // outer split-on-`:` already, but `<target>` is the first segment
    // before `:`, so an IPv6 addr in a target must use either CIDR
    // form or be square-bracket-quoted. Bare IPv6 in target isn't
    // supported by this grammar; recommend cidr form.)
    if let Ok(ip) = IpAddr::from_str(raw) {
        let prefix = if ip.is_ipv4() { 32 } else { 128 };
        let net = IpNetwork::new(ip, prefix).map_err(|_| RuleParseError::InvalidIp {
            raw: raw.to_string(),
        })?;
        return Ok(Destination::Cidr(net));
    }

    // 7. Bare token with `.` and valid DNS labels → Domain (auto)
    if raw.contains('.') {
        return DomainName::from_str(raw)
            .map(Destination::Domain)
            .map_err(|source| RuleParseError::InvalidDomain {
                raw: raw.to_string(),
                source,
            });
    }

    // 8. Bare single-label is ambiguous — could be a typoed group.
    let suggestion = suggest(raw, GROUP_KEYWORDS);
    Err(RuleParseError::AmbiguousBareToken {
        raw: raw.to_string(),
        suggestion: SuggestionDisplay(suggestion),
    })
}

fn group_from_keyword(s: &str) -> Option<DestinationGroup> {
    match s {
        "public" => Some(DestinationGroup::Public),
        "private" => Some(DestinationGroup::Private),
        "loopback" => Some(DestinationGroup::Loopback),
        "link-local" => Some(DestinationGroup::LinkLocal),
        "meta" => Some(DestinationGroup::Metadata),
        "multicast" => Some(DestinationGroup::Multicast),
        "host" => Some(DestinationGroup::Host),
        _ => None,
    }
}

fn parse_protocol(raw: &str) -> Result<Vec<Protocol>, RuleParseError> {
    match raw {
        "any" => Ok(Vec::new()),
        "tcp" => Ok(vec![Protocol::Tcp]),
        "udp" => Ok(vec![Protocol::Udp]),
        "icmpv4" => Ok(vec![Protocol::Icmpv4]),
        "icmpv6" => Ok(vec![Protocol::Icmpv6]),
        other => Err(RuleParseError::InvalidProtocol {
            raw: other.to_string(),
            suggestion: SuggestionDisplay(suggest(other, PROTOCOL_KEYWORDS)),
        }),
    }
}

fn parse_ports(raw: &str) -> Result<Vec<PortRange>, RuleParseError> {
    if raw == "any" {
        return Ok(Vec::new());
    }
    if let Some((lo_raw, hi_raw)) = raw.split_once('-') {
        let lo: u16 = lo_raw.parse().map_err(|_| RuleParseError::InvalidPorts {
            raw: raw.to_string(),
        })?;
        let hi: u16 = hi_raw.parse().map_err(|_| RuleParseError::InvalidPorts {
            raw: raw.to_string(),
        })?;
        if lo > hi {
            return Err(RuleParseError::InvalidPortRange { lo, hi });
        }
        return Ok(vec![PortRange::range(lo, hi)]);
    }
    let port: u16 = raw.parse().map_err(|_| RuleParseError::InvalidPorts {
        raw: raw.to_string(),
    })?;
    Ok(vec![PortRange::single(port)])
}

//--------------------------------------------------------------------------------------------------
// Levenshtein-2 typo suggestions
//--------------------------------------------------------------------------------------------------

/// Returns the closest keyword within Levenshtein distance 2, or
/// `None` if no keyword is close enough.
fn suggest(input: &str, keywords: &[&'static str]) -> Option<&'static str> {
    let mut best: Option<(&'static str, usize)> = None;
    for &kw in keywords {
        let dist = levenshtein(input, kw);
        if dist <= 2 && best.map(|(_, d)| dist < d).unwrap_or(true) {
            best = Some((kw, dist));
        }
    }
    best.map(|(kw, _)| kw)
}

/// Wagner–Fischer Levenshtein distance using two rolling rows.
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr: Vec<usize> = vec![0; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        curr[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            curr[j + 1] = (curr[j] + 1).min(prev[j + 1] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[track_caller]
    fn assert_destination_matches(rule: &Rule, expected: &str) {
        let actual = format!("{:?}", rule.destination);
        assert!(
            actual.contains(expected),
            "expected destination to contain `{expected}`, got `{actual}`"
        );
    }

    #[test]
    fn allow_at_public_defaults_to_egress() {
        let r = parse_rule_token("allow@public").unwrap();
        assert!(matches!(r.action, Action::Allow));
        assert!(matches!(r.direction, Direction::Egress));
        assert!(matches!(
            r.destination,
            Destination::Group(DestinationGroup::Public)
        ));
        assert!(r.protocols.is_empty());
        assert!(r.ports.is_empty());
    }

    #[test]
    fn deny_with_explicit_direction() {
        let r = parse_rule_token("deny:any@host").unwrap();
        assert!(matches!(r.action, Action::Deny));
        assert!(matches!(r.direction, Direction::Any));
        assert!(matches!(
            r.destination,
            Destination::Group(DestinationGroup::Host)
        ));
    }

    #[test]
    fn allow_with_proto_and_port() {
        let r = parse_rule_token("allow@public:tcp:443").unwrap();
        assert_eq!(r.protocols, vec![Protocol::Tcp]);
        assert_eq!(r.ports.len(), 1);
        assert_eq!(r.ports[0].start, 443);
        assert_eq!(r.ports[0].end, 443);
    }

    #[test]
    fn allow_with_port_range() {
        let r = parse_rule_token("allow@public:tcp:80-443").unwrap();
        assert_eq!(r.ports.len(), 1);
        assert_eq!(r.ports[0].start, 80);
        assert_eq!(r.ports[0].end, 443);
    }

    #[test]
    fn ip_target_becomes_cidr() {
        let r = parse_rule_token("deny@198.51.100.5").unwrap();
        match r.destination {
            Destination::Cidr(net) => assert_eq!(net.to_string(), "198.51.100.5/32"),
            other => panic!("expected /32 cidr, got {other:?}"),
        }
    }

    #[test]
    fn cidr_target_parses() {
        let r = parse_rule_token("allow@10.0.0.0/8").unwrap();
        match r.destination {
            Destination::Cidr(net) => assert_eq!(net.to_string(), "10.0.0.0/8"),
            other => panic!("expected cidr, got {other:?}"),
        }
    }

    #[test]
    fn domain_with_dot_auto_detects() {
        let r = parse_rule_token("allow@example.com:tcp:443").unwrap();
        assert_destination_matches(&r, "example.com");
    }

    #[test]
    fn suffix_prefix_explicit() {
        let r = parse_rule_token("allow@suffix=.local").unwrap();
        match r.destination {
            Destination::DomainSuffix(name) => assert_eq!(name.as_str(), "local"),
            other => panic!("expected DomainSuffix, got {other:?}"),
        }
    }

    #[test]
    fn domain_prefix_escape_hatch() {
        // `public` would normally parse as the group; `domain=public`
        // forces it to be a literal hostname.
        let r = parse_rule_token("allow@domain=public").unwrap();
        match r.destination {
            Destination::Domain(name) => assert_eq!(name.as_str(), "public"),
            other => panic!("expected Domain, got {other:?}"),
        }
    }

    #[test]
    fn missing_at_errors() {
        let err = parse_rule_token("allow public").unwrap_err();
        assert!(matches!(err, RuleParseError::MissingAt { .. }), "{err}");
    }

    #[test]
    fn invalid_action_suggests_close_keyword() {
        let err = parse_rule_token("alow@public").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Did you mean `allow`?"),
            "expected suggestion in `{msg}`"
        );
    }

    #[test]
    fn invalid_direction_suggests_close_keyword() {
        // `iingress` has distance 1 to `ingress`, distance 3 to
        // `egress`, distance 7 to `any` — unambiguous suggestion.
        let err = parse_rule_token("allow:iingress@public").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Did you mean `ingress`?"),
            "expected suggestion in `{msg}`"
        );
    }

    #[test]
    fn ambiguous_bare_token_suggests_group() {
        let err = parse_rule_token("allow@piublic").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Did you mean `public`?"),
            "expected suggestion in `{msg}`"
        );
    }

    #[test]
    fn invalid_protocol_suggests_close_keyword() {
        let err = parse_rule_token("allow@public:tpc:443").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Did you mean `tcp`?"),
            "expected suggestion in `{msg}`"
        );
    }

    #[test]
    fn icmp_in_ingress_is_rejected() {
        let err = parse_rule_token("allow:ingress@public:icmpv4:any").unwrap_err();
        assert!(
            matches!(err, RuleParseError::IngressDoesNotSupportIcmp),
            "{err}"
        );
    }

    #[test]
    fn icmp_in_any_direction_is_rejected() {
        let err = parse_rule_token("allow:any@public:icmpv6").unwrap_err();
        assert!(
            matches!(err, RuleParseError::IngressDoesNotSupportIcmp),
            "{err}"
        );
    }

    #[test]
    fn icmp_in_egress_is_allowed() {
        let r = parse_rule_token("allow:egress@public:icmpv4").unwrap();
        assert_eq!(r.protocols, vec![Protocol::Icmpv4]);
    }

    #[test]
    fn invalid_port_range_lo_gt_hi_rejected() {
        let err = parse_rule_token("allow@public:tcp:443-80").unwrap_err();
        assert!(
            matches!(err, RuleParseError::InvalidPortRange { lo: 443, hi: 80 }),
            "{err}"
        );
    }

    #[test]
    fn parse_rule_list_preserves_order() {
        let rules = parse_rule_list("deny@198.51.100.5,allow@public").unwrap();
        assert_eq!(rules.len(), 2);
        assert!(matches!(rules[0].action, Action::Deny));
        assert!(matches!(rules[1].action, Action::Allow));
    }

    #[test]
    fn parse_rule_list_skips_empty_segments() {
        let rules = parse_rule_list("allow@public,, allow@private").unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn trailing_junk_rejected() {
        let err = parse_rule_token("allow@public:tcp:443:extra").unwrap_err();
        assert!(matches!(err, RuleParseError::TrailingJunk { .. }), "{err}");
    }

    #[test]
    fn levenshtein_basic() {
        assert_eq!(levenshtein("public", "public"), 0);
        assert_eq!(levenshtein("piublic", "public"), 1);
        assert_eq!(levenshtein("iingress", "ingress"), 1);
        // Far-apart strings: just assert "well above the suggestion threshold".
        assert!(levenshtein("totally-different", "tcp") > 5);
    }

    #[test]
    fn suggest_returns_none_when_too_far() {
        assert_eq!(suggest("xyz", &["public", "private"]), None);
    }

    #[test]
    fn suggest_returns_closest_within_distance_two() {
        assert_eq!(
            suggest("piublic", &["public", "private", "loopback"]),
            Some("public")
        );
    }
}
