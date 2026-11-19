//! Address-policy proofs for names that expose local network information.

use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_net::proto::rr::Name;
use ipnetwork::IpNetwork;

use super::common::filter::{is_private_ipv4, is_private_ipv6};
use crate::addr::{nat64_embedded_ipv4_addr, normalize_ip_addr};
use crate::netstack::shared::SharedState;
use crate::policy::{
    Action, Destination, DestinationGroup, Direction, NetworkPolicy, Protocol, matches_cidr,
    matches_group,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

// These boundaries cover both DNS reserved-address predicates and destination
// groups. Extra boundaries only cost an evaluation; missing one invalidates a
// whole-range proof. Host networks, rules and address translations are added below.
const IPV4_RANGES: &[&str] = &[
    "0.0.0.0/8",
    "0.0.0.0/32",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "169.254.169.254/32",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
];
const IPV6_RANGES: &[&str] = &[
    "::/128",
    "::1/128",
    "100::/64",
    "64:ff9b:1::/48",
    "2001:db8::/32",
    "3fff::/20",
    "fc00::/7",
    "fe80::/10",
    "fec0::/10",
    "ff00::/8",
];

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Per-message policy view. Expensive range boundaries and hostname snapshots
/// are lazy, and are reused for all names and records in that message.
pub(super) struct NamePolicy<'a> {
    tenant: &'a NetworkPolicy,
    platform: Option<&'a NetworkPolicy>,
    shared: &'a SharedState,
    boundaries: OnceCell<Boundaries>,
    hostnames: OnceCell<HashMap<IpAddr, Vec<String>>>,
    discovery: OnceCell<bool>,
    ranges: RefCell<HashMap<AddressRange, bool>>,
}

struct Boundaries {
    ipv4: Vec<u128>,
    ipv6: Vec<u128>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct AddressRange {
    first: IpAddr,
    last: IpAddr,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<'a> NamePolicy<'a> {
    pub(super) fn new(
        tenant: &'a NetworkPolicy,
        platform: Option<&'a NetworkPolicy>,
        shared: &'a SharedState,
    ) -> Self {
        Self {
            tenant,
            platform,
            shared,
            boundaries: OnceCell::new(),
            hostnames: OnceCell::new(),
            discovery: OnceCell::new(),
            ranges: RefCell::new(HashMap::new()),
        }
    }

    pub(super) fn allows_name(&self, name: &Name) -> bool {
        if name
            .iter()
            .next_back()
            .is_some_and(|label| label.eq_ignore_ascii_case(b"local"))
        {
            return *self.discovery.get_or_init(|| self.broad_private_access());
        }
        let Some(range) = reverse_range(name) else {
            return true;
        };
        if let Some(&allowed) = self.ranges.borrow().get(&range) {
            return allowed;
        }
        let points = self.points(range);
        // Purely public reverse lookups retain ordinary DNS semantics. A mixed
        // zone, however, needs authorization for its entire address range.
        let allowed = !points.iter().any(|&addr| self.restricted_address(addr))
            || points.into_iter().all(|addr| self.admits(addr));
        // Cache by address range, not spelling: many DNS-SD names can describe
        // the same zone, and must not repeat a whole-cache proof in one reply.
        self.ranges.borrow_mut().insert(range, allowed);
        allowed
    }

    pub(super) fn allows_address(&self, addr: IpAddr) -> bool {
        !self.restricted_address(addr) || self.admits(addr)
    }

    fn restricted_address(&self, addr: IpAddr) -> bool {
        let normalized = normalize_ip_addr(addr);
        let reserved = match normalized {
            IpAddr::V4(v4) => is_private_ipv4(v4),
            IpAddr::V6(v6) => {
                is_private_ipv6(v6)
                    || nat64_embedded_ipv4_addr(v6, self.shared.nat64_prefixes())
                        .is_some_and(is_private_ipv4)
            }
        };
        reserved || !matches_group(DestinationGroup::Public, normalized, self.shared)
    }

    fn admits(&self, addr: IpAddr) -> bool {
        [Protocol::Tcp, Protocol::Udp].into_iter().any(|protocol| {
            self.tenant
                .evaluate_explicit_egress_ip(addr, protocol, self.shared)
                == Some(Action::Allow)
                && self
                    .platform
                    .is_none_or(|policy| self.floor_allows(policy, addr, protocol))
        })
    }

    fn floor_allows(&self, policy: &NetworkPolicy, addr: IpAddr, protocol: Protocol) -> bool {
        for rule in &policy.rules {
            if !matches!(rule.direction, Direction::Egress | Direction::Any)
                || !rule.ports.is_empty()
                || (!rule.protocols.is_empty() && !rule.protocols.contains(&protocol))
            {
                continue;
            }
            let matches = match &rule.destination {
                Destination::Any => true,
                Destination::Cidr(network) => matches_cidr(network, addr, self.shared),
                Destination::Group(group) => matches_group(*group, addr, self.shared),
                Destination::Domain(domain) => {
                    self.hostname_matches(addr, |name| name == domain.as_str())
                }
                Destination::DomainSuffix(suffix) => self.hostname_matches(addr, |name| {
                    name == suffix.as_str()
                        || name
                            .strip_suffix(suffix.as_str())
                            .is_some_and(|prefix| prefix.len() > 1 && prefix.ends_with('.'))
                }),
            };
            if matches {
                return rule.action.is_allow();
            }
        }
        policy.default_egress.is_allow()
    }

    fn hostname_matches(&self, addr: IpAddr, predicate: impl Fn(&str) -> bool) -> bool {
        self.hostname_snapshot()
            .get(&normalize_ip_addr(addr))
            .is_some_and(|names| names.iter().any(|name| predicate(name)))
    }

    fn hostname_snapshot(&self) -> &HashMap<IpAddr, Vec<String>> {
        self.hostnames.get_or_init(|| {
            if self.platform.is_some_and(|policy| {
                policy.rules.iter().any(|rule| {
                    matches!(
                        rule.destination,
                        Destination::Domain(_) | Destination::DomainSuffix(_)
                    )
                })
            }) {
                self.shared.resolved_hostname_snapshot()
            } else {
                HashMap::new()
            }
        })
    }

    fn broad_private_access(&self) -> bool {
        // The Private profile deliberately excludes Host and LinkLocal. Require
        // every native Private segment, not those other groups, so normal
        // --net private remains useful. Returned host/link-local records still
        // undergo their own authorization; one allowed RFC1918 range is not enough.
        [
            AddressRange {
                first: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                last: IpAddr::V4(Ipv4Addr::BROADCAST),
            },
            AddressRange {
                first: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                last: IpAddr::V6(Ipv6Addr::from(u128::MAX)),
            },
        ]
        .into_iter()
        .all(|range| {
            self.points(range).into_iter().all(|addr| {
                let translated = match addr {
                    IpAddr::V6(v6) => {
                        v6.to_ipv4_mapped().is_some()
                            || nat64_embedded_ipv4_addr(v6, self.shared.nat64_prefixes()).is_some()
                    }
                    _ => false,
                };
                translated
                    || !matches_group(DestinationGroup::Private, addr, self.shared)
                    || self.admits(addr)
            })
        })
    }

    fn points(&self, range: AddressRange) -> Vec<IpAddr> {
        // Exact reverse names are common and do not need an interval proof.
        if range.first == range.last {
            return vec![range.first];
        }
        let boundaries = self.boundaries.get_or_init(|| self.prepare_boundaries());
        let ipv6 = range.first.is_ipv6();
        let (first, last) = (numeric(range.first), numeric(range.last));
        let source = if ipv6 {
            &boundaries.ipv6
        } else {
            &boundaries.ipv4
        };
        let mut points = vec![range.first];
        let start = source.partition_point(|&point| point <= first);
        let end = source.partition_point(|&point| point <= last);
        points.extend(source[start..end].iter().map(|&point| address(point, ipv6)));
        points
    }

    fn prepare_boundaries(&self) -> Boundaries {
        let mut result = Boundaries {
            ipv4: vec![0],
            ipv6: vec![0],
        };
        for raw in IPV4_RANGES.iter().chain(IPV6_RANGES) {
            result.network(raw.parse().expect("constant DNS classification network"));
        }
        for policy in [Some(self.tenant), self.platform].into_iter().flatten() {
            for rule in &policy.rules {
                if let Destination::Cidr(network) = rule.destination {
                    result.network(network);
                }
            }
        }
        for network in self.shared.host_ipv4_networks() {
            result.network(IpNetwork::V4(*network));
        }
        for network in self.shared.host_ipv6_networks() {
            result.network(IpNetwork::V6(*network));
        }
        for addr in self
            .shared
            .host_ipv4()
            .iter()
            .copied()
            .chain(self.shared.gateway_ipv4())
        {
            result.singleton(IpAddr::V4(addr));
        }
        for addr in self
            .shared
            .host_ipv6()
            .iter()
            .copied()
            .chain(self.shared.gateway_ipv6())
        {
            result.singleton(IpAddr::V6(addr));
        }
        for &addr in self.hostname_snapshot().keys() {
            result.singleton(addr);
        }
        result.ipv4.sort_unstable();
        result.ipv4.dedup();
        // IPv4-mapped and configured /96 translations inherit every IPv4
        // classification and policy boundary. Keep original IPv6 CIDR boundaries
        // too: existing NAT64 rules may authorize either spelling.
        let prefixes = std::iter::once(u128::from("::ffff:0:0".parse::<Ipv6Addr>().unwrap()))
            .chain(
                self.shared
                    .nat64_prefixes()
                    .iter()
                    .map(|network| u128::from(network.network())),
            );
        for prefix in prefixes {
            push_span(&mut result.ipv6, prefix, prefix | u128::from(u32::MAX));
            result.ipv6.extend(
                result
                    .ipv4
                    .iter()
                    .copied()
                    .filter(|&point| point <= u128::from(u32::MAX))
                    .map(|point| prefix | point),
            );
        }
        result.ipv6.sort_unstable();
        result.ipv6.dedup();
        result
    }
}

impl Boundaries {
    fn network(&mut self, network: IpNetwork) {
        match network {
            IpNetwork::V4(network) => push_span(
                &mut self.ipv4,
                u128::from(u32::from(network.network())),
                u128::from(u32::from(network.broadcast())),
            ),
            IpNetwork::V6(network) => push_span(
                &mut self.ipv6,
                u128::from(network.network()),
                u128::from(network.network())
                    | (u128::MAX
                        .checked_shr(u32::from(network.prefix()))
                        .unwrap_or(0)),
            ),
        }
    }

    fn singleton(&mut self, addr: IpAddr) {
        let points = if addr.is_ipv6() {
            &mut self.ipv6
        } else {
            &mut self.ipv4
        };
        push_span(points, numeric(addr), numeric(addr));
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn push_span(points: &mut Vec<u128>, first: u128, last: u128) {
    points.push(first);
    if let Some(after) = last.checked_add(1) {
        points.push(after);
    }
}

fn numeric(addr: IpAddr) -> u128 {
    match addr {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

fn address(value: u128, ipv6: bool) -> IpAddr {
    if ipv6 {
        IpAddr::V6(Ipv6Addr::from(value))
    } else {
        IpAddr::V4(Ipv4Addr::from(value as u32))
    }
}

fn reverse_range(name: &Name) -> Option<AddressRange> {
    let labels: Vec<&[u8]> = name.iter().rev().collect();
    let [arpa, kind, rest @ ..] = labels.as_slice() else {
        return None;
    };
    if !arpa.eq_ignore_ascii_case(b"arpa") {
        return None;
    }
    let ipv6 = kind.eq_ignore_ascii_case(b"ip6");
    if !ipv6 && !kind.eq_ignore_ascii_case(b"in-addr") {
        return None;
    }
    let (maximum, width) = if ipv6 { (32, 4) } else { (4, 8) };
    let mut first = 0u128;
    let mut count = 0;
    for label in rest.iter().take(maximum) {
        let digit = if ipv6 {
            match label {
                [nibble] => char::from(*nibble).to_digit(16).map(u128::from),
                _ => None,
            }
        } else if label.len() <= 3 && !label.is_empty() && label.iter().all(u8::is_ascii_digit) {
            std::str::from_utf8(label)
                .ok()
                .and_then(|value| value.parse::<u8>().ok())
                .map(u128::from)
        } else {
            None
        };
        let Some(digit) = digit else {
            break;
        };
        first = (first << width) | digit;
        count += 1;
    }
    let remaining = (maximum - count) * width;
    let mask = if ipv6 {
        u128::MAX
    } else {
        u128::from(u32::MAX)
    };
    first = first.checked_shl(remaining as u32).unwrap_or(0);
    let last = first | mask.checked_shr((count * width) as u32).unwrap_or(0);
    Some(AddressRange {
        first: address(first, ipv6),
        last: address(last, ipv6),
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netstack::shared::ResolvedHostnameFamily;
    use crate::policy::{NetworkProfile, Rule};
    use std::time::Duration;

    fn allow_name(policy: &NamePolicy<'_>, name: &str) -> bool {
        policy.allows_name(&Name::from_ascii(name).unwrap())
    }

    fn cidr(raw: &str, action: Action) -> Rule {
        Rule {
            direction: Direction::Egress,
            destination: Destination::Cidr(raw.parse().unwrap()),
            protocols: vec![],
            ports: vec![],
            action,
        }
    }

    fn reverse(addr: &str) -> String {
        let addr: Ipv6Addr = addr.parse().unwrap();
        format!(
            "{}.ip6.arpa.",
            format!("{:032x}", u128::from(addr))
                .chars()
                .rev()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(".")
        )
    }

    #[test]
    fn broad_private_profile_survives_host_holes_but_records_stay_protected() {
        let shared = SharedState::new(4);
        shared.set_gateway_ips(
            Some("10.0.0.1".parse().unwrap()),
            Some("fd42::1".parse().unwrap()),
        );
        shared.set_host_networks(
            vec!["192.168.1.2".parse().unwrap()],
            vec!["192.168.1.0/24".parse().unwrap()],
            vec!["2001:4860:1234::1".parse().unwrap()],
            vec!["2001:4860:1234::/64".parse().unwrap()],
        );
        let tenant =
            NetworkPolicy::from_profiles([NetworkProfile::Public, NetworkProfile::Private]);
        let policy = NamePolicy::new(&tenant, None, &shared);
        assert!(allow_name(&policy, "Printer.LOCAL."));
        assert!(policy.allows_address("2001:4860:1234::2".parse().unwrap()));
        assert!(!policy.allows_address("192.168.1.2".parse().unwrap()));
        assert!(!policy.allows_address("fe80::2".parse().unwrap()));
        assert!(!allow_name(&policy, "10.in-addr.arpa."));
        assert!(allow_name(&policy, "2.0.0.10.in-addr.arpa."));
    }

    #[test]
    fn public_profile_respects_actual_host_networks() {
        let shared = SharedState::new(4);
        shared.set_host_networks(
            vec![],
            vec!["11.22.33.0/24".parse().unwrap()],
            vec![],
            vec!["2001:4860:1234::/64".parse().unwrap()],
        );
        let tenant = NetworkPolicy::from_profiles([NetworkProfile::Public]);
        let policy = NamePolicy::new(&tenant, None, &shared);
        assert!(!policy.allows_address("11.22.33.4".parse().unwrap()));
        assert!(!allow_name(&policy, "11.in-addr.arpa."));
        assert!(!allow_name(&policy, &reverse("2001:4860:1234::2")));
        assert!(allow_name(&policy, "4.33.23.11.in-addr.arpa."));
    }

    #[test]
    fn ordered_interior_denies_and_tiled_allows_apply_to_discovery() {
        let shared = SharedState::new(4);
        let mut tenant = NetworkPolicy::from_profiles([NetworkProfile::Private]);
        tenant.rules.insert(0, cidr("10.42.17.9/32", Action::Deny));
        let policy = NamePolicy::new(&tenant, None, &shared);
        assert!(!allow_name(&policy, "printer.local."));
        assert!(!allow_name(&policy, "10.in-addr.arpa."));
        assert!(allow_name(&policy, "9.18.42.10.in-addr.arpa."));
        tenant.rules[0].action = Action::Allow;
        assert!(allow_name(
            &NamePolicy::new(&tenant, None, &shared),
            "local."
        ));
    }

    #[test]
    fn whole_zone_allows_each_segment_under_its_own_common_protocol() {
        let shared = SharedState::new(4);
        let mut tenant = NetworkPolicy::from_profiles([NetworkProfile::Public]);
        let mut first = cidr("10.0.0.0/9", Action::Allow);
        first.protocols = vec![Protocol::Tcp];
        let mut second = cidr("10.128.0.0/9", Action::Allow);
        second.protocols = vec![Protocol::Udp];
        tenant.rules.extend([first, second]);
        let platform = NetworkPolicy::allow_all();
        assert!(allow_name(
            &NamePolicy::new(&tenant, Some(&platform), &shared),
            "10.in-addr.arpa."
        ));
        let mut platform = NetworkPolicy::none();
        let mut rule = cidr("10.0.0.0/8", Action::Allow);
        rule.protocols = vec![Protocol::Tcp];
        platform.rules.push(rule);
        assert!(!allow_name(
            &NamePolicy::new(&tenant, Some(&platform), &shared),
            "10.in-addr.arpa."
        ));
    }

    #[test]
    fn platform_cached_hostname_denial_is_a_range_boundary() {
        let shared = SharedState::new(4);
        let tenant = NetworkPolicy::from_profiles([NetworkProfile::Private]);
        let mut platform = NetworkPolicy::allow_all();
        platform.rules.push(Rule {
            direction: Direction::Egress,
            destination: Destination::DomainSuffix("blocked.example".parse().unwrap()),
            protocols: vec![],
            ports: vec![],
            action: Action::Deny,
        });
        shared.cache_resolved_hostname(
            "host.blocked.example",
            ResolvedHostnameFamily::Ipv4,
            ["10.42.17.9".parse().unwrap()],
            Duration::from_secs(60),
        );
        let policy = NamePolicy::new(&tenant, Some(&platform), &shared);
        assert!(!allow_name(&policy, "10.in-addr.arpa."));
        assert!(!allow_name(&policy, "printer.local."));
        assert!(allow_name(&policy, "8.17.42.10.in-addr.arpa."));
        shared.clear_resolved_hostname("host.blocked.example", ResolvedHostnameFamily::Ipv4);
        assert!(
            !allow_name(&policy, "10.in-addr.arpa."),
            "one decision keeps a consistent cache snapshot"
        );
        assert!(allow_name(
            &NamePolicy::new(&tenant, Some(&platform), &shared),
            "10.in-addr.arpa."
        ));
    }

    #[test]
    fn mapped_and_configured_nat64_reverse_names_follow_existing_policy() {
        let shared = SharedState::new(4);
        shared.set_nat64_prefixes(vec![
            "64:ff9b::/96".parse().unwrap(),
            "2001:4860:64::/96".parse().unwrap(),
        ]);
        let mut tenant = NetworkPolicy::from_profiles([NetworkProfile::Public]);
        let policy = NamePolicy::new(&tenant, None, &shared);
        for addr in ["::ffff:10.0.0.1", "64:ff9b::a00:1", "2001:4860:64::a00:1"] {
            assert!(!policy.allows_address(addr.parse().unwrap()));
            assert!(!allow_name(&policy, &reverse(addr)));
        }
        assert!(policy.allows_address("64:ff9b::808:808".parse().unwrap()));
        assert!(
            policy.allows_address("2001:4860:65::a00:1".parse().unwrap()),
            "unconfigured IPv6 prefix is not guessed to be NAT64"
        );
        tenant.rules.push(cidr("64:ff9b::/96", Action::Allow));
        let policy = NamePolicy::new(&tenant, None, &shared);
        assert!(allow_name(&policy, &reverse("64:ff9b::a00:1")));
        assert!(!allow_name(&policy, &reverse("::ffff:10.0.0.1")));
        tenant.rules.insert(0, cidr("10.0.0.1/32", Action::Deny));
        assert!(!allow_name(
            &NamePolicy::new(&tenant, None, &shared),
            &reverse("64:ff9b::a00:1")
        ));
    }

    #[test]
    fn reverse_roots_mixed_zones_and_dns_sd_are_bounded_and_conservative() {
        let shared = SharedState::new(4);
        let public = NetworkPolicy::from_profiles([NetworkProfile::Public]);
        let policy = NamePolicy::new(&public, None, &shared);
        for name in [
            "in-addr.arpa.",
            "ip6.arpa.",
            "172.in-addr.arpa.",
            "300.in-addr.arpa.",
            "e.f.ip6.arpa.",
            "db._dns-sd._udp.10.in-addr.arpa.",
        ] {
            assert!(!allow_name(&policy, name), "{name}");
        }
        for name in [
            "1.1.1.172.in-addr.arpa.",
            "local.example.",
            "8.8.8.8.in-addr.arpa.",
        ] {
            assert!(allow_name(&policy, name), "{name}");
        }
        let mut all = NetworkPolicy::none();
        all.rules.extend([
            cidr("0.0.0.0/0", Action::Allow),
            cidr("::/0", Action::Allow),
        ]);
        let policy = NamePolicy::new(&all, None, &shared);
        assert!(allow_name(&policy, "in-addr.arpa."));
        assert!(allow_name(&policy, "ip6.arpa."));
    }

    #[test]
    fn whole_translated_prefixes_preserve_interior_and_native_denies() {
        let shared = SharedState::new(4);
        shared.set_nat64_prefixes(vec!["64:ff9b::/96".parse().unwrap()]);
        let mut tenant = NetworkPolicy::none();
        tenant.rules.extend([
            cidr("10.42.17.9/32", Action::Deny),
            cidr("0.0.0.0/0", Action::Allow),
            cidr("::/0", Action::Allow),
        ]);
        for addr in ["::ffff:0:0", "64:ff9b::"] {
            let reverse = reverse(addr);
            let zone = reverse.split('.').skip(8).collect::<Vec<_>>().join(".");
            assert!(!allow_name(&NamePolicy::new(&tenant, None, &shared), &zone));
        }
        tenant.rules[0] = cidr("64:ff9b::a2a:1109/128", Action::Deny);
        assert!(!allow_name(
            &NamePolicy::new(&tenant, None, &shared),
            &reverse("64:ff9b::a2a:1109")
        ));
        let nat64_zone = reverse("64:ff9b::")
            .split('.')
            .skip(8)
            .collect::<Vec<_>>()
            .join(".");
        assert!(!allow_name(
            &NamePolicy::new(&tenant, None, &shared),
            &nat64_zone
        ));
        for (deny, zone) in [
            ("255.255.255.255/32", "in-addr.arpa."),
            ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", "ip6.arpa."),
            ("0.0.0.0/32", "in-addr.arpa."),
            ("::/128", "ip6.arpa."),
        ] {
            tenant.rules[0] = cidr(deny, Action::Deny);
            assert!(
                !allow_name(&NamePolicy::new(&tenant, None, &shared), zone),
                "{deny}"
            );
        }
    }

    #[test]
    fn snapshot_floor_matches_the_existing_policy_evaluator() {
        let shared = SharedState::new(4);
        shared.set_nat64_prefixes(vec!["64:ff9b::/96".parse().unwrap()]);
        for (hostname, address) in [
            ("host.example.com", "10.0.0.1"),
            ("example.com", "10.0.0.2"),
            (".example.com", "10.0.0.3"),
            ("evilexample.com", "10.0.0.4"),
        ] {
            shared.cache_resolved_hostname(
                hostname,
                ResolvedHostnameFamily::Ipv4,
                [address.parse().unwrap()],
                Duration::from_secs(60),
            );
        }
        let tenant = NetworkPolicy::from_profiles([NetworkProfile::Private]);
        let destinations = [
            Destination::Any,
            Destination::Cidr("10.0.0.0/8".parse().unwrap()),
            Destination::Group(DestinationGroup::Private),
            Destination::Domain("example.com".parse().unwrap()),
            Destination::DomainSuffix("example.com".parse().unwrap()),
        ];
        for destination in destinations {
            for action in [Action::Allow, Action::Deny] {
                for direction in [Direction::Ingress, Direction::Egress, Direction::Any] {
                    for ports in [vec![], vec![crate::policy::PortRange::single(80)]] {
                        for protocols in [vec![], vec![Protocol::Tcp], vec![Protocol::Udp]] {
                            let mut floor = NetworkPolicy::allow_all();
                            floor.rules = vec![
                                Rule {
                                    destination: destination.clone(),
                                    action,
                                    direction,
                                    ports: ports.clone(),
                                    protocols,
                                },
                                cidr("10.0.0.2/32", Action::Deny),
                            ];
                            let view = NamePolicy::new(&tenant, Some(&floor), &shared);
                            for address in [
                                "10.0.0.1",
                                "10.0.0.2",
                                "10.0.0.3",
                                "10.0.0.4",
                                "8.8.8.8",
                                "64:ff9b::a00:1",
                                "::ffff:10.0.0.1",
                            ] {
                                for protocol in [Protocol::Tcp, Protocol::Udp] {
                                    let address = address.parse().unwrap();
                                    assert_eq!(
                                        view.floor_allows(&floor, address, protocol),
                                        floor
                                            .evaluate_egress_ip(address, protocol, &shared)
                                            .is_allow(),
                                        "{floor:?} {address} {protocol:?}"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn full_hostname_cache_and_repeated_zone_proofs_remain_bounded() {
        let shared = SharedState::new(4);
        for index in 0..16u32 {
            let addresses = (0..1024)
                .map(|offset| IpAddr::V4(Ipv4Addr::from(0x0a000000 + index * 1024 + offset)));
            assert!(shared.cache_resolved_hostname(
                &format!("host{index}.example"),
                ResolvedHostnameFamily::Ipv4,
                addresses,
                Duration::from_secs(60)
            ));
        }
        let tenant = NetworkPolicy::from_profiles([NetworkProfile::Private]);
        let mut floor = NetworkPolicy::allow_all();
        floor.rules.push(Rule {
            direction: Direction::Egress,
            destination: Destination::Domain("absent.example".parse().unwrap()),
            ports: vec![],
            protocols: vec![],
            action: Action::Deny,
        });
        let view = NamePolicy::new(&tenant, Some(&floor), &shared);
        for index in 0..256 {
            assert!(allow_name(
                &view,
                &format!("service{index}.10.in-addr.arpa.")
            ));
        }
        assert_eq!(view.ranges.borrow().len(), 1);
        assert_eq!(view.hostname_snapshot().len(), 16_384);
        assert!(allow_name(&view, "1.0.0.10.in-addr.arpa."));
    }
}
