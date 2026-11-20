//! Validate gateway DNS records and preserve complete public answers safely.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_net::proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_net::proto::rr::rdata::{SVCB, svcb::SvcParamValue};
use hickory_net::proto::rr::{DNSClass, Name, RData, Record, RecordType};

use super::name_policy::NamePolicy;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

type RecordSet = (Name, DNSClass, RecordType);

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Reject restricted answers. Ancillary RRsets may be removed only when the
/// independently complete answer remains usable without them.
pub(super) fn filter_response(
    policy: &NamePolicy<'_>,
    query: &Message,
    response: &mut Message,
    gateway: bool,
) -> bool {
    if !gateway {
        // Explicitly selected resolvers retain their existing address-rebind
        // contract. Local-name discovery restrictions protect the host resolver.
        return response
            .answers
            .iter()
            .all(|record| address_record_allowed(policy, record));
    }
    if response.metadata.message_type != MessageType::Response
        || response.metadata.op_code != query.metadata.op_code
        || response.queries != query.queries
        || response
            .answers
            .iter()
            .any(|record| !record_allowed(policy, record))
    {
        return false;
    }

    let denied: HashSet<RecordSet> = response
        .authorities
        .iter()
        .chain(&response.additionals)
        .filter(|record| !record_allowed(policy, record))
        .map(record_set)
        .collect();
    let signature_denied = response.signature.as_ref().is_some_and(|record| {
        !policy.allows_name(&record.name) || !policy.allows_name(&record.data.algorithm.to_name())
    });
    if denied.is_empty() && !signature_denied {
        return true;
    }
    if !complete_answer(query, response) {
        return false;
    }

    let retain = |record: &Record| {
        !denied.contains(&record_set(record))
            && signature_covered_type(record)
                .is_none_or(|kind| !denied.contains(&(record.name.clone(), record.dns_class, kind)))
            && !message_signature(record)
    };
    response.answers.retain(|record| !message_signature(record));
    response.authorities.retain(retain);
    response.additionals.retain(retain);
    // Rewriting invalidates whole-message authentication. Unchanged answer
    // RRsets and their DNSSEC signatures remain available for client validation.
    response.metadata.authentic_data = false;
    response.signature = None;
    true
}

fn address_record_allowed(policy: &NamePolicy<'_>, record: &Record) -> bool {
    match &record.data {
        RData::A(addr) => policy.allows_address(IpAddr::V4((*addr).into())),
        RData::AAAA(addr) => policy.allows_address(IpAddr::V6((*addr).into())),
        _ => true,
    }
}

fn record_allowed(policy: &NamePolicy<'_>, record: &Record) -> bool {
    if !policy.allows_name(&record.name) || !address_record_allowed(policy, record) {
        return false;
    }
    match &record.data {
        RData::ANAME(name) => policy.allows_name(&name.0),
        RData::CNAME(name) => policy.allows_name(&name.0),
        RData::NS(name) => policy.allows_name(&name.0),
        RData::PTR(name) => policy.allows_name(&name.0),
        RData::MX(data) => policy.allows_name(&data.exchange),
        RData::SOA(data) => policy.allows_name(&data.mname) && policy.allows_name(&data.rname),
        RData::SRV(data) => policy.allows_name(&data.target),
        RData::NAPTR(data) => policy.allows_name(&data.replacement),
        RData::SVCB(data) => service_binding_allowed(policy, data),
        RData::HTTPS(data) => service_binding_allowed(policy, &data.0),
        RData::TSIG(data) => policy.allows_name(&data.algorithm.to_name()),
        RData::Unknown { code, rdata } => {
            raw_names_allowed(policy, u16::from(*code), &rdata.anything)
        }
        _ => true,
    }
}

fn service_binding_allowed(policy: &NamePolicy<'_>, data: &SVCB) -> bool {
    policy.allows_name(&data.target_name)
        && data.svc_params.iter().all(|(_, value)| match value {
            SvcParamValue::Ipv4Hint(hints) => hints
                .0
                .iter()
                .all(|addr| policy.allows_address(IpAddr::V4((*addr).into()))),
            SvcParamValue::Ipv6Hint(hints) => hints
                .0
                .iter()
                .all(|addr| policy.allows_address(IpAddr::V6((*addr).into()))),
            _ => true,
        })
}

/// Hickory does not decode DNAME and DNSSEC RDATA in this feature set. Inspect
/// the recognized wire names without enabling a cryptographic dependency.
/// Legacy types that permit compression are expanded from the original packet
/// by wire_names first. Remaining detached pointers are invalid for these types.
fn raw_names_allowed(policy: &NamePolicy<'_>, kind: u16, bytes: &[u8]) -> bool {
    let (mut offset, count, trailing) = match kind {
        3 | 4 | 7 | 8 | 9 | 23 | 39 => (0, 1, false), // MD/MF/MB/MG/MR/NSAP-PTR/DNAME
        14 | 17 => (0, 2, false),                     // MINFO/RP
        18 | 21 | 36 | 107 => (2, 1, false),          // AFSDB/RT/KX
        26 => (2, 2, false),                          // PX
        24 | 46 => (18, 1, true),                     // SIG/RRSIG signer
        30 | 47 => (0, 1, true),                      // NXT/NSEC next name
        249 => (0, 1, true),                          // TKEY algorithm
        // RFC 2874: an A6 suffix has ceil((128-prefix)/8) octets;
        // only prefix zero is a complete address, otherwise a name follows.
        38 => {
            let Some(&prefix) = bytes.first().filter(|&&prefix| prefix <= 128) else {
                return false;
            };
            if prefix == 0 {
                return bytes.len() == 17 && raw_address_allowed(policy, &bytes[1..]);
            }
            (1 + usize::from(128 - prefix).div_ceil(8), 1, false)
        }
        45 | 260 => {
            // IPSECKEY / AMTRELAY (RFC 4025 / RFC 8777)
            let header = if kind == 45 { 3 } else { 2 };
            if bytes.len() < header {
                return false;
            }
            let gateway = if kind == 45 {
                bytes[1]
            } else {
                bytes[1] & 0x7f
            };
            let length = match gateway {
                0 => 0,
                1 => 4,
                2 => 16,
                3 => return raw_target_allowed(policy, bytes, header, kind == 45),
                _ => return false,
            };
            let Some(address) = bytes.get(header..header + length) else {
                return false;
            };
            return (length == 0 || raw_address_allowed(policy, address))
                && (kind == 45 || bytes.len() == header + length);
        }
        55 => {
            // HIP: HIT and public key precede zero or more RVS names.
            if bytes.len() < 4 {
                return false;
            }
            let mut offset =
                4 + usize::from(bytes[0]) + usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
            if offset > bytes.len() {
                return false;
            }
            while offset < bytes.len() {
                let Some(name) = raw_name(bytes, &mut offset) else {
                    return false;
                };
                if !policy.allows_name(&name) {
                    return false;
                }
            }
            return true;
        }
        _ => return true,
    };
    for _ in 0..count {
        let Some(name) = raw_name(bytes, &mut offset) else {
            return false;
        };
        if !policy.allows_name(&name) {
            return false;
        }
    }
    if trailing {
        offset < bytes.len()
    } else {
        offset == bytes.len()
    }
}

fn raw_target_allowed(
    policy: &NamePolicy<'_>,
    bytes: &[u8],
    mut offset: usize,
    trailing: bool,
) -> bool {
    raw_name(bytes, &mut offset).is_some_and(|name| policy.allows_name(&name))
        && (trailing || offset == bytes.len())
}

fn raw_address_allowed(policy: &NamePolicy<'_>, bytes: &[u8]) -> bool {
    match bytes.len() {
        4 => policy.allows_address(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(bytes).unwrap(),
        ))),
        16 => policy.allows_address(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).unwrap(),
        ))),
        _ => false,
    }
}

fn raw_name(bytes: &[u8], offset: &mut usize) -> Option<Name> {
    let start = *offset;
    let mut labels = Vec::new();
    loop {
        let len = usize::from(*bytes.get(*offset)?);
        *offset += 1;
        if len > 63 || *offset - start > 255 {
            return None;
        }
        if len == 0 {
            return Name::from_labels(labels).ok();
        }
        let end = offset.checked_add(len)?;
        labels.push(bytes.get(*offset..end)?);
        *offset = end;
    }
}

fn record_set(record: &Record) -> RecordSet {
    (record.name.clone(), record.dns_class, record.record_type())
}

fn signature_covered_type(record: &Record) -> Option<RecordType> {
    let RData::Unknown { code, rdata } = &record.data else {
        return None;
    };
    if !matches!(u16::from(*code), 24 | 46) {
        return None;
    }
    let prefix: [u8; 2] = rdata.anything.get(..2)?.try_into().ok()?;
    Some(RecordType::from(u16::from_be_bytes(prefix)))
}

pub(super) fn message_signature(record: &Record) -> bool {
    u16::from(record.record_type()) == 250
        || (u16::from(record.record_type()) == 24
            && signature_covered_type(record).is_some_and(|kind| u16::from(kind) == 0))
}

/// Establish completion before stripping anything. A CNAME-only response,
/// referral, negative answer, cycle or conflicting alias cannot be repaired by
/// deleting the very metadata a resolver may still need to complete it.
fn complete_answer(query: &Message, response: &Message) -> bool {
    let [question] = query.queries.as_slice() else {
        return false;
    };
    if query.metadata.op_code != OpCode::Query
        || response.metadata.response_code != ResponseCode::NoError
        || response
            .answers
            .iter()
            .any(|record| matches!(record.data, RData::Update0(_)))
        || response.metadata.truncation
        || matches!(
            question.query_type(),
            RecordType::ANY | RecordType::AXFR | RecordType::IXFR
        )
    {
        return false;
    }
    let mut owner = question.name();
    let mut visited = HashSet::new();
    let mut dnames = HashSet::new();
    loop {
        if !visited.insert(owner.clone()) {
            return false;
        }
        let mut target = None;
        let mut terminal = false;
        for record in response
            .answers
            .iter()
            .filter(|record| &record.name == owner)
        {
            if record.dns_class != question.query_class() {
                return false;
            }
            if let RData::CNAME(name) = &record.data {
                if target.is_some_and(|existing| existing != &name.0) {
                    return false;
                }
                target = Some(&name.0);
            }
            if record.record_type() == question.query_type() {
                terminal = true;
            }
        }
        if let Some(next) = target {
            // DNAME redirects a subtree and is accompanied by a synthesized CNAME.
            // Retain it only when that exact substitution agrees with this chain.
            for record in &response.answers {
                if u16::from(record.record_type()) == 39
                    && record.name != *owner
                    && record.name.zone_of(owner)
                {
                    if record.dns_class != question.query_class()
                        || dname_substitution(record, owner).as_ref() != Some(next)
                    {
                        return false;
                    }
                    dnames.insert(record_set(record));
                }
            }
        }
        if terminal {
            if target.is_some() && question.query_type() != RecordType::CNAME {
                return false;
            }
            // No unrelated answer can justify throwing away its dependencies.
            return response.answers.iter().all(|record| {
                (visited.contains(&record.name)
                    && (record.record_type() == question.query_type()
                        || record.record_type() == RecordType::CNAME
                        || signature_covered_type(record).is_some()))
                    || dnames.contains(&record_set(record))
                    || signature_covered_type(record).is_some_and(|kind| {
                        dnames.contains(&(record.name.clone(), record.dns_class, kind))
                    })
            });
        }
        let Some(next) = target else {
            return false;
        };
        owner = next;
    }
}

fn dname_substitution(record: &Record, owner: &Name) -> Option<Name> {
    let RData::Unknown { rdata, .. } = &record.data else {
        return None;
    };
    let mut offset = 0;
    let suffix = raw_name(&rdata.anything, &mut offset)?;
    if offset != rdata.anything.len() {
        return None;
    }
    let labels = owner
        .iter()
        .count()
        .checked_sub(record.name.iter().count())?;
    Name::from_labels(owner.iter().take(labels))
        .ok()?
        .append_name(&suffix)
        .ok()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netstack::shared::SharedState;
    use crate::policy::{NetworkPolicy, NetworkProfile};
    use hickory_net::proto::op::Query;
    use hickory_net::proto::rr::rdata::{
        A, AAAA, ANAME, CNAME, HTTPS, MX, NAPTR, NS, NULL, PTR, SOA, SRV, TXT,
        svcb::{IpHint, SvcParamKey},
    };
    use hickory_net::proto::serialize::binary::BinEncodable;

    fn name(value: &str) -> Name {
        Name::from_ascii(value).unwrap()
    }
    fn record(owner: &str, data: RData) -> Record {
        Record::from_rdata(name(owner), 30, data)
    }
    fn public_a(owner: &str) -> Record {
        record(owner, RData::A(A("8.8.8.8".parse().unwrap())))
    }
    fn raw(kind: u16, bytes: Vec<u8>) -> RData {
        RData::Unknown {
            code: RecordType::from(kind),
            rdata: NULL::with(bytes),
        }
    }
    fn pair() -> (Message, Message) {
        let mut query = Message::new(7, MessageType::Query, OpCode::Query);
        query
            .queries
            .push(Query::query(name("public.example."), RecordType::A));
        let mut response = Message::response(7, OpCode::Query);
        response.queries = query.queries.clone();
        response.answers.push(public_a("public.example."));
        (query, response)
    }
    fn signature(kind: u16, covered: u16, signer: &str) -> RData {
        let mut bytes = vec![0; 18];
        bytes[..2].copy_from_slice(&covered.to_be_bytes());
        bytes.extend(name(signer).to_bytes().unwrap());
        bytes.push(1);
        raw(kind, bytes)
    }

    #[test]
    fn all_typed_name_records_are_checked_in_each_section() {
        let local = name("printer.local.");
        let records = vec![
            RData::ANAME(ANAME(local.clone())),
            RData::CNAME(CNAME(local.clone())),
            RData::NS(NS(local.clone())),
            RData::PTR(PTR(local.clone())),
            RData::MX(MX::new(1, local.clone())),
            RData::SOA(SOA::new(
                local.clone(),
                name("admin.example."),
                1,
                2,
                3,
                4,
                5,
            )),
            RData::SOA(SOA::new(name("ns.example."), local.clone(), 1, 2, 3, 4, 5)),
            RData::SRV(SRV::new(0, 0, 80, local.clone())),
            RData::NAPTR(NAPTR::new(
                0,
                0,
                Box::from(&b"S"[..]),
                Box::default(),
                Box::default(),
                local.clone(),
            )),
            RData::SVCB(SVCB::new(1, local.clone(), vec![])),
            RData::HTTPS(HTTPS(SVCB::new(1, local, vec![]))),
        ];
        let shared = SharedState::new(4);
        let tenant = NetworkPolicy::from_profiles([NetworkProfile::Public]);
        let policy = NamePolicy::new(&tenant, None, &shared);
        for data in records {
            for section in 0..3 {
                let (query, mut response) = pair();
                let restricted = record("alias.example.", data.clone());
                match section {
                    0 => response.answers.push(restricted),
                    1 => response.authorities.push(restricted),
                    _ => response.additionals.push(restricted),
                }
                assert_eq!(
                    filter_response(&policy, &query, &mut response, true),
                    section != 0,
                    "{data:?}, section {section}"
                );
                if section != 0 {
                    assert_eq!(response.answers, vec![public_a("public.example.")]);
                    assert!(response.authorities.is_empty() && response.additionals.is_empty());
                }
            }
        }
    }

    #[test]
    fn owners_and_address_hints_cannot_bypass_filtering() {
        let shared = SharedState::new(4);
        shared.set_nat64_prefixes(vec!["64:ff9b::/96".parse().unwrap()]);
        let tenant = NetworkPolicy::from_profiles([NetworkProfile::Public]);
        let policy = NamePolicy::new(&tenant, None, &shared);
        let candidates = vec![
            record(
                "printer.local.",
                RData::TXT(TXT::new(vec!["device".into()])),
            ),
            record(
                "public.example.",
                RData::AAAA(AAAA("::ffff:10.0.0.1".parse().unwrap())),
            ),
            record(
                "public.example.",
                RData::AAAA(AAAA("64:ff9b::a00:1".parse().unwrap())),
            ),
            record(
                "public.example.",
                RData::SVCB(SVCB::new(
                    1,
                    name("svc.example."),
                    vec![(
                        SvcParamKey::Ipv4Hint,
                        SvcParamValue::Ipv4Hint(IpHint(vec![A("10.0.0.1".parse().unwrap())])),
                    )],
                )),
            ),
            record(
                "public.example.",
                RData::HTTPS(HTTPS(SVCB::new(
                    1,
                    name("svc.example."),
                    vec![(
                        SvcParamKey::Ipv6Hint,
                        SvcParamValue::Ipv6Hint(IpHint(vec![AAAA(
                            "64:ff9b::a00:1".parse().unwrap(),
                        )])),
                    )],
                ))),
            ),
        ];
        for restricted in candidates {
            let (query, mut response) = pair();
            response.answers = vec![restricted];
            assert!(!filter_response(&policy, &query, &mut response, true));
        }
    }

    #[test]
    fn raw_name_records_check_signers_next_names_and_legacy_targets() {
        let shared = SharedState::new(4);
        let tenant = NetworkPolicy::from_profiles([NetworkProfile::Public]);
        let policy = NamePolicy::new(&tenant, None, &shared);
        for kind in [
            3, 4, 7, 8, 9, 23, 39, 14, 17, 18, 21, 36, 26, 24, 46, 30, 47,
        ] {
            for local in [false, true] {
                let wire = name(if local {
                    "printer.local."
                } else {
                    "public.example."
                })
                .to_bytes()
                .unwrap();
                let mut bytes = match kind {
                    18 | 21 | 36 | 26 => vec![0; 2],
                    24 | 46 => vec![0; 18],
                    _ => vec![],
                };
                bytes.extend(&wire);
                if matches!(kind, 14 | 17 | 26) {
                    bytes.extend(&wire);
                }
                if matches!(kind, 24 | 46 | 30 | 47) {
                    bytes.extend([0, 1, 2]);
                }
                assert_eq!(
                    record_allowed(&policy, &record("public.example.", raw(kind, bytes))),
                    !local,
                    "type {kind}"
                );
            }
        }
        for bytes in [vec![0xc0, 12], vec![64, 0], vec![8, b'x'], vec![1, b'x']] {
            assert!(!record_allowed(
                &policy,
                &record("public.example.", raw(39, bytes))
            ));
        }
        assert!(
            record_allowed(
                &policy,
                &record("public.example.", raw(65280, vec![0xc0, 12]))
            ),
            "opaque unrelated record types retain their behavior"
        );
    }

    #[test]
    fn incomplete_or_ambiguous_answers_cannot_drop_restricted_dependencies() {
        let shared = SharedState::new(4);
        let tenant = NetworkPolicy::from_profiles([NetworkProfile::Public]);
        let policy = NamePolicy::new(&tenant, None, &shared);
        for case in 0..9 {
            let (query, mut response) = pair();
            response.additionals.push(record(
                "secret.example.",
                RData::A(A("10.0.0.9".parse().unwrap())),
            ));
            match case {
                0 => response.answers.clear(),
                1 => response.metadata.truncation = true,
                2 => response.metadata.response_code = ResponseCode::NXDomain,
                3 => response.queries[0] = Query::query(name("different.example."), RecordType::A),
                4 => {
                    response.answers = vec![record(
                        "public.example.",
                        RData::CNAME(CNAME(name("missing.example."))),
                    )]
                }
                5 => {
                    response.answers = vec![
                        record(
                            "public.example.",
                            RData::CNAME(CNAME(name("loop.example."))),
                        ),
                        record(
                            "loop.example.",
                            RData::CNAME(CNAME(name("public.example."))),
                        ),
                    ]
                }
                6 => response.answers.extend([
                    record("public.example.", RData::CNAME(CNAME(name("one.example.")))),
                    record("public.example.", RData::CNAME(CNAME(name("two.example.")))),
                ]),
                7 => response.answers[0].dns_class = DNSClass::CH,
                _ => response.answers = vec![public_a("unrelated.example.")],
            }
            assert!(
                !filter_response(&policy, &query, &mut response, true),
                "case {case}"
            );
        }
    }

    #[test]
    fn stripping_removes_whole_rrsets_and_only_invalid_signatures() {
        let shared = SharedState::new(4);
        let tenant = NetworkPolicy::from_profiles([NetworkProfile::Public]);
        let policy = NamePolicy::new(&tenant, None, &shared);
        let (query, mut response) = pair();
        response.metadata.authentic_data = true;
        response
            .answers
            .push(record("public.example.", signature(46, 1, "example.")));
        response.additionals.extend([
            public_a("mixed.example."),
            record("mixed.example.", RData::A(A("10.0.0.1".parse().unwrap()))),
            record("mixed.example.", signature(46, 1, "example.")),
            record("key.example.", signature(24, 0, "example.")),
            public_a("safe.example."),
        ]);
        assert!(filter_response(&policy, &query, &mut response, true));
        assert!(!response.metadata.authentic_data);
        assert_eq!(
            response.answers.len(),
            2,
            "unchanged public answer signature is retained"
        );
        assert_eq!(response.additionals, vec![public_a("safe.example.")]);
    }

    #[test]
    fn complete_public_cname_chain_survives_ancillary_filtering() {
        let shared = SharedState::new(4);
        let tenant = NetworkPolicy::from_profiles([NetworkProfile::Public]);
        let policy = NamePolicy::new(&tenant, None, &shared);
        let (query, mut response) = pair();
        response.answers = vec![
            record(
                "public.example.",
                RData::CNAME(CNAME(name("target.example."))),
            ),
            public_a("target.example."),
        ];
        response.authorities.push(record(
            "172.in-addr.arpa.",
            RData::NS(NS(name("ns.example."))),
        ));
        let expected = response.answers.clone();
        assert!(filter_response(&policy, &query, &mut response, true));
        assert_eq!(response.answers, expected);
        assert!(response.authorities.is_empty());
    }

    #[test]
    fn safe_answers_and_explicit_resolver_names_keep_their_contract() {
        let shared = SharedState::new(4);
        let tenant = NetworkPolicy::from_profiles([NetworkProfile::Public]);
        let policy = NamePolicy::new(&tenant, None, &shared);
        let (query, mut response) = pair();
        response.metadata.authentic_data = true;
        let original = response.clone();
        assert!(filter_response(&policy, &query, &mut response, true));
        assert_eq!(response, original);
        response.answers = vec![record(
            "public.example.",
            RData::PTR(PTR(name("printer.local."))),
        )];
        assert!(filter_response(&policy, &query, &mut response, false));
        assert!(!filter_response(&policy, &query, &mut response, true));
    }

    #[test]
    fn uncommon_name_and_address_records_enforce_the_same_policy() {
        let shared = SharedState::new(4);
        let public = NetworkPolicy::from_profiles([NetworkProfile::Public]);
        let policy = NamePolicy::new(&public, None, &shared);
        for target in ["printer.local.", "public.example."] {
            let wire = name(target).to_bytes().unwrap();
            for (kind, prefix, suffix) in [
                (38, vec![128], vec![]),
                (45, vec![0, 3, 0], vec![]),
                (55, vec![1, 0, 0, 1, 0, 0], vec![]),
                (107, vec![0, 1], vec![]),
                (249, vec![], vec![0; 16]),
                (260, vec![0, 3], vec![]),
            ] {
                let bytes = [prefix, wire.clone(), suffix].concat();
                assert_eq!(
                    record_allowed(&policy, &record("public.example.", raw(kind, bytes))),
                    target == "public.example.",
                    "kind {kind}"
                );
            }
        }
        for (kind, prefix, address) in [
            (38, vec![0], "fd00::1"),
            (45, vec![0, 1, 0], "10.0.0.1"),
            (45, vec![0, 2, 0], "::ffff:10.0.0.1"),
            (260, vec![0, 1], "10.0.0.1"),
            (260, vec![0, 2], "fd00::1"),
        ] {
            let bytes = match address.parse::<IpAddr>().unwrap() {
                IpAddr::V4(a) => a.octets().to_vec(),
                IpAddr::V6(a) => a.octets().to_vec(),
            };
            assert!(!record_allowed(
                &policy,
                &record("public.example.", raw(kind, [prefix, bytes].concat()))
            ));
        }
        for kind in [38, 45, 55, 107, 249, 260] {
            assert!(
                !raw_names_allowed(&policy, kind, &[]),
                "truncated kind {kind}"
            );
        }
        assert!(!raw_names_allowed(&policy, 55, &[255, 0, 255, 255]));
        assert!(!raw_names_allowed(&policy, 38, &[129]));
        assert!(!raw_names_allowed(&policy, 260, &[0, 3, 0xc0, 0x0c]));
    }

    #[test]
    fn complete_dname_substitution_survives_ancillary_filtering() {
        let shared = SharedState::new(4);
        let tenant = NetworkPolicy::from_profiles([NetworkProfile::Public]);
        let policy = NamePolicy::new(&tenant, None, &shared);
        let (query, mut response) = pair();
        response.answers = vec![
            record("example.", raw(39, name("net.").to_bytes().unwrap())),
            record("public.example.", RData::CNAME(CNAME(name("public.net.")))),
            public_a("public.net."),
        ];
        response
            .authorities
            .push(record("printer.local.", RData::NS(NS(name("ns.example.")))));
        let mut invalid = response.clone();
        invalid.answers[1] = record("public.example.", RData::CNAME(CNAME(name("wrong.net."))));
        assert!(!filter_response(&policy, &query, &mut invalid, true));
        assert!(filter_response(&policy, &query, &mut response, true));
        assert_eq!(response.answers.len(), 3);
        assert!(response.authorities.is_empty());
        let mut cname_query = query.clone();
        cname_query.queries[0] = Query::query(name("public.example."), RecordType::CNAME);
        response.queries = cname_query.queries.clone();
        response.answers.pop();
        response
            .authorities
            .push(record("printer.local.", RData::NS(NS(name("ns.example.")))));
        assert!(filter_response(&policy, &cname_query, &mut response, true));
        assert_eq!(response.answers.len(), 2);
    }

    #[test]
    fn matching_other_opcodes_are_preserved_without_ancillary_rewriting() {
        let shared = SharedState::new(4);
        let tenant = NetworkPolicy::from_profiles([NetworkProfile::Public]);
        let policy = NamePolicy::new(&tenant, None, &shared);
        let (mut query, mut response) = pair();
        query.metadata.op_code = OpCode::Update;
        response.metadata.op_code = OpCode::Update;
        assert!(filter_response(&policy, &query, &mut response, true));
        response
            .authorities
            .push(record("printer.local.", RData::NS(NS(name("ns.example.")))));
        assert!(!filter_response(&policy, &query, &mut response, true));
    }

    #[test]
    fn empty_update_records_cannot_prove_completion() {
        let (query, mut response) = pair();
        response.answers[0] = Record::update0(name("public.example."), 30, RecordType::A);
        assert!(!complete_answer(&query, &response));
    }
}
