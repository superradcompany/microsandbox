//! Expand legacy compressed RDATA names while their original packet is available.

use std::collections::HashMap;

use hickory_net::proto::op::{Header, Message, Query};
use hickory_net::proto::rr::{Name, RData};
use hickory_net::proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable};

use super::response_policy::message_signature;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Hickory leaves some historical name-bearing types opaque. RFC 3597 section 4
/// still requires/supports compression in these types. Expand them before policy
/// inspection or re-encoding: a pointer belongs to the original packet, not to
/// detached RDATA or to the differently laid out response sent to the guest.
pub(super) fn expand_names(message: &mut Message, wire: &[u8]) -> Option<()> {
    let records = message
        .answers
        .iter()
        .chain(&message.authorities)
        .chain(&message.additionals);
    if !records.clone().any(|record| matches!(&record.data, RData::Unknown { code, .. } if layout(u16::from(*code)).is_some())) {
        return Some(());
    }
    let mut decoder = BinDecoder::new(wire);
    let header = Header::read(&mut decoder).ok()?;
    for _ in 0..header.counts.queries {
        Query::read(&mut decoder).ok()?;
    }
    let total = usize::from(header.counts.answers)
        + usize::from(header.counts.authorities)
        + usize::from(header.counts.additionals);
    let mut expanded = HashMap::new();
    for _ in 0..total {
        Name::read(&mut decoder).ok()?;
        let kind = decoder.read_u16().ok()?.unverified();
        decoder.read_slice(6).ok()?; // class and TTL
        let length = usize::from(decoder.read_u16().ok()?.unverified());
        let start = decoder.index();
        let bytes = decoder.read_slice(length).ok()?.unverified();
        let Some((prefix, count, trailing)) = layout(kind) else {
            continue;
        };
        if bytes.len() < prefix {
            return None;
        }
        let mut names = BinDecoder::new(wire).clone(u16::try_from(start + prefix).ok()?);
        let mut normalized = bytes[..prefix].to_vec();
        for _ in 0..count {
            let name = Name::read(&mut names).ok()?;
            if names.index() > start + length {
                return None;
            }
            normalized.extend(name.to_bytes().ok()?);
        }
        if !trailing && names.index() != start + length {
            return None;
        }
        normalized.extend(wire.get(names.index()..start + length)?);
        expanded.insert((kind, bytes.to_vec()), normalized);
    }
    let mut changed = false;
    for record in message
        .answers
        .iter_mut()
        .chain(&mut message.authorities)
        .chain(&mut message.additionals)
    {
        if let RData::Unknown { code, rdata } = &mut record.data
            && layout(u16::from(*code)).is_some()
        {
            let normalized = expanded.get(&(u16::from(*code), rdata.anything.clone()))?;
            changed |= rdata.anything != *normalized;
            rdata.anything.clone_from(normalized);
        }
    }
    if changed {
        // Compression changes preserve RRset contents and DNSSEC signatures,
        // but not signatures over the original message's exact wire bytes.
        message.signature = None;
        message.answers.retain(|record| !message_signature(record));
        message
            .authorities
            .retain(|record| !message_signature(record));
        message
            .additionals
            .retain(|record| !message_signature(record));
    }
    Some(())
}

fn layout(kind: u16) -> Option<(usize, usize, bool)> {
    Some(match kind {
        3 | 4 | 7 | 8 | 9 => (0, 1, false), // RFC 1035 MD/MF/MB/MG/MR
        14 | 17 => (0, 2, false),           // MINFO/RP
        18 | 21 => (2, 1, false),           // AFSDB/RT
        26 => (2, 2, false),                // PX
        24 => (18, 1, true),                // SIG signer, then signature
        30 => (0, 1, true),                 // NXT next name, then bitmap
        _ => return None,
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_net::proto::op::{MessageType, OpCode};
    use hickory_net::proto::rr::{Record, RecordType, rdata::NULL};

    #[test]
    fn legacy_compression_is_expanded_before_reencoding() {
        for kind in [3, 4, 7, 8, 9, 14, 17, 18, 21, 24, 26, 30] {
            let (prefix, count, trailing) = layout(kind).unwrap();
            let target = Name::from_ascii("public.example.").unwrap();
            let mut data = vec![0; prefix];
            if kind == 24 {
                data[1] = 1;
            }
            for _ in 0..count {
                data.extend([0xc0, 0x0c]);
            }
            if trailing {
                data.push(1);
            }
            let mut message = Message::new(9, MessageType::Response, OpCode::Query);
            message
                .queries
                .push(Query::query(target.clone(), RecordType::A));
            message.additionals.push(Record::from_rdata(
                target.clone(),
                30,
                RData::Unknown {
                    code: RecordType::from(kind),
                    rdata: NULL::with(data),
                },
            ));
            let wire = message.to_bytes().unwrap();
            let mut parsed = Message::from_bytes(&wire).unwrap();
            expand_names(&mut parsed, &wire).unwrap();
            let RData::Unknown { rdata, .. } = &parsed.additionals[0].data else {
                panic!()
            };
            let mut expected = vec![0; prefix];
            if kind == 24 {
                expected[1] = 1;
            }
            for _ in 0..count {
                expected.extend(target.to_bytes().unwrap());
            }
            if trailing {
                expected.push(1);
            }
            assert_eq!(rdata.anything, expected, "kind {kind}");
            // Moving the question changes all packet offsets, but detached data
            // now contains full names and is safe to serialize at any position.
            parsed.queries[0] = Query::query(
                Name::from_ascii("different.example.").unwrap(),
                RecordType::A,
            );
            assert_eq!(
                Message::from_bytes(&parsed.to_bytes().unwrap())
                    .unwrap()
                    .additionals[0]
                    .data,
                parsed.additionals[0].data
            );
        }
    }

    #[test]
    fn out_of_packet_and_self_referential_pointers_are_rejected() {
        let target = Name::from_ascii("public.example.").unwrap();
        for pointer in [[0xff, 0xff], [0xc0, 0x00]] {
            let mut message = Message::new(0xffff, MessageType::Response, OpCode::Query);
            message
                .queries
                .push(Query::query(target.clone(), RecordType::A));
            message.answers.push(Record::from_rdata(
                target.clone(),
                30,
                RData::Unknown {
                    code: RecordType::from(3),
                    rdata: NULL::with(pointer.to_vec()),
                },
            ));
            let wire = message.to_bytes().unwrap();
            assert!(expand_names(&mut message, &wire).is_none());
        }
    }

    #[test]
    fn expanding_public_names_removes_only_whole_message_authentication() {
        use hickory_net::proto::rr::rdata::{TSIG, tsig::TsigAlgorithm};
        let target = Name::from_ascii("public.example.").unwrap();
        for compressed in [false, true] {
            let mut message = Message::new(9, MessageType::Response, OpCode::Query);
            message.metadata.authentic_data = true;
            message
                .queries
                .push(Query::query(target.clone(), RecordType::from(3)));
            message.answers.push(Record::from_rdata(
                target.clone(),
                30,
                RData::Unknown {
                    code: RecordType::from(3),
                    rdata: NULL::with(if compressed {
                        vec![0xc0, 0x0c]
                    } else {
                        target.to_bytes().unwrap()
                    }),
                },
            ));
            message.additionals.push(Record::from_rdata(
                target.clone(),
                0,
                RData::TSIG(TSIG::new(
                    TsigAlgorithm::HmacSha256,
                    0,
                    300,
                    vec![1],
                    9,
                    None,
                    vec![],
                )),
            ));
            let wire = message.to_bytes().unwrap();
            expand_names(&mut message, &wire).unwrap();
            assert_eq!(message.additionals.is_empty(), compressed);
            assert!(
                message.metadata.authentic_data,
                "RRset semantics did not change"
            );
        }
    }
}
