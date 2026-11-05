//! TLS ClientHello SNI extraction.
//!
//! Parses the Server Name Indication extension from a buffered TLS
//! ClientHello message to determine which domain the guest is connecting to.

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A complete ClientHello, which may omit the server name.
pub(super) struct ClientHello {
    /// The wire hostname, before DNS-name validation.
    pub server_name: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Extract the SNI hostname from a buffered TLS ClientHello.
/// Returns `None` for incomplete or malformed messages, or an absent SNI.
pub fn extract_sni(data: &[u8]) -> Option<String> {
    // Policy peeking has always used the first SNI. A later malformed or
    // duplicate extension must not erase or replace that policy evidence.
    parse_client_hello_inner(data, true)?.server_name
}

/// Peek at a complete ClientHello without requiring rustls-compatible ciphers
/// or extensions. Bypass forwards legacy TLS without terminating it.
pub(super) fn parse_client_hello(data: &[u8]) -> Option<ClientHello> {
    parse_client_hello_inner(data, false)
}

fn parse_client_hello_inner(mut data: &[u8], first_name_only: bool) -> Option<ClientHello> {
    let mut handshake = Vec::new();
    loop {
        let header = data.get(..5)?;
        if header[0] != 0x16 || header[1] != 3 {
            return None;
        }
        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let record_end = 5 + record_len;
        handshake.extend_from_slice(data.get(5..record_end)?);
        data = &data[record_end..];
        if handshake.len() < 4 {
            continue;
        }
        if handshake[0] != 1 {
            return None;
        }
        let length = ((handshake[1] as usize) << 16)
            | ((handshake[2] as usize) << 8)
            | handshake[3] as usize;
        if handshake.len() >= 4 + length {
            return parse_hello_body(&handshake[4..4 + length], first_name_only);
        }
    }
}

fn parse_hello_body(hello: &[u8], first_name_only: bool) -> Option<ClientHello> {
    // Version and random, then length-prefixed session ID, cipher suites,
    // and compression methods. Extensions are optional in legacy TLS.
    let mut pos = 34;
    let session_id_len = *hello.get(pos)? as usize;
    pos += 1 + session_id_len;
    let cipher_len = hello.get(pos..pos + 2)?;
    pos += 2 + u16::from_be_bytes([cipher_len[0], cipher_len[1]]) as usize;
    let compression_len = *hello.get(pos)? as usize;
    pos += 1 + compression_len;
    if pos == hello.len() {
        return Some(ClientHello { server_name: None });
    }
    let length = hello.get(pos..pos + 2)?;
    pos += 2;
    let end = pos + u16::from_be_bytes([length[0], length[1]]) as usize;
    if !first_name_only && end != hello.len() {
        return None;
    }
    let mut server_name = None;
    while pos + 4 <= end && pos + 4 <= hello.len() {
        let header = hello.get(pos..pos + 4)?;
        let kind = u16::from_be_bytes([header[0], header[1]]);
        let length = u16::from_be_bytes([header[2], header[3]]) as usize;
        pos += 4;
        let extension = hello.get(pos..pos + length)?;
        if kind == 0 {
            if server_name.is_some() {
                return None;
            }
            server_name = Some(parse_sni_extension(extension, first_name_only)?);
            if first_name_only {
                return Some(ClientHello { server_name });
            }
        }
        pos += length;
    }
    if !first_name_only && pos != end {
        return None;
    }
    Some(ClientHello { server_name })
}

/// Parse the SNI extension data to extract the hostname.
fn parse_sni_extension(data: &[u8], first_name_only: bool) -> Option<String> {
    let length = data.get(..2)?;
    let list_len = u16::from_be_bytes([length[0], length[1]]) as usize;
    if !first_name_only && list_len != data.len() - 2 {
        return None;
    }
    let mut list = data.get(2..2 + list_len)?;
    let mut server_name = None;
    while !list.is_empty() {
        let header = list.get(..3)?;
        let name_len = u16::from_be_bytes([header[1], header[2]]) as usize;
        let name = list.get(3..3 + name_len)?;
        if header[0] == 0 {
            if server_name.is_some() {
                return None;
            }
            server_name = Some(String::from_utf8(name.to_vec()).ok()?);
            if first_name_only {
                return server_name;
            }
        } else if !first_name_only {
            // rustls only supports host_name entries in ServerNameList.
            return None;
        }
        list = &list[3 + name_len..];
    }
    server_name
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal TLS 1.2 ClientHello with SNI "example.com".
    fn build_client_hello(hostname: &str) -> Vec<u8> {
        let hostname_bytes = hostname.as_bytes();

        // SNI extension.
        let sni_entry_len = 3 + hostname_bytes.len(); // type(1) + len(2) + name
        let sni_list_len = sni_entry_len;
        let sni_ext_data_len = 2 + sni_list_len; // list_len(2) + entries
        let sni_ext_len = 4 + sni_ext_data_len; // type(2) + len(2) + data

        let extensions_len = sni_ext_len;

        // ClientHello body.
        let hello_len = (2 + 32 + 1) + 2 + 2 + 1 + 1 + 2 + extensions_len;

        // Handshake.
        let hs_len = 4 + hello_len;

        // Record.
        let record_len = hs_len;
        let total = 5 + record_len;

        let mut buf = vec![0u8; total];
        let mut pos = 0;

        // TLS record header.
        buf[pos] = 0x16; // Handshake
        pos += 1;
        buf[pos..pos + 2].copy_from_slice(&[0x03, 0x01]); // TLS 1.0
        pos += 2;
        buf[pos..pos + 2].copy_from_slice(&(record_len as u16).to_be_bytes());
        pos += 2;

        // Handshake header.
        buf[pos] = 0x01; // ClientHello
        pos += 1;
        buf[pos] = 0;
        buf[pos + 1] = ((hello_len >> 8) & 0xFF) as u8;
        buf[pos + 2] = (hello_len & 0xFF) as u8;
        pos += 3;

        // ClientHello.
        buf[pos..pos + 2].copy_from_slice(&[0x03, 0x03]); // TLS 1.2
        pos += 2;
        // Random (32 bytes of zeros).
        pos += 32;
        // Session ID length: 0.
        buf[pos] = 0;
        pos += 1;
        // Cipher suites: 1 suite (2 bytes).
        buf[pos..pos + 2].copy_from_slice(&2u16.to_be_bytes());
        pos += 2;
        buf[pos..pos + 2].copy_from_slice(&[0x00, 0x2F]); // TLS_RSA_WITH_AES_128_CBC_SHA
        pos += 2;
        // Compression: 1 method (null).
        buf[pos] = 1;
        pos += 1;
        buf[pos] = 0;
        pos += 1;

        // Extensions length.
        buf[pos..pos + 2].copy_from_slice(&(extensions_len as u16).to_be_bytes());
        pos += 2;

        // SNI extension.
        buf[pos..pos + 2].copy_from_slice(&0u16.to_be_bytes()); // type: SNI
        pos += 2;
        buf[pos..pos + 2].copy_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
        pos += 2;
        buf[pos..pos + 2].copy_from_slice(&(sni_list_len as u16).to_be_bytes());
        pos += 2;
        buf[pos] = 0x00; // HostName type
        pos += 1;
        buf[pos..pos + 2].copy_from_slice(&(hostname_bytes.len() as u16).to_be_bytes());
        pos += 2;
        buf[pos..pos + hostname_bytes.len()].copy_from_slice(hostname_bytes);

        buf
    }

    #[test]
    fn extract_sni_from_client_hello() {
        let hello = build_client_hello("example.com");
        assert_eq!(extract_sni(&hello), Some("example.com".to_string()));
    }

    #[test]
    fn extract_sni_long_hostname() {
        let hello = build_client_hello("api.staging.internal.example.com");
        assert_eq!(
            extract_sni(&hello),
            Some("api.staging.internal.example.com".to_string())
        );
    }

    #[test]
    fn extract_sni_returns_none_for_garbage() {
        assert_eq!(extract_sni(&[]), None);
        assert_eq!(extract_sni(&[0x17, 0x03, 0x01, 0x00, 0x05]), None);
    }

    #[test]
    fn extract_sni_returns_none_for_short_client_hello_record() {
        assert_eq!(extract_sni(&[0x16, 0x03, 0x01, 0x00, 0x01, 0x01]), None);
    }

    #[test]
    fn extract_sni_returns_none_for_fragmented_client_hello_prefixes() {
        let hello = build_client_hello("example.com");

        for len in 0..hello.len() {
            assert_eq!(extract_sni(&hello[..len]), None, "prefix length {len}");
        }

        assert_eq!(extract_sni(&hello), Some("example.com".to_string()));
    }
    #[test]
    fn complete_hello_without_sni_is_distinct_from_incomplete() {
        let named = build_client_hello("example.com");
        // No extensions (legacy), an empty extension block, and an unknown
        // extension are all complete hellos with no server name.
        for (kind, extensions) in [
            ("absent", None),
            ("empty", Some(Vec::new())),
            ("unknown", Some(vec![0x12, 0x34, 0, 2, 7, 8])),
        ] {
            let mut hello = named[..50].to_vec();
            if let Some(extensions) = extensions {
                hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
                hello.extend_from_slice(&extensions);
            }
            patch_hello_lengths(&mut hello);
            for end in 0..hello.len() {
                assert!(
                    parse_client_hello(&hello[..end]).is_none(),
                    "{kind}: prefix={end}"
                );
            }
            assert!(parse_client_hello(&hello).unwrap().server_name.is_none());
        }
    }

    #[test]
    fn every_record_split_preserves_name_and_requires_complete_input() {
        let hello = build_client_hello("example.com");
        for split in 1..hello.len() - 5 {
            let mut wire = Vec::new();
            for body in [&hello[5..5 + split], &hello[5 + split..]] {
                wire.extend_from_slice(&hello[..3]);
                wire.extend_from_slice(&(body.len() as u16).to_be_bytes());
                wire.extend_from_slice(body);
            }
            for end in 0..wire.len() {
                assert!(
                    parse_client_hello(&wire[..end]).is_none(),
                    "split={split}, prefix={end}"
                );
            }
            assert_eq!(
                parse_client_hello(&wire).unwrap().server_name.as_deref(),
                Some("example.com")
            );
            assert_eq!(extract_sni(&wire).as_deref(), Some("example.com"));
            // Later records are not part of the ClientHello being inspected.
            wire.extend_from_slice(&[0x17, 3, 3, 0, 3, 1, 2, 3]);
            assert_eq!(extract_sni(&wire).as_deref(), Some("example.com"));
        }
    }

    #[test]
    fn malformed_lengths_and_record_headers_are_rejected() {
        let hello = build_client_hello("example.com");
        // Wire offsets in this fixture: record length, handshake length,
        // session ID length, ciphers length, compression length, extensions
        // length, SNI extension length, name-list length, hostname length.
        for (offset, replacement) in [
            (0, vec![0x17]),
            (1, vec![4]),
            (5, vec![2]),
            (3, vec![0xff, 0xff]),
            (6, vec![0xff, 0xff, 0xff]),
            (43, vec![0xff]),
            (44, vec![0xff, 0xff]),
            (48, vec![0xff]),
            (50, vec![0xff, 0xff]),
            (54, vec![0xff, 0xff]),
            (56, vec![0xff, 0xff]),
            (59, vec![0xff, 0xff]),
        ] {
            let mut malformed = hello.clone();
            malformed[offset..offset + replacement.len()].copy_from_slice(&replacement);
            assert!(parse_client_hello(&malformed).is_none(), "offset={offset}");
        }
        // Unknown SNI name types and an empty name list must reach the
        // validating TLS decoder, not be mistaken for an absent extension.
        let mut unknown = hello.clone();
        unknown[58] = 1;
        assert!(parse_client_hello(&unknown).is_none());
        let mut empty = hello[..58].to_vec();
        empty[50..52].copy_from_slice(&6u16.to_be_bytes());
        empty[54..56].copy_from_slice(&2u16.to_be_bytes());
        empty[56..58].copy_from_slice(&0u16.to_be_bytes());
        patch_hello_lengths(&mut empty);
        assert!(parse_client_hello(&empty).is_none());
    }

    fn patch_hello_lengths(hello: &mut [u8]) {
        let record = (hello.len() - 5) as u16;
        let handshake = (hello.len() - 9) as u32;
        hello[3..5].copy_from_slice(&record.to_be_bytes());
        hello[6..9].copy_from_slice(&handshake.to_be_bytes()[1..]);
    }
}
