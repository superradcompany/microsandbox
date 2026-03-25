//! TLS ClientHello SNI extraction.
//!
//! Parses the Server Name Indication extension from a buffered TLS
//! ClientHello message to determine which domain the guest is connecting to.

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Extract the SNI hostname from a TLS ClientHello message.
///
/// `data` should contain at least the TLS record header and the ClientHello.
/// Returns `None` if the data is not a valid ClientHello or has no SNI.
pub fn extract_sni(data: &[u8]) -> Option<String> {
    // TLS record header: type(1) + version(2) + length(2).
    if data.len() < 5 {
        return None;
    }
    if data[0] != 0x16 {
        return None; // Not a Handshake record.
    }

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    let record = data.get(5..5 + record_len)?;

    // Handshake header: type(1) + length(3).
    if record.first() != Some(&0x01) {
        return None; // Not ClientHello.
    }
    let hs_len = (record[1] as usize) << 16 | (record[2] as usize) << 8 | (record[3] as usize);
    let hello = record.get(4..4 + hs_len)?;

    // ClientHello: version(2) + random(32) = 34 bytes.
    if hello.len() < 34 {
        return None;
    }
    let mut pos = 34;

    // Session ID.
    let session_id_len = *hello.get(pos)? as usize;
    pos += 1 + session_id_len;

    // Cipher suites.
    if pos + 2 > hello.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    // Compression methods.
    let comp_len = *hello.get(pos)? as usize;
    pos += 1 + comp_len;

    // Extensions.
    if pos + 2 > hello.len() {
        return None;
    }
    let extensions_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = pos + extensions_len;
    while pos + 4 <= extensions_end && pos + 4 <= hello.len() {
        let ext_type = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
        let ext_len = u16::from_be_bytes([hello[pos + 2], hello[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension.
            return parse_sni_extension(hello.get(pos..pos + ext_len)?);
        }

        pos += ext_len;
    }

    None
}

/// Parse the SNI extension data to extract the hostname.
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    // ServerNameList: length(2) + entries.
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let list = data.get(2..2 + list_len)?;

    let mut pos = 0;
    while pos + 3 <= list.len() {
        let name_type = list[pos];
        let name_len = u16::from_be_bytes([list[pos + 1], list[pos + 2]]) as usize;
        pos += 3;

        if name_type == 0x00 {
            // HostName.
            let name_bytes = list.get(pos..pos + name_len)?;
            return String::from_utf8(name_bytes.to_vec()).ok();
        }

        pos += name_len;
    }

    None
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
        let hello_len = 2 + 32 + 1 + 0 + 2 + 2 + 1 + 1 + 2 + extensions_len;

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
}
