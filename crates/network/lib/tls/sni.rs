//! TLS ClientHello parser for SNI (Server Name Indication) extraction.

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// TLS record content type for handshake messages.
const TLS_CONTENT_HANDSHAKE: u8 = 0x16;

/// TLS handshake type for ClientHello.
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;

/// TLS extension type for Server Name Indication.
const EXT_SERVER_NAME: u16 = 0x0000;

/// SNI host name type.
const SNI_HOST_NAME: u8 = 0x00;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Extracts the SNI (Server Name Indication) from a TLS ClientHello message.
///
/// Parses the TLS record layer, handshake header, and walks the extensions list
/// to find the SNI extension. Returns `None` if the bytes are not a valid
/// ClientHello or if no SNI extension is present.
pub fn extract_sni(buf: &[u8]) -> Option<String> {
    // TLS record header: content_type(1) + version(2) + length(2) = 5 bytes
    if buf.len() < 5 {
        return None;
    }

    if buf[0] != TLS_CONTENT_HANDSHAKE {
        return None;
    }

    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let record_end = 5 + record_len;
    if buf.len() < record_end {
        return None;
    }

    let handshake = &buf[5..record_end];

    // Handshake header: type(1) + length(3) = 4 bytes
    if handshake.len() < 4 {
        return None;
    }

    if handshake[0] != HANDSHAKE_CLIENT_HELLO {
        return None;
    }

    let handshake_len =
        ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | (handshake[3] as usize);
    let hello = &handshake[4..];
    if hello.len() < handshake_len {
        return None;
    }
    let hello = &hello[..handshake_len];

    // ClientHello: version(2) + random(32) = 34 bytes minimum
    if hello.len() < 34 {
        return None;
    }
    let mut pos = 34;

    // Session ID: length(1) + data
    if pos >= hello.len() {
        return None;
    }
    let session_id_len = hello[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher suites: length(2) + data
    if pos + 2 > hello.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    // Compression methods: length(1) + data
    if pos >= hello.len() {
        return None;
    }
    let compression_len = hello[pos] as usize;
    pos += 1 + compression_len;

    // Extensions: length(2) + data
    if pos + 2 > hello.len() {
        return None;
    }
    let extensions_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = pos + extensions_len;
    if extensions_end > hello.len() {
        return None;
    }

    // Walk extensions
    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
        let ext_len = u16::from_be_bytes([hello[pos + 2], hello[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > extensions_end {
            return None;
        }

        if ext_type == EXT_SERVER_NAME {
            return parse_sni_extension(&hello[pos..pos + ext_len]);
        }

        pos += ext_len;
    }

    None
}

/// Parses the SNI extension data to extract the server name.
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    // ServerNameList: length(2) + entries
    if data.len() < 2 {
        return None;
    }

    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return None;
    }

    let mut pos = 2;
    let list_end = 2 + list_len;

    while pos + 3 <= list_end {
        let name_type = data[pos];
        let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
        pos += 3;

        if pos + name_len > list_end {
            return None;
        }

        if name_type == SNI_HOST_NAME {
            return std::str::from_utf8(&data[pos..pos + name_len])
                .ok()
                .map(|s| s.to_string());
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

    /// Builds a minimal TLS ClientHello with a single SNI extension.
    fn build_client_hello(sni: &str) -> Vec<u8> {
        let name_bytes = sni.as_bytes();

        // SNI extension data:
        // ServerNameList length(2) + entry: type(1) + name_length(2) + name
        let sni_entry_len = 1 + 2 + name_bytes.len();
        let sni_list_len = sni_entry_len;
        let mut sni_ext_data = Vec::new();
        sni_ext_data.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        sni_ext_data.push(SNI_HOST_NAME);
        sni_ext_data.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        sni_ext_data.extend_from_slice(name_bytes);

        // Extensions block: type(2) + length(2) + data
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
        extensions.extend_from_slice(&(sni_ext_data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext_data);

        // ClientHello body:
        // version(2) + random(32) + session_id_len(1) + cipher_suites_len(2) +
        // cipher_suite(2) + compression_len(1) + compression(1) + extensions_len(2) + extensions
        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        hello.extend_from_slice(&[0u8; 32]); // random
        hello.push(0); // session ID length
        hello.extend_from_slice(&2u16.to_be_bytes()); // cipher suites length
        hello.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        hello.push(1); // compression methods length
        hello.push(0); // null compression
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        // Handshake header: type(1) + length(3)
        let mut handshake = Vec::new();
        handshake.push(HANDSHAKE_CLIENT_HELLO);
        let hello_len = hello.len();
        handshake.push((hello_len >> 16) as u8);
        handshake.push((hello_len >> 8) as u8);
        handshake.push(hello_len as u8);
        handshake.extend_from_slice(&hello);

        // TLS record header: content_type(1) + version(2) + length(2)
        let mut record = Vec::new();
        record.push(TLS_CONTENT_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        record
    }

    #[test]
    fn test_extract_sni_valid() {
        let data = build_client_hello("api.openai.com");
        assert_eq!(extract_sni(&data), Some("api.openai.com".to_string()));
    }

    #[test]
    fn test_extract_sni_different_domain() {
        let data = build_client_hello("example.com");
        assert_eq!(extract_sni(&data), Some("example.com".to_string()));
    }

    #[test]
    fn test_extract_sni_non_tls() {
        let data = b"GET / HTTP/1.1\r\n\r\n";
        assert_eq!(extract_sni(data), None);
    }

    #[test]
    fn test_extract_sni_truncated() {
        let data = build_client_hello("example.com");
        // Truncate at various points
        assert_eq!(extract_sni(&data[..3]), None);
        assert_eq!(extract_sni(&data[..5]), None);
        assert_eq!(extract_sni(&data[..10]), None);
    }

    #[test]
    fn test_extract_sni_empty() {
        assert_eq!(extract_sni(&[]), None);
    }

    #[test]
    fn test_extract_sni_no_extensions() {
        // Build a ClientHello without extensions
        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]); // version
        hello.extend_from_slice(&[0u8; 32]); // random
        hello.push(0); // session ID length
        hello.extend_from_slice(&2u16.to_be_bytes()); // cipher suites length
        hello.extend_from_slice(&[0x13, 0x01]); // cipher suite
        hello.push(1); // compression methods length
        hello.push(0); // null compression
        // No extensions

        let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
        let len = hello.len();
        handshake.push((len >> 16) as u8);
        handshake.push((len >> 8) as u8);
        handshake.push(len as u8);
        handshake.extend_from_slice(&hello);

        let mut record = vec![TLS_CONTENT_HANDSHAKE, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        assert_eq!(extract_sni(&record), None);
    }
}
