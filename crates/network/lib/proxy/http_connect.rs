//! HTTP CONNECT outbound proxy builders and transport.

use std::net::AddrParseError;
#[cfg(feature = "engine")]
use std::{io, net::SocketAddr, time::Duration};

#[cfg(feature = "engine")]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use super::types::{
    OutboundProxy, OutboundProxyBuildError, OutboundProxyConfig, OutboundProxyProtocol,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "engine")]
const CONNECT_RESPONSE_HEADER_LIMIT: usize = 8192;
#[cfg(feature = "engine")]
const CONNECT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Builds an HTTP CONNECT outbound proxy.
#[derive(Debug, Clone)]
pub struct HttpConnectProxyBuilder {
    address: String,
}

/// HTTP CONNECT wire protocol operations.
#[cfg(feature = "engine")]
pub(super) struct HttpConnectProtocol;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl HttpConnectProxyBuilder {
    /// Creates a builder for the configured proxy address.
    pub(super) fn new(address: impl Into<String>) -> Self {
        Self {
            address: address.into(),
        }
    }
}

#[cfg(feature = "engine")]
impl HttpConnectProtocol {
    /// Opens a TCP tunnel through the configured HTTP proxy.
    pub(super) async fn connect(
        address: SocketAddr,
        destination: SocketAddr,
    ) -> io::Result<TcpStream> {
        let mut stream = TcpStream::connect(address).await?;
        let authority = destination.to_string();
        let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");

        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;

        let status = timeout(
            CONNECT_RESPONSE_TIMEOUT,
            Self::read_connect_response_status(&mut stream),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP CONNECT proxy did not complete its response headers within 10 seconds",
            )
        })??;

        if (200..300).contains(&status) {
            return Ok(stream);
        }

        let kind = if status == 407 {
            io::ErrorKind::PermissionDenied
        } else {
            io::ErrorKind::ConnectionRefused
        };

        Err(io::Error::new(
            kind,
            format!("HTTP CONNECT proxy rejected the tunnel with status {status}"),
        ))
    }

    async fn read_connect_response_status(stream: &mut TcpStream) -> io::Result<u16> {
        let mut total_header_bytes = 0;

        loop {
            let mut header = Vec::with_capacity(256);
            loop {
                if total_header_bytes >= CONNECT_RESPONSE_HEADER_LIMIT {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "HTTP CONNECT proxy response headers exceeded 8192 bytes",
                    ));
                }

                header.push(stream.read_u8().await?);
                total_header_bytes += 1;
                if header.ends_with(b"\r\n\r\n") {
                    break;
                }
            }

            let status_end = header
                .windows(2)
                .position(|window| window == b"\r\n")
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "HTTP CONNECT proxy returned an invalid status line",
                    )
                })?;
            let status = Self::parse_status_line(&header[..status_end])?;

            if (100..200).contains(&status) && status != 101 {
                continue;
            }

            return Ok(status);
        }
    }

    /// Parses an HTTP/1.x status line and returns its status code.
    ///
    /// Fields are split on ASCII whitespace, so leading whitespace is tolerated
    /// and one or more SP/HTAB separators are accepted. The version token must be
    /// exactly `HTTP/1.0` or `HTTP/1.1` and the status code must be exactly three
    /// ASCII digits; a trailing separator after the code is optional. The reason
    /// phrase is ignored and may contain spaces, tabs, and valid-UTF-8 non-ASCII
    /// text, but every control byte other than HTAB is rejected anywhere in the
    /// line and the line must be valid UTF-8.
    fn parse_status_line(status_line: &[u8]) -> io::Result<u16> {
        if status_line
            .iter()
            .any(|b| b.is_ascii_control() && *b != b'\t')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP CONNECT proxy returned a status line containing control characters",
            ));
        }
        let status_line = std::str::from_utf8(status_line).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP CONNECT proxy returned a non-ASCII status line",
            )
        })?;
        let mut fields = status_line.split_ascii_whitespace();
        let version = fields.next().unwrap_or_default();
        if version != "HTTP/1.0" && version != "HTTP/1.1" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP CONNECT proxy returned an invalid HTTP status line",
            ));
        }
        let status = fields.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP CONNECT proxy returned a status line without a status code",
            )
        })?;
        if status.len() != 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP CONNECT proxy returned a status code that is not three digits",
            ));
        }
        if !status.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP CONNECT proxy returned a status code containing non-digit characters",
            ));
        }
        status.parse::<u16>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP CONNECT proxy returned an invalid status code",
            )
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl OutboundProxyConfig for HttpConnectProxyBuilder {
    fn build(self) -> Result<OutboundProxy, OutboundProxyBuildError> {
        let address = self.address.parse().map_err(|source: AddrParseError| {
            OutboundProxyBuildError::InvalidAddress {
                protocol: OutboundProxyProtocol::HttpConnect,
                address: self.address,
                source,
            }
        })?;

        Ok(OutboundProxy::HttpConnect { address })
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, feature = "engine"))]
mod tests {
    use std::{future::Future, io, net::SocketAddr, time::Duration};

    use futures::FutureExt;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::oneshot,
        task::JoinHandle,
        time::{Instant, timeout},
    };

    use super::{CONNECT_RESPONSE_HEADER_LIMIT, CONNECT_RESPONSE_TIMEOUT, HttpConnectProtocol};

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    // Exact rejection diagnostics, one per rejection class.
    const CONTROL: &str = "HTTP CONNECT proxy returned a status line containing control characters";
    const NON_ASCII: &str = "HTTP CONNECT proxy returned a non-ASCII status line";
    const INVALID_LINE: &str = "HTTP CONNECT proxy returned an invalid HTTP status line";
    const NO_CODE: &str = "HTTP CONNECT proxy returned a status line without a status code";
    const CODE_LENGTH: &str = "HTTP CONNECT proxy returned a status code that is not three digits";
    const CODE_DIGITS: &str =
        "HTTP CONNECT proxy returned a status code containing non-digit characters";

    #[tokio::test]
    async fn connect_rejects_malformed_status_lines() {
        let cases: &[(&str, &[u8])] = &[
            ("signed", b"HTTP/1.1 +200 OK"),
            ("signed two-digit", b"HTTP/1.1 +20 OK"),
            ("signed two-digit 99", b"HTTP/1.1 +99 OK"),
            ("padded", b"HTTP/1.1 0200 OK"),
            ("short", b"HTTP/1.1 20 OK"),
            ("long", b"HTTP/1.1 2000 OK"),
            ("FF", b"HTTP/1.1\x0c200 OK"),
            ("VT", b"HTTP/1.1\x0b200 OK"),
            ("bare CR", b"HTTP/1.1\r200 OK"),
            ("NUL", b"HTTP/1.1 200 O\0K"),
            ("DEL", b"HTTP/1.1 200 O\x7fK"),
            ("bare LF", b"HTTP/1.1 200 O\nK"),
            ("trailing CR", b"HTTP/1.1 200 OK\r"),
            ("HTTP/2", b"HTTP/2 200 OK"),
            ("HTTP/1.2", b"HTTP/1.2 200 OK"),
            ("lowercase", b"http/1.1 200 OK"),
            ("letter code", b"HTTP/1.1 2O0 OK"),
            ("joined reason", b"HTTP/1.1 200OK"),
            ("missing code", b"HTTP/1.1 OK"),
            ("NBSP", b"HTTP/1.1\xa0200 OK"),
            ("non-ASCII code", b"HTTP/1.1 2\xc30 OK"),
        ];
        // Collect failures so every regression is exercised in one run.
        let mut failures = Vec::new();

        for (label, line) in cases {
            let response = [*line, b"\r\n\r\n"].concat();
            let (result, request) = exchange(response, destination()).await;
            assert_eq!(
                request,
                expected_request(destination()),
                "{label}: {line:?}"
            );
            if !matches!(&result, Err(error) if error.kind() == io::ErrorKind::InvalidData) {
                failures.push(format!("{label}: {line:?}: {result:?}"));
            }
        }

        assert!(failures.is_empty(), "{}", failures.join("\n"));

        // Pin one exact diagnostic per rejection class on the wire.
        for (label, line, message) in [
            ("control byte", &b"HTTP/1.1 200 O\0K"[..], CONTROL),
            ("bad version", b"HTTP/2 200 OK", INVALID_LINE),
            ("missing code", b"HTTP/1.1", NO_CODE),
            ("wrong length", b"HTTP/1.1 +200 OK", CODE_LENGTH),
            ("non-digit", b"HTTP/1.1 2O0 OK", CODE_DIGITS),
            ("non-ASCII status line", b"HTTP/1.1 200 \xff", NON_ASCII),
        ] {
            let response = [line, b"\r\n\r\n"].concat();
            let (result, _) = exchange(response, destination()).await;
            let error = result.expect_err(label);
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{label}");
            assert_eq!(error.to_string(), message, "{label}");
        }
    }

    #[tokio::test]
    async fn connect_accepts_sp_htab_separator_runs() {
        for line in [
            &b"HTTP/1.1\t200 OK"[..],
            b"HTTP/1.1  200 OK",
            b"HTTP/1.1 \t 200\t\tOK",
            b"HTTP/1.1 204\t",
            b"HTTP/1.0 200 \tleading tab reason",
        ] {
            assert_success([line, b"\r\n\r\n"].concat(), &format!("{line:?}"), b"").await;
        }
    }

    #[tokio::test]
    async fn connect_accepts_utf8_non_ascii_reason_phrase() {
        for line in [
            "HTTP/1.1 200 café".as_bytes(),
            b"HTTP/1.1 200 \xc2\x85obs",
            "HTTP/1.0 201 résumé".as_bytes(),
        ] {
            let tail = b"\0\xfftail";
            assert_success(
                [line, b"\r\n\r\n", tail].concat(),
                &format!("{line:?}"),
                tail,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn connect_rejects_invalid_utf8_reason_phrase() {
        for (label, line) in [
            ("obs-text FF/80", &b"HTTP/1.1 200 \xff\x80"[..]),
            ("Latin-1 e9", b"HTTP/1.0 201 \xe9t\xe9"),
        ] {
            let response = [line, b"\r\n\r\n"].concat();
            let (result, request) = exchange(response, destination()).await;
            assert_eq!(request, expected_request(destination()), "{label}");
            let error = result.expect_err(label);
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{label}");
            assert_eq!(error.to_string(), NON_ASCII, "{label}: {line:?}");
        }
    }

    #[tokio::test]
    async fn connect_waits_for_final_response_after_interim_headers() {
        let tail = b"\0\xffinterim tail";
        let cases: &[(&str, &[u8], &str, u16)] = &[
            (
                "100 then 200",
                b"HTTP/1.1 100 Continue\r\n\r\n",
                "HTTP/1.1",
                200,
            ),
            (
                "103 then 201",
                b"HTTP/1.1 103 Early Hints\r\n\r\n",
                "HTTP/1.1",
                201,
            ),
            (
                "100 then 103 then 299",
                b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\n\r\n",
                "HTTP/1.0",
                299,
            ),
            (
                "HTAB interim",
                b"HTTP/1.1\t103\tEarly Hints\r\n\r\n",
                "HTTP/1.1",
                200,
            ),
        ];

        for (label, interim, version, status) in cases {
            let final_header = format!("{version} {status} OK\r\n\r\n");
            assert_success(
                [*interim, final_header.as_bytes(), tail].concat(),
                &format!("{label}: {interim:?}"),
                tail,
            )
            .await;
        }
        let prefix = b"HTTP/1.1 103 Early Hints\r\n\r\n";
        let error = assert_error(
            [prefix.as_slice(), b"HTTP/1.1 503 Unavailable\r\n\r\n"].concat(),
            "103 then 503",
            io::ErrorKind::ConnectionRefused,
        )
        .await;
        assert_eq!(
            error.to_string(),
            "HTTP CONNECT proxy rejected the tunnel with status 503",
            "103 then 503"
        );
        assert_error(
            [prefix.as_slice(), b"HTTP/1.1 +200 OK\r\n\r\n"].concat(),
            "malformed final after 103",
            io::ErrorKind::InvalidData,
        )
        .await;
        assert_error(
            b"HTTP/1.1 +100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\n".to_vec(),
            "malformed interim",
            io::ErrorKind::InvalidData,
        )
        .await;
    }

    #[test]
    fn status_line_accepts_rfc_aligned_framing() {
        for version in ["HTTP/1.0", "HTTP/1.1"] {
            for status in [0, 100, 101, 103, 199, 200, 201, 204, 299, 407, 503, 999] {
                for separator in [" ", "\t", "  ", " \t "] {
                    for reason in [
                        &b"OK"[..],
                        b"Connection Established",
                        b"",
                        b"OK ",
                        b"A\tB",
                        "café".as_bytes(),
                        b"\xc2\x85",
                    ] {
                        let mut line =
                            format!("{version}{separator}{status:03}{separator}").into_bytes();
                        line.extend_from_slice(reason);
                        assert_eq!(
                            HttpConnectProtocol::parse_status_line(&line)
                                .map_err(|error| error.kind()),
                            Ok(status),
                            "{line:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn status_line_accepts_mixed_separator_runs() {
        // A different SP/HTAB run in each separator position must be accepted;
        // these also fail if the second separator is required to match the first.
        for (line, status) in [
            (&b"HTTP/1.1 \t 407  Proxy Auth "[..], 407),
            (b"HTTP/1.1\t407  Proxy Auth ", 407),
            (b"HTTP/1.1 \t200 OK", 200),
            (b"HTTP/1.1\t\t200  OK", 200),
            (b"HTTP/1.0 204\t", 204),
            // No trailing separator after the code is required.
            (b"HTTP/1.1 200", 200),
            (b"HTTP/1.0 204", 204),
            // Leading whitespace is tolerated by ASCII-whitespace splitting.
            (b" HTTP/1.1 200 OK", 200),
            (b"\tHTTP/1.1\t200\tOK", 200),
        ] {
            assert_eq!(
                HttpConnectProtocol::parse_status_line(line).map_err(|error| error.kind()),
                Ok(status),
                "{line:?}"
            );
        }
    }

    #[test]
    fn status_line_rejects_malformed_framing() {
        for line in [
            &b""[..],
            b"HTTP/",
            b"HTTP/1.1",
            b"HTTP/1.1 ",
            b"HTTP/1.1  ",
            b"HTTP/2 200 OK",
            b"HTTP/2.0 200 OK",
            b"HTTP/1.2 200 OK",
            b"HTTP/1.10 200 OK",
            b"http/1.1 200 OK",
            b"Http/1.1 200 OK",
            b"HTTP/1.1200 OK",
            b"HTTP/1.1 200OK",
            b"HTTP/1.1 +200 OK",
            b"HTTP/1.1 +20 OK",
            b"HTTP/1.1 +99 OK",
            b"HTTP/1.1 -200 OK",
            b"HTTP/1.1 0200 OK",
            b"HTTP/1.1 2O0 OK",
            b"HTTP/1.1 20 OK",
            b"HTTP/1.1 20",
            b"HTTP/1.1 2000 OK",
            b"HTTP/1.1 OK",
            "HTTP/1.1 ٢٠٠ OK".as_bytes(),
            b"HTTP/1.1\xa0200 OK",
            b"HTTP/1.1\x0c200 OK",
            b"HTTP/1.1\x0b200 OK",
            b"HTTP/1.1\r200 OK",
            b"HTTP/1.1 200 OK\r",
            b"HTTP/1.1 200 O\nK",
        ] {
            assert_eq!(
                HttpConnectProtocol::parse_status_line(line).map_err(|error| error.kind()),
                Err(io::ErrorKind::InvalidData),
                "{line:?}"
            );
        }

        // Pin one exact diagnostic per rejection class so a message swap cannot survive.
        for (line, message) in [
            (&b"HTTP/1.1 200 O\0K"[..], CONTROL),
            (b"HTTP/2 200 OK", INVALID_LINE),
            (b"HTTP/1.1", NO_CODE),
            (b"HTTP/1.1 +200 OK", CODE_LENGTH),
            (b"HTTP/1.1 2O0 OK", CODE_DIGITS),
            (b"HTTP/1.1 200 \xff", NON_ASCII),
        ] {
            assert_eq!(
                HttpConnectProtocol::parse_status_line(line)
                    .unwrap_err()
                    .to_string(),
                message,
                "{line:?}"
            );
        }
    }

    #[test]
    fn status_line_byte_class_sweep() {
        for byte in 0..=u8::MAX {
            // The oracle is the grammar's explicit byte ranges, not the parser's predicates.
            let digit = b"0123456789".iter().position(|&digit| byte == digit);
            let control = byte.is_ascii_control() && byte != b'\t';
            let non_ascii = byte >= 0x80;
            let mut cases: Vec<(&str, Vec<u8>, Result<u16, String>)> = vec![
                (
                    "reason",
                    [b"HTTP/1.1 200 A".as_slice(), &[byte], b"B"].concat(),
                    if matches!(byte, 0x09 | 0x20..=0x7e) {
                        Ok(200)
                    } else if control {
                        Err(CONTROL.to_string())
                    } else {
                        Err(NON_ASCII.to_string())
                    },
                ),
                (
                    "version separator",
                    [b"HTTP/1.1".as_slice(), &[byte], b"200 OK"].concat(),
                    if matches!(byte, 0x09 | 0x20) {
                        Ok(200)
                    } else if control {
                        Err(CONTROL.to_string())
                    } else if non_ascii {
                        Err(NON_ASCII.to_string())
                    } else {
                        Err(INVALID_LINE.to_string())
                    },
                ),
                (
                    "reason separator",
                    [b"HTTP/1.1 200".as_slice(), &[byte], b"OK"].concat(),
                    if matches!(byte, 0x09 | 0x20) {
                        Ok(200)
                    } else if control {
                        Err(CONTROL.to_string())
                    } else if non_ascii {
                        Err(NON_ASCII.to_string())
                    } else {
                        Err(CODE_LENGTH.to_string())
                    },
                ),
                (
                    "version digit",
                    [b"HTTP/1.".as_slice(), &[byte], b" 200 OK"].concat(),
                    if matches!(byte, b'0' | b'1') {
                        Ok(200)
                    } else if control {
                        Err(CONTROL.to_string())
                    } else if non_ascii {
                        Err(NON_ASCII.to_string())
                    } else {
                        Err(INVALID_LINE.to_string())
                    },
                ),
            ];
            // Sweep each of the three code digits independently so a sign or a
            // non-ASCII digit in any position is rejected, not just the middle one.
            for (position, weight) in [(0usize, 100u16), (1, 10), (2, 1)] {
                let mut code = *b"000";
                code[position] = byte;
                cases.push((
                    "code digit",
                    [b"HTTP/1.1 ".as_slice(), code.as_slice(), b" OK"].concat(),
                    if let Some(digit) = digit {
                        Ok(weight * digit as u16)
                    } else if control {
                        Err(CONTROL.to_string())
                    } else if non_ascii {
                        Err(NON_ASCII.to_string())
                    } else if matches!(byte, 0x09 | 0x20) {
                        Err(CODE_LENGTH.to_string())
                    } else {
                        Err(CODE_DIGITS.to_string())
                    },
                ));
            }
            for (label, line, expected) in cases {
                assert_eq!(
                    HttpConnectProtocol::parse_status_line(&line)
                        .map_err(|error| error.to_string()),
                    expected,
                    "{label}: {line:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn connect_accepts_all_2xx_statuses() {
        for (index, status) in [200, 201, 204, 299].into_iter().enumerate() {
            let version = if index % 2 == 0 {
                "HTTP/1.0"
            } else {
                "HTTP/1.1"
            };
            let reason = if status == 204 { "" } else { "OK" };
            let response = format!("{version} {status} {reason}\r\n\r\n");
            assert_success(response.into_bytes(), &format!("status {status}"), b"").await;
        }
    }

    #[tokio::test]
    async fn connect_rejects_non_2xx_statuses() {
        // Expected kinds are an independent oracle, not re-derived from production.
        for (status, kind) in [
            (101, io::ErrorKind::ConnectionRefused),
            (300, io::ErrorKind::ConnectionRefused),
            (403, io::ErrorKind::ConnectionRefused),
            (407, io::ErrorKind::PermissionDenied),
            (503, io::ErrorKind::ConnectionRefused),
            (0, io::ErrorKind::ConnectionRefused),
            (999, io::ErrorKind::ConnectionRefused),
        ] {
            let response = format!("HTTP/1.1 {status:03} Rejected\r\n\r\n");
            let (result, request) = exchange(response.into_bytes(), destination()).await;
            assert_eq!(request, expected_request(destination()), "status {status}");
            let error = result.unwrap_err();
            assert_eq!(error.kind(), kind, "status {status}");
            assert_eq!(
                error.to_string(),
                format!("HTTP CONNECT proxy rejected the tunnel with status {status}"),
                "status {status}"
            );
        }
    }

    #[tokio::test]
    async fn connect_sends_canonical_ipv6_authority() {
        let destination = "[2001:db8::9]:443".parse().unwrap();
        let (result, request) = exchange(b"HTTP/1.1 200 OK\r\n\r\n".to_vec(), destination).await;
        result.unwrap();
        assert_eq!(
            request,
            b"CONNECT [2001:db8::9]:443 HTTP/1.1\r\nHost: [2001:db8::9]:443\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn connect_enforces_response_header_limit() {
        assert_eq!(CONNECT_RESPONSE_HEADER_LIMIT, 8192);
        for len in [8191, 8192] {
            assert_success(
                response_headers_with_len(b"HTTP/1.1 200 OK", len),
                &format!("length {len}"),
                b"",
            )
            .await;
        }
        let oversized = response_headers_with_len(b"HTTP/1.1 200 OK", 8193);
        let (result, request) = exchange(oversized, destination()).await;
        assert_eq!(request, expected_request(destination()));
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "HTTP CONNECT proxy response headers exceeded 8192 bytes"
        );

        for (len, kind) in [
            (8192, io::ErrorKind::InvalidData),
            (8191, io::ErrorKind::UnexpectedEof),
        ] {
            let mut response = b"HTTP/1.1 200 OK\r\nX-Pad: ".to_vec();
            response.resize(len, b'a');
            assert_eq!(response.len(), len, "unterminated length {len}");
            assert_error(response, &format!("unterminated length {len}"), kind).await;
        }

        let tail = b"\0\xfflimit\r\n\r\n";
        let mut response = response_headers_with_len(b"HTTP/1.1 200 OK", 8192);
        response.extend_from_slice(tail);
        assert_success(response, "exact limit with tail", tail).await;
    }

    #[tokio::test]
    async fn connect_counts_interim_headers_toward_total_limit() {
        for (len, accepted) in [(4096, true), (4097, false)] {
            let mut response = response_headers_with_len(b"HTTP/1.1 103 Early Hints", 4096);
            response.extend(response_headers_with_len(b"HTTP/1.1 200 OK", len));
            if accepted {
                assert_success(response, "4096 + 4096", b"").await;
            } else {
                assert_error(response, "4096 + 4097", io::ErrorKind::InvalidData).await;
            }
        }
    }

    #[tokio::test]
    async fn connect_rejects_early_eof() {
        for response in [
            &b""[..],
            b"HTTP/1.1 20",
            b"HTTP/1.1 200 OK\r\nX-Test: value\r\n",
            b"HTTP/1.1 103 Early Hints\r\n\r\n",
        ] {
            assert_error(
                response.to_vec(),
                &format!("{response:?}"),
                io::ErrorKind::UnexpectedEof,
            )
            .await;
        }
        assert_success(
            b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
            "complete before EOF",
            b"",
        )
        .await;
    }

    #[tokio::test]
    async fn connect_rejects_101_without_waiting_for_another_response() {
        let (listener, address, request_tx, request_rx) = bind_mock_proxy().await;
        let (release_tx, release_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut stream = accept_and_capture(listener, request_tx).await;
            bounded(stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\n"))
                .await
                .unwrap();
            bounded(release_rx).await.unwrap();
        });

        let result = bounded(HttpConnectProtocol::connect(address, destination())).await;

        let request = bounded(request_rx).await.unwrap();
        release_tx.send(()).unwrap();
        join_proxy(task).await;

        assert_eq!(request, expected_request(destination()));
        let error = result.expect_err("101 must be terminal while proxy stays open");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(
            error.to_string(),
            "HTTP CONNECT proxy rejected the tunnel with status 101"
        );
    }

    #[tokio::test]
    async fn connect_preserves_tunnel_bytes_and_supports_bidirectional_io() {
        let (listener, address, request_tx, request_rx) = bind_mock_proxy().await;
        let tail = b"\0\xffearly\r\n\r\ndata";
        let task = tokio::spawn(async move {
            let mut stream = accept_and_capture(listener, request_tx).await;
            let response = [b"HTTP/1.1 201 Created\r\n\r\n".as_slice(), tail].concat();
            bounded(stream.write_all(&response)).await.unwrap();
            let mut ping = [0; 4];
            bounded(stream.read_exact(&mut ping)).await.unwrap();
            assert_eq!(&ping, b"ping");
            bounded(stream.write_all(b"pong")).await.unwrap();
        });

        let mut stream = bounded(HttpConnectProtocol::connect(address, destination()))
            .await
            .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), address);
        assert_eq!(
            bounded(request_rx).await.unwrap(),
            expected_request(destination())
        );
        let mut received = vec![0; tail.len()];
        bounded(stream.read_exact(&mut received)).await.unwrap();
        assert_eq!(received, tail);
        bounded(stream.write_all(b"ping")).await.unwrap();
        let mut pong = [0; 4];
        bounded(stream.read_exact(&mut pong)).await.unwrap();
        assert_eq!(&pong, b"pong");
        join_proxy(task).await;
    }

    #[tokio::test]
    async fn connect_waits_for_all_fragments_and_preserves_tail() {
        // Each server phase is released with an explicit ack, so this proves the
        // handshake does not complete before the last fragment arrives and that
        // bytes queued after the terminator are preserved. Polling the handshake
        // once per phase does not prove it consumed fragment k before k + 1 was
        // written (bytes may still be in flight), so it is not an incremental
        // parsing proof.
        let cases: &[(&str, &[&[u8]])] = &[
            ("status code", &[b"HTTP/1.1 2", b"00 OK\r\n", b"\r", b"\n"]),
            (
                "UTF-8 reason",
                &[b"HTTP/1.1 200 caf\xc3", b"\xa9\r", b"\n\r", b"\n"],
            ),
        ];
        for (label, fragments) in cases {
            let label = format!("{label}: {fragments:?}");
            let (listener, address, request_tx, request_rx) = bind_mock_proxy().await;
            let tail = b"\0\xfffragmented tail";
            let fragments: Vec<Vec<u8>> =
                fragments.iter().map(|fragment| fragment.to_vec()).collect();
            let mut phases = Vec::new();
            let mut server_phases = Vec::new();
            for _ in &fragments {
                let (written_tx, written_rx) = oneshot::channel();
                let (ack_tx, ack_rx) = oneshot::channel();
                phases.push((written_rx, ack_tx));
                server_phases.push((written_tx, ack_rx));
            }
            let task = tokio::spawn(async move {
                let mut stream = accept_and_capture(listener, request_tx).await;
                let last = fragments.len() - 1;
                for (index, (mut fragment, (written_tx, ack_rx))) in
                    fragments.into_iter().zip(server_phases).enumerate()
                {
                    if index == last {
                        fragment.extend_from_slice(tail);
                    }
                    bounded(stream.write_all(&fragment)).await.unwrap();
                    written_tx.send(()).unwrap();
                    bounded(ack_rx).await.unwrap();
                }
            });

            let mut handshake = Box::pin(HttpConnectProtocol::connect(address, destination()));

            let request = tokio::select! {
                biased;
                result = &mut handshake => panic!("{label}: completed before fragments: {result:?}"),
                captured = bounded(request_rx) => captured.unwrap(),
            };
            assert_eq!(request, expected_request(destination()), "{label}");
            let last = phases.len() - 1;
            for (index, (written_rx, ack_tx)) in phases.into_iter().enumerate() {
                // Await the server phase without awaiting a pending handshake: no implicit sleeps.
                bounded(written_rx).await.unwrap();
                if index < last {
                    assert!(
                        futures::poll!(&mut handshake).is_pending(),
                        "{label}: fragment {index}"
                    );
                }
                ack_tx.send(()).unwrap();
            }
            let mut stream = bounded(&mut handshake).await.unwrap();
            assert_eq!(stream.peer_addr().unwrap(), address, "{label}");
            let mut received = vec![0; tail.len()];
            bounded(stream.read_exact(&mut received)).await.unwrap();
            assert_eq!(received, tail, "{label}");
            join_proxy(task).await;
        }
    }

    #[tokio::test]
    async fn connect_times_out_stalled_response() {
        assert_eq!(CONNECT_RESPONSE_TIMEOUT, Duration::from_secs(10));
        for (label, response) in [
            ("no bytes", &b""[..]),
            ("partial final", b"HTTP/1.1 200 OK\r\nX-Test: partial"),
            ("interim then stall", b"HTTP/1.1 103 Early Hints\r\n\r\n"),
        ] {
            let (address, request_rx, written_rx, task) =
                spawn_stalled_proxy(response.to_vec()).await;
            let started = Instant::now();
            let mut handshake = Box::pin(HttpConnectProtocol::connect(address, destination()));

            let request = tokio::select! {
                biased;
                result = &mut handshake => panic!("{label}: stalled proxy completed early: {result:?}"),
                captured = bounded(request_rx) => captured.unwrap(),
            };
            assert_eq!(request, expected_request(destination()), "{label}");
            tokio::select! {
                biased;
                result = &mut handshake => panic!("{label}: stalled proxy completed early: {result:?}"),
                written = bounded(written_rx) => written.unwrap(),
            }
            assert!(futures::poll!(&mut handshake).is_pending(), "{label}");

            // On macOS, advancing virtual time can outrun socket readiness for the
            // written variants: closing with unread bytes produces a reset instead of EOF.
            // Use the plan's real-clock fallback, retaining the production 10s deadline.
            let outcome = timeout(Duration::from_secs(15), &mut handshake).await;
            let error = outcome
                .expect("response deadline was not enforced")
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{label}");
            let elapsed = Instant::now().duration_since(started);
            assert!(
                elapsed >= CONNECT_RESPONSE_TIMEOUT,
                "{label}: expired early"
            );
            assert!(elapsed < Duration::from_secs(15), "{label}: expired late");
            join_proxy(task).await;
        }
    }

    #[tokio::test]
    async fn cancelling_connect_closes_proxy_socket() {
        let (address, request_rx, written_rx, task) = spawn_stalled_proxy(Vec::new()).await;
        let handshake = tokio::spawn(HttpConnectProtocol::connect(address, destination()));

        let request = bounded(request_rx).await.unwrap();
        assert_eq!(request, expected_request(destination()));
        bounded(written_rx).await.unwrap();

        handshake.abort();
        let error = bounded(handshake).await.unwrap_err();
        assert!(error.is_cancelled());
        // The proxy must observe EOF, not be aborted to hide a leaked client socket.
        join_proxy(task).await;
    }

    #[tokio::test]
    async fn injected_authorities_are_rejected_before_proxy_contact() {
        for raw in [
            "203.0.113.9:443\r\nX-Injected: yes",
            "203.0.113.9:443\r",
            "203.0.113.9:443\n",
            "203.0.113.9 :443",
            "203.0.113.9:4\t43",
            " 203.0.113.9:443",
            "203.0.113.9:443 ",
            "[2001:db8::9]:443\r\nHost: evil",
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_address = listener.local_addr().unwrap();

            // SocketAddr cannot represent these authorities. InvalidInput is synthesized
            // by this test adapter at construction, not returned by connect.
            let result = bounded(async {
                let destination = raw.parse::<SocketAddr>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid CONNECT destination")
                })?;
                HttpConnectProtocol::connect(proxy_address, destination).await
            })
            .await;

            assert_eq!(
                result.unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "{raw:?}"
            );
            assert!(
                listener.accept().now_or_never().is_none(),
                "{raw:?} contacted the proxy"
            );
        }
    }

    async fn assert_success(response: Vec<u8>, label: &str, tail: &[u8]) {
        let (result, request) = exchange(response, destination()).await;

        assert_eq!(request, expected_request(destination()), "{label}");
        let mut stream = result.unwrap_or_else(|error| panic!("{label}: {error}"));
        let mut received = vec![0; tail.len()];
        bounded(stream.read_exact(&mut received)).await.unwrap();
        assert_eq!(received, tail, "{label}");
    }

    async fn assert_error(response: Vec<u8>, label: &str, kind: io::ErrorKind) -> io::Error {
        let (result, request) = exchange(response, destination()).await;

        assert_eq!(request, expected_request(destination()), "{label}");
        let error = result.expect_err(label);
        assert_eq!(error.kind(), kind, "{label}: {error}");
        error
    }

    async fn exchange(
        response: Vec<u8>,
        destination: SocketAddr,
    ) -> (io::Result<TcpStream>, Vec<u8>) {
        let (address, request_rx, task) = spawn_mock_proxy(response).await;
        let result = bounded(HttpConnectProtocol::connect(address, destination)).await;

        let request = bounded(request_rx).await.expect("request capture stalled");
        join_proxy(task).await;
        if let Ok(stream) = &result {
            assert_eq!(stream.peer_addr().unwrap(), address);
        }
        (result, request)
    }

    async fn spawn_mock_proxy(
        response: Vec<u8>,
    ) -> (SocketAddr, oneshot::Receiver<Vec<u8>>, JoinHandle<()>) {
        let (listener, address, request_tx, request_rx) = bind_mock_proxy().await;
        let task = tokio::spawn(async move {
            let mut stream = accept_and_capture(listener, request_tx).await;
            bounded(stream.write_all(&response))
                .await
                .expect("proxy response write stalled");
            // Returning drops the stream, producing EOF for empty/truncated responses.
        });
        (address, request_rx, task)
    }

    async fn spawn_stalled_proxy(
        response: Vec<u8>,
    ) -> (
        SocketAddr,
        oneshot::Receiver<Vec<u8>>,
        oneshot::Receiver<()>,
        JoinHandle<()>,
    ) {
        let (listener, address, request_tx, request_rx) = bind_mock_proxy().await;
        let (written_tx, written_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut stream = accept_and_capture(listener, request_tx).await;
            bounded(stream.write_all(&response)).await.unwrap();
            written_tx.send(()).unwrap();
            let mut byte = [0];
            // A 5s EOF watchdog would fire before the real 10s handshake deadline.
            // The caller bounds the fixture join after timeout or cancellation.
            assert_eq!(
                stream.read(&mut byte).await.unwrap(),
                0,
                "client did not close the proxy socket"
            );
        });
        (address, request_rx, written_rx, task)
    }

    async fn read_request_headers(stream: &mut TcpStream) -> Vec<u8> {
        bounded(async {
            let mut request = Vec::new();
            loop {
                assert!(request.len() < 8192, "unterminated CONNECT request");
                request.push(stream.read_u8().await.unwrap());
                if request.ends_with(b"\r\n\r\n") {
                    return request;
                }
            }
        })
        .await
    }

    fn response_headers_with_len(status_line: &[u8], total_len: usize) -> Vec<u8> {
        let mut response = status_line.to_vec();
        response.extend_from_slice(b"\r\nX-Pad: ");
        let fixed_len = response.len() + b"\r\n\r\n".len();
        assert!(total_len >= fixed_len);
        response.resize(response.len() + total_len - fixed_len, b'a');
        response.extend_from_slice(b"\r\n\r\n");
        assert_eq!(response.len(), total_len);
        response
    }

    fn expected_request(destination: SocketAddr) -> Vec<u8> {
        format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n\r\n").into_bytes()
    }

    fn destination() -> SocketAddr {
        "203.0.113.9:443".parse().unwrap()
    }

    async fn join_proxy(task: JoinHandle<()>) {
        bounded(task).await.expect("proxy fixture did not finish");
    }

    /// Awaits a fixture future under `TEST_TIMEOUT`, panicking if it stalls.
    async fn bounded<F: Future>(future: F) -> F::Output {
        timeout(TEST_TIMEOUT, future)
            .await
            .expect("operation did not complete before TEST_TIMEOUT")
    }

    /// Binds a loopback listener for a mock proxy and returns its address plus
    /// the channel used to capture the CONNECT request the client sends.
    async fn bind_mock_proxy() -> (
        TcpListener,
        SocketAddr,
        oneshot::Sender<Vec<u8>>,
        oneshot::Receiver<Vec<u8>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (request_tx, request_rx) = oneshot::channel();
        (listener, address, request_tx, request_rx)
    }

    /// Accepts one proxy connection and captures the client's CONNECT request.
    async fn accept_and_capture(
        listener: TcpListener,
        request_tx: oneshot::Sender<Vec<u8>>,
    ) -> TcpStream {
        let (mut stream, _) = bounded(listener.accept())
            .await
            .expect("proxy was not contacted");
        request_tx
            .send(read_request_headers(&mut stream).await)
            .unwrap();
        stream
    }

    // --- Independent verification additions (verifier) ---

    fn xorshift(state: &mut u64) -> u64 {
        let mut value = *state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        *state = value;
        value
    }

    /// Fuzz over the deterministic xorshift generator: the parser consumes
    /// untrusted bytes, so it must always return `Ok`/`Err` and never panic.
    #[test]
    fn parse_status_line_never_panics_on_arbitrary_bytes() {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let pool: &[u8] = b"HTTP/1.1HTTP/1.0200 \t+-OK\r\n";
        let extras: &[u8] = &[
            0x00, 0x08, 0x0a, 0x0b, 0x0c, 0x1f, 0x7f, 0x80, 0x85, 0xc3, 0xff, b'a', b'0', b'1',
            b'.', b'/',
        ];
        let seeds: &[&[u8]] = &[
            b"",
            b"HTTP/1.1 200 OK",
            b"HTTP/1.0 204 ",
            b"HTTP/1.1\t200 OK",
            b"HTTP/1.1  200 OK",
            b"HTTP/1.1 200",
            b"HTTP/1.1 +20 OK",
            b"HTTP/2 200 OK",
            b"HTTP/1.1 200 O\x00K",
            b"HTTP/1.1 \t 407  Proxy Auth ",
        ];
        for iteration in 0..200_000u64 {
            let mut line: Vec<u8> = match xorshift(&mut state) % 3 {
                0 => {
                    let len = (xorshift(&mut state) % 24) as usize;
                    (0..len)
                        .map(|_| {
                            if xorshift(&mut state).is_multiple_of(4) {
                                extras[(xorshift(&mut state) as usize) % extras.len()]
                            } else {
                                pool[(xorshift(&mut state) as usize) % pool.len()]
                            }
                        })
                        .collect()
                }
                _ => {
                    let mut line = seeds[(xorshift(&mut state) as usize) % seeds.len()].to_vec();
                    if !line.is_empty() {
                        for _ in 0..(xorshift(&mut state) % 4) {
                            let pos = (xorshift(&mut state) as usize) % line.len();
                            line[pos] = if xorshift(&mut state).is_multiple_of(2) {
                                extras[(xorshift(&mut state) as usize) % extras.len()]
                            } else {
                                pool[(xorshift(&mut state) as usize) % pool.len()]
                            };
                        }
                    }
                    match xorshift(&mut state) % 4 {
                        0 => line.push(extras[(xorshift(&mut state) as usize) % extras.len()]),
                        1 if line.len() > 1 => {
                            let keep = line.len() - ((xorshift(&mut state) as usize) % 3) - 1;
                            line.truncate(keep);
                        }
                        _ => {}
                    }
                    line
                }
            };
            if iteration % 7 == 0 {
                let mut prefixed = b"HTTP/1.1 200 OK".to_vec();
                prefixed.extend_from_slice(&line);
                line = prefixed;
            }
            match HttpConnectProtocol::parse_status_line(&line) {
                Ok(status) => assert!(status <= 999, "iteration {iteration}: {line:?}"),
                Err(error) => assert_eq!(
                    error.kind(),
                    io::ErrorKind::InvalidData,
                    "iteration {iteration}: {line:?}"
                ),
            }
        }
    }

    #[test]
    fn parse_status_line_boundary_cases() {
        // A wrong-length code and a non-digit code are reported distinctly.
        for bad in [
            &b"HTTP/1.1 +200 OK"[..],
            b"HTTP/1.1 -200 OK",
            b"HTTP/1.1 0200 OK",
            b"HTTP/1.1 20 OK",
            b"HTTP/1.1 20",
            b"HTTP/1.1 2000 OK",
            b"HTTP/1.1 200OK",
        ] {
            assert_eq!(
                HttpConnectProtocol::parse_status_line(bad).map_err(|error| error.to_string()),
                Err(CODE_LENGTH.to_string()),
                "{bad:?}"
            );
        }
        for bad in [&b"HTTP/1.1 +20 OK"[..], b"HTTP/1.1 2O0 OK"] {
            assert_eq!(
                HttpConnectProtocol::parse_status_line(bad).map_err(|error| error.to_string()),
                Err(CODE_DIGITS.to_string()),
                "{bad:?}"
            );
        }

        // Version token is exact and case-sensitive; HTTP/2 is rejected.
        for bad in [
            &b"HTTP/2 200 OK"[..],
            b"HTTP/2.0 200 OK",
            b"http/1.1 200 OK",
            b"Http/1.1 200 OK",
            b"HTTP/1.10 200 OK",
            b"HTTP/1.2 200 OK",
        ] {
            assert_eq!(
                HttpConnectProtocol::parse_status_line(bad).map_err(|error| error.to_string()),
                Err(INVALID_LINE.to_string()),
                "{bad:?}"
            );
        }

        // A missing code field is reported distinctly from a malformed one.
        for bad in [&b"HTTP/1.1"[..], b"HTTP/1.1 ", b"HTTP/1.1  "] {
            assert_eq!(
                HttpConnectProtocol::parse_status_line(bad).map_err(|error| error.to_string()),
                Err(NO_CODE.to_string()),
                "{bad:?}"
            );
        }

        // The trailing separator is optional, leading whitespace is tolerated,
        // and SP/HTAB runs are accepted in both separator positions.
        for (good, status) in [
            (&b"HTTP/1.1 200"[..], 200),
            (b"HTTP/1.1\t200", 200),
            (b" HTTP/1.1 200 OK", 200),
            (b"\tHTTP/1.1  200\tOK", 200),
            (b"HTTP/1.1\t200 OK", 200),
            (b"HTTP/1.1  200 OK", 200),
            (b"HTTP/1.1 \t 200 \t OK", 200),
            (b"HTTP/1.0 204 \t", 204),
            (b"HTTP/1.1 \t 407  Proxy Auth ", 407),
        ] {
            assert_eq!(
                HttpConnectProtocol::parse_status_line(good).map_err(|error| error.kind()),
                Ok(status),
                "{good:?}"
            );
        }

        // Every control byte other than HTAB is rejected, in the reason position.
        for byte in 0x00..=0x7fu8 {
            if byte.is_ascii_control() && byte != b'\t' {
                let line = [b"HTTP/1.1 200 A".as_slice(), &[byte], b"B"].concat();
                assert_eq!(
                    HttpConnectProtocol::parse_status_line(&line)
                        .map_err(|error| error.to_string()),
                    Err(CONTROL.to_string()),
                    "control {byte:#04x}"
                );
            }
        }

        // Valid-UTF-8 non-ASCII reasons are accepted; invalid UTF-8 is rejected.
        for good in [
            &b"HTTP/1.1 200 A\tB"[..],
            b"HTTP/1.1 200 \xc2\x85",
            "HTTP/1.1 200 café".as_bytes(),
        ] {
            assert!(
                HttpConnectProtocol::parse_status_line(good).is_ok(),
                "{good:?}"
            );
        }
        for bad in [&b"HTTP/1.1 200 \xff\x80"[..], b"HTTP/1.0 201 \xe9t\xe9"] {
            assert_eq!(
                HttpConnectProtocol::parse_status_line(bad).map_err(|error| error.to_string()),
                Err(NON_ASCII.to_string()),
                "{bad:?}"
            );
        }
    }
}
