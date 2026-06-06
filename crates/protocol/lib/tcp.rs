//! TCP stream protocol message payloads.

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Request to open a TCP connection from inside the guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpConnect {
    /// Destination host name or address as seen by the guest.
    pub host: String,

    /// Destination TCP port.
    pub port: u16,
}

/// Confirmation that a TCP connection was opened.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpConnected {}

/// TCP stream data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpData {
    /// The raw stream bytes.
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// Notification that one side has closed its write half.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpEof {}

/// Request to close the TCP session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpClose {}

/// Terminal notification that the TCP session is closed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpClosed {}

/// Terminal notification that the TCP session failed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFailed {
    /// Human-readable failure description.
    pub error: String,
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_payloads_roundtrip() {
        let connect = TcpConnect {
            host: "127.0.0.1".to_string(),
            port: 8080,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&connect, &mut buf).unwrap();
        let decoded: TcpConnect = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(decoded.host, connect.host);
        assert_eq!(decoded.port, connect.port);

        let data = TcpData {
            data: b"hello".to_vec(),
        };
        buf.clear();
        ciborium::into_writer(&data, &mut buf).unwrap();
        let decoded: TcpData = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(decoded.data, data.data);

        let failed = TcpFailed {
            error: "connection refused".to_string(),
        };
        buf.clear();
        ciborium::into_writer(&failed, &mut buf).unwrap();
        let decoded: TcpFailed = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(decoded.error, failed.error);
    }
}
