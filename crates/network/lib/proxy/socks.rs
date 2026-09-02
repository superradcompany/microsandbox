//! SOCKS outbound proxy builders, credentials, and transport implementations.

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use microsandbox_types::SecretSource;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks4Stream;
use zeroize::Zeroizing;

use super::types::{
    OutboundProxy, OutboundProxyBuildError, OutboundProxyBuilder, OutboundProxyConfig,
    OutboundProxyProtocol, ResolvedOutboundProxy,
};
use crate::dns::forwarder::{DnsForwarder, DnsForwarderHandle};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Environment-backed username/password credentials for a SOCKS5 proxy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Socks5Credentials {
    username: String,
    password: SecretSource,
}

/// Resolved SOCKS5 credentials held only by the network runtime.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedSocks5Credentials {
    username: String,
    password: Zeroizing<String>,
}

/// Builds a SOCKS4 outbound proxy.
#[derive(Debug, Clone)]
pub struct Socks4ProxyBuilder {
    address: String,
    user_id: Option<String>,
}

/// Builds a SOCKS5 outbound proxy.
#[derive(Debug, Clone)]
pub struct Socks5ProxyBuilder {
    address: String,
    credentials: Option<Socks5Credentials>,
}

/// Active SOCKS5 UDP association.
pub(crate) struct Socks5UdpAssociation {
    _control: TcpStream,
    socket: tokio::net::UdpSocket,
    dns_forwarder: Option<DnsForwarderHandle>,
}

/// SOCKS5 wire protocol operations shared by TCP and UDP proxying.
struct Socks5Protocol;

/// Address returned by a SOCKS5 command reply.
enum Socks5ReplyAddress {
    Socket(SocketAddr),
    Domain { name: String, port: u16 },
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ResolvedOutboundProxy {
    /// Builds the complete proxy used by the network runtime.
    #[doc(hidden)]
    pub fn build(
        configured: Option<&OutboundProxy>,
        resolved: Option<ResolvedSocks5Credentials>,
    ) -> Result<Option<Self>, OutboundProxyBuildError> {
        let Some(configured) = configured else {
            if resolved.is_some() {
                return Err(OutboundProxyBuildError::InvalidSocks5Credentials {
                    reason: "launch credentials require a configured SOCKS5 proxy",
                });
            }
            return Ok(None);
        };

        configured.validate()?;
        match configured {
            OutboundProxy::Socks4 { address, user_id } => {
                if resolved.is_some() {
                    return Err(OutboundProxyBuildError::InvalidSocks5Credentials {
                        reason: "launch credentials require a configured SOCKS5 proxy",
                    });
                }
                Ok(Some(Self::Socks4 {
                    address: *address,
                    user_id: user_id.clone(),
                }))
            }
            OutboundProxy::Socks5 {
                address,
                credentials,
            } => {
                let credentials = match (credentials, resolved) {
                    (None, None) => None,
                    (None, Some(_)) => {
                        return Err(OutboundProxyBuildError::InvalidSocks5Credentials {
                            reason: "launch credentials require configured SOCKS5 credentials",
                        });
                    }
                    (Some(_), None) => {
                        return Err(OutboundProxyBuildError::InvalidSocks5Credentials {
                            reason: "configured SOCKS5 credentials were not resolved at launch",
                        });
                    }
                    (Some(configured), Some(resolved)) => {
                        if resolved.username != configured.username {
                            return Err(OutboundProxyBuildError::InvalidSocks5Credentials {
                                reason: "launch username does not match the durable configuration",
                            });
                        }
                        resolved.validate()?;
                        Some(resolved)
                    }
                };
                Ok(Some(Self::Socks5 {
                    address: *address,
                    credentials,
                }))
            }
        }
    }

    /// Connects to `destination` through this outbound proxy.
    pub(crate) async fn connect(&self, destination: SocketAddr) -> io::Result<TcpStream> {
        match self {
            Self::Socks4 { address, user_id } => match user_id {
                Some(user_id) => {
                    Socks4Stream::connect_with_userid(*address, destination, user_id).await
                }
                None => Socks4Stream::connect(*address, destination).await,
            }
            .map(|stream| stream.into_inner())
            .map_err(io::Error::other),
            Self::Socks5 {
                address,
                credentials,
            } => {
                let mut stream = TcpStream::connect(*address).await?;
                Socks5Protocol::negotiate(&mut stream, credentials.as_ref()).await?;
                // The bound address is informational for CONNECT. Parse it to
                // validate the reply, but do not resolve proxy-supplied domains.
                let _ = Socks5Protocol::command(&mut stream, 0x01, destination).await?;
                Ok(stream)
            }
        }
    }

    /// Opens a SOCKS5 UDP association for relaying datagrams.
    pub(crate) async fn associate_udp(
        &self,
        dns_forwarder: Option<DnsForwarderHandle>,
    ) -> io::Result<Socks5UdpAssociation> {
        let Self::Socks5 {
            address,
            credentials,
        } = self
        else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "SOCKS4 does not support UDP relay",
            ));
        };

        let mut control = TcpStream::connect(*address).await?;
        Socks5Protocol::negotiate(&mut control, credentials.as_ref()).await?;

        let control_local = control.local_addr()?;
        // The UDP endpoint is not known until the proxy returns its relay.
        // RFC 1928 requires an all-zero endpoint in that case.
        let request_address = match control_local.ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let relays = match Socks5Protocol::command(&mut control, 0x03, request_address).await? {
            Socks5ReplyAddress::Socket(relay) => vec![relay],
            Socks5ReplyAddress::Domain { name, port } => {
                Socks5Protocol::resolve_domain(dns_forwarder.as_ref(), &name, port).await?
            }
        };
        Socks5UdpAssociation::connect(control, relays, dns_forwarder).await
    }
}

impl OutboundProxy {
    fn validate(&self) -> Result<(), OutboundProxyBuildError> {
        match self {
            Self::Socks4 { user_id, .. } => Self::validate_socks4_user_id(user_id.as_deref()),
            Self::Socks5 { credentials, .. } => credentials
                .as_ref()
                .map_or(Ok(()), Socks5Credentials::validate),
        }
    }

    fn validate_socks4_user_id(user_id: Option<&str>) -> Result<(), OutboundProxyBuildError> {
        let Some(user_id) = user_id else {
            return Ok(());
        };
        let reason = if user_id.is_empty() {
            "must not be empty"
        } else if user_id.len() > 255 {
            "must be at most 255 bytes"
        } else if user_id.contains('\0') {
            "must not contain a null byte"
        } else {
            return Ok(());
        };

        Err(OutboundProxyBuildError::InvalidSocks4UserId { reason })
    }
}

impl ResolvedSocks5Credentials {
    /// Creates credentials for the private launch contract.
    #[doc(hidden)]
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: Zeroizing::new(password.into()),
        }
    }

    /// Validates the RFC 1929 one-octet credential lengths.
    fn validate(&self) -> Result<(), OutboundProxyBuildError> {
        let reason = if self.username.is_empty() {
            "username must not be empty"
        } else if self.username.len() > u8::MAX as usize {
            "username must be at most 255 bytes"
        } else if self.password.is_empty() {
            "password must not be empty"
        } else if self.password.len() > u8::MAX as usize {
            "password must be at most 255 bytes"
        } else {
            return Ok(());
        };

        Err(OutboundProxyBuildError::InvalidSocks5Credentials { reason })
    }
}

impl Socks5Credentials {
    pub(crate) fn username(&self) -> &str {
        &self.username
    }

    pub(crate) fn password_source(&self) -> &SecretSource {
        &self.password
    }

    /// Validates the durable SOCKS5 credential configuration.
    fn validate(&self) -> Result<(), OutboundProxyBuildError> {
        if self.username.is_empty() {
            return Err(OutboundProxyBuildError::InvalidSocks5Credentials {
                reason: "username must not be empty",
            });
        }
        if self.username.len() > u8::MAX as usize {
            return Err(OutboundProxyBuildError::InvalidSocks5Credentials {
                reason: "username must be at most 255 bytes",
            });
        }
        match &self.password {
            SecretSource::Env { var } if var.is_empty() => {
                Err(OutboundProxyBuildError::InvalidSocks5Credentials {
                    reason: "password environment variable must not be empty",
                })
            }
            SecretSource::Env { .. } => Ok(()),
            SecretSource::Store { .. } => Err(OutboundProxyBuildError::InvalidSocks5Credentials {
                reason: "store-backed password sources are not supported yet",
            }),
        }
    }
}

impl Socks5UdpAssociation {
    /// Connects a UDP socket to the first usable relay address.
    async fn connect(
        control: TcpStream,
        relays: Vec<SocketAddr>,
        dns_forwarder: Option<DnsForwarderHandle>,
    ) -> io::Result<Self> {
        let peer_ip = control.peer_addr()?.ip();
        let mut last_error = None;

        for relay in relays {
            let relay = if relay.ip().is_unspecified() {
                SocketAddr::new(peer_ip, relay.port())
            } else {
                relay
            };
            let bind_address = match relay.ip() {
                IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            };
            let socket = match tokio::net::UdpSocket::bind(bind_address).await {
                Ok(socket) => socket,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            match socket.connect(relay).await {
                Ok(()) => {
                    return Ok(Self {
                        _control: control,
                        socket,
                        dns_forwarder,
                    });
                }
                Err(error) => last_error = Some(error),
            }
        }

        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "SOCKS5 proxy returned no usable UDP relay address",
            )
        }))
    }

    /// Sends one payload to `destination` through the UDP association.
    pub(crate) async fn send_to(
        &self,
        payload: &[u8],
        destination: SocketAddr,
    ) -> io::Result<usize> {
        let mut datagram =
            Vec::with_capacity(Socks5Protocol::address_len(destination) + 3 + payload.len());
        datagram.extend_from_slice(&[0x00, 0x00, 0x00]);
        Socks5Protocol::encode_address(&mut datagram, destination);
        datagram.extend_from_slice(payload);
        self.socket.send(&datagram).await.map(|_| payload.len())
    }

    /// Receives one payload and returns the remote endpoints encoded by the proxy.
    pub(crate) async fn recv_from(
        &self,
        buffer: &mut [u8],
    ) -> io::Result<(usize, Vec<SocketAddr>)> {
        let received = self.socket.recv(buffer).await?;
        let (header_len, source) = Socks5Protocol::decode_udp_header(&buffer[..received])?;
        let sources = match source {
            Socks5ReplyAddress::Socket(source) => vec![source],
            Socks5ReplyAddress::Domain { name, port } => {
                Socks5Protocol::resolve_domain(self.dns_forwarder.as_ref(), &name, port).await?
            }
        };
        let payload_len = received - header_len;
        buffer.copy_within(header_len..received, 0);
        Ok((payload_len, sources))
    }
}

impl fmt::Debug for ResolvedSocks5Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedSocks5Credentials")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

impl OutboundProxyBuilder {
    /// Creates a protocol selector.
    pub fn new() -> Self {
        Self
    }

    /// Starts building a SOCKS4 outbound proxy.
    pub fn socks4(self, address: impl Into<String>) -> Socks4ProxyBuilder {
        Socks4ProxyBuilder {
            address: address.into(),
            user_id: None,
        }
    }

    /// Starts building a SOCKS5 outbound proxy.
    pub fn socks5(self, address: impl Into<String>) -> Socks5ProxyBuilder {
        Socks5ProxyBuilder {
            address: address.into(),
            credentials: None,
        }
    }
}

impl Socks4ProxyBuilder {
    /// Sets the optional user ID sent during the SOCKS4 handshake.
    pub fn user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }
}

impl Socks5ProxyBuilder {
    /// Sets username authentication and a host-side password source.
    pub fn credentials(mut self, username: impl Into<String>, password: SecretSource) -> Self {
        self.credentials = Some(Socks5Credentials {
            username: username.into(),
            password,
        });
        self
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl OutboundProxyConfig for Socks4ProxyBuilder {
    fn build(self) -> Result<OutboundProxy, OutboundProxyBuildError> {
        let address =
            self.address
                .parse()
                .map_err(|source| OutboundProxyBuildError::InvalidAddress {
                    protocol: OutboundProxyProtocol::Socks4,
                    address: self.address,
                    source,
                })?;

        OutboundProxy::validate_socks4_user_id(self.user_id.as_deref())?;
        Ok(OutboundProxy::Socks4 {
            address,
            user_id: self.user_id,
        })
    }
}

impl OutboundProxyConfig for Socks5ProxyBuilder {
    fn build(self) -> Result<OutboundProxy, OutboundProxyBuildError> {
        let address =
            self.address
                .parse()
                .map_err(|source| OutboundProxyBuildError::InvalidAddress {
                    protocol: OutboundProxyProtocol::Socks5,
                    address: self.address,
                    source,
                })?;
        if let Some(credentials) = &self.credentials {
            credentials.validate()?;
        }
        Ok(OutboundProxy::Socks5 {
            address,
            credentials: self.credentials,
        })
    }
}

impl OutboundProxyConfig for OutboundProxy {
    fn build(self) -> Result<OutboundProxy, OutboundProxyBuildError> {
        self.validate()?;
        Ok(self)
    }
}

impl Socks5Protocol {
    /// Resolves a domain-form SOCKS5 endpoint through the internal DNS path.
    async fn resolve_domain(
        dns_forwarder: Option<&DnsForwarderHandle>,
        name: &str,
        port: u16,
    ) -> io::Result<Vec<SocketAddr>> {
        let dns_forwarder = dns_forwarder.ok_or_else(|| {
            io::Error::other("DNS forwarder is unavailable for SOCKS5 UDP endpoint resolution")
        })?;
        let forwarder = DnsForwarder::wait(dns_forwarder.clone())
            .await
            .ok_or_else(|| {
                io::Error::other("DNS forwarder is unavailable for SOCKS5 UDP endpoint resolution")
            })?;
        Ok(forwarder
            .resolve_proxy_domain(name)
            .await?
            .into_iter()
            .map(|address| SocketAddr::new(address, port))
            .collect())
    }

    /// Negotiates a SOCKS5 authentication method and performs username/password
    /// authentication when selected by the proxy.
    async fn negotiate(
        stream: &mut TcpStream,
        credentials: Option<&ResolvedSocks5Credentials>,
    ) -> io::Result<()> {
        if let Some(credentials) = credentials {
            credentials.validate().map_err(io::Error::other)?;
        }

        match credentials {
            Some(_) => stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?,
            None => stream.write_all(&[0x05, 0x01, 0x00]).await?,
        }

        let mut selection = [0u8; 2];
        stream.read_exact(&mut selection).await?;
        if selection[0] != 0x05 {
            return Err(Self::invalid_response("invalid method-selection version"));
        }

        match selection[1] {
            0x00 => Ok(()),
            0x02 => {
                let credentials = credentials.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "SOCKS5 proxy requires username/password authentication",
                    )
                })?;
                let username = credentials.username.as_bytes();
                let password = credentials.password.as_bytes();
                let mut request = Vec::with_capacity(3 + username.len() + password.len());
                request.extend_from_slice(&[0x01, username.len() as u8]);
                request.extend_from_slice(username);
                request.push(password.len() as u8);
                request.extend_from_slice(password);
                stream.write_all(&request).await?;

                let mut response = [0u8; 2];
                stream.read_exact(&mut response).await?;
                if response[0] != 0x01 {
                    return Err(Self::invalid_response(
                        "invalid username/password response version",
                    ));
                }
                if response[1] != 0x00 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "SOCKS5 username/password authentication failed",
                    ));
                }
                Ok(())
            }
            0xff => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 proxy rejected all offered authentication methods",
            )),
            method => Err(Self::invalid_response(format!(
                "SOCKS5 proxy selected unsupported authentication method {method:#04x}"
            ))),
        }
    }

    /// Sends a SOCKS5 command and returns the bound address from its reply.
    async fn command(
        stream: &mut TcpStream,
        command: u8,
        destination: SocketAddr,
    ) -> io::Result<Socks5ReplyAddress> {
        let mut request = Vec::with_capacity(3 + Self::address_len(destination));
        request.extend_from_slice(&[0x05, command, 0x00]);
        Self::encode_address(&mut request, destination);
        stream.write_all(&request).await?;

        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await?;
        if header[0] != 0x05 || header[2] != 0x00 {
            return Err(Self::invalid_response("invalid SOCKS5 command reply"));
        }
        if header[1] != 0x00 {
            return Err(io::Error::other(format!(
                "SOCKS5 proxy command failed: {}",
                Self::reply_message(header[1])
            )));
        }

        Self::read_address(stream, header[3]).await
    }

    /// Reads a SOCKS5 address whose address-type byte was already consumed.
    async fn read_address(
        stream: &mut TcpStream,
        address_type: u8,
    ) -> io::Result<Socks5ReplyAddress> {
        let ip = match address_type {
            0x01 => {
                let mut octets = [0u8; 4];
                stream.read_exact(&mut octets).await?;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            0x04 => {
                let mut octets = [0u8; 16];
                stream.read_exact(&mut octets).await?;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            0x03 => {
                let length = stream.read_u8().await? as usize;
                let mut domain = vec![0u8; length];
                stream.read_exact(&mut domain).await?;
                let domain = String::from_utf8(domain).map_err(|_| {
                    Self::invalid_response("SOCKS5 reply contains a non-UTF-8 domain")
                })?;
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).await?;
                return Ok(Socks5ReplyAddress::Domain {
                    name: domain,
                    port: u16::from_be_bytes(port),
                });
            }
            _ => return Err(Self::invalid_response("unsupported SOCKS5 address type")),
        };

        let mut port = [0u8; 2];
        stream.read_exact(&mut port).await?;
        Ok(Socks5ReplyAddress::Socket(SocketAddr::new(
            ip,
            u16::from_be_bytes(port),
        )))
    }

    /// Encodes a socket address in SOCKS5 address form.
    fn encode_address(output: &mut Vec<u8>, address: SocketAddr) {
        match address {
            SocketAddr::V4(address) => {
                output.push(0x01);
                output.extend_from_slice(&address.ip().octets());
                output.extend_from_slice(&address.port().to_be_bytes());
            }
            SocketAddr::V6(address) => {
                output.push(0x04);
                output.extend_from_slice(&address.ip().octets());
                output.extend_from_slice(&address.port().to_be_bytes());
            }
        }
    }

    /// Returns the encoded length of a SOCKS5 socket address.
    fn address_len(address: SocketAddr) -> usize {
        match address {
            SocketAddr::V4(_) => 7,
            SocketAddr::V6(_) => 19,
        }
    }

    /// Decodes a SOCKS5 UDP request header and returns its payload offset and endpoint.
    fn decode_udp_header(datagram: &[u8]) -> io::Result<(usize, Socks5ReplyAddress)> {
        if datagram.len() < 4 || datagram[..2] != [0x00, 0x00] {
            return Err(Self::invalid_response("invalid SOCKS5 UDP header"));
        }
        if datagram[2] != 0x00 {
            return Err(Self::invalid_response(
                "fragmented SOCKS5 UDP datagrams are not supported",
            ));
        }

        let (endpoint, port_offset) = match datagram[3] {
            0x01 if datagram.len() >= 10 => (
                Socks5ReplyAddress::Socket(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(
                        datagram[4],
                        datagram[5],
                        datagram[6],
                        datagram[7],
                    )),
                    u16::from_be_bytes([datagram[8], datagram[9]]),
                )),
                8,
            ),
            0x04 if datagram.len() >= 22 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&datagram[4..20]);
                (
                    Socks5ReplyAddress::Socket(SocketAddr::new(
                        IpAddr::V6(Ipv6Addr::from(octets)),
                        u16::from_be_bytes([datagram[20], datagram[21]]),
                    )),
                    20,
                )
            }
            0x03 if datagram.len() >= 7 => {
                let length = datagram[4] as usize;
                let port_offset = 5 + length;
                if length == 0 || datagram.len() < port_offset + 2 {
                    return Err(Self::invalid_response("invalid SOCKS5 UDP domain address"));
                }
                let name = std::str::from_utf8(&datagram[5..port_offset])
                    .map_err(|_| Self::invalid_response("non-UTF-8 SOCKS5 UDP domain address"))?
                    .to_owned();
                (
                    Socks5ReplyAddress::Domain {
                        name,
                        port: u16::from_be_bytes([
                            datagram[port_offset],
                            datagram[port_offset + 1],
                        ]),
                    },
                    port_offset,
                )
            }
            _ => return Err(Self::invalid_response("invalid SOCKS5 UDP address")),
        };
        Ok((port_offset + 2, endpoint))
    }

    /// Converts a SOCKS5 reply code into a stable diagnostic.
    fn reply_message(reply: u8) -> &'static str {
        match reply {
            0x01 => "general server failure",
            0x02 => "connection not allowed by ruleset",
            0x03 => "network unreachable",
            0x04 => "host unreachable",
            0x05 => "connection refused",
            0x06 => "TTL expired",
            0x07 => "command not supported",
            0x08 => "address type not supported",
            _ => "unknown error",
        }
    }

    /// Builds an invalid-data error for malformed SOCKS5 responses.
    fn invalid_response(message: impl Into<String>) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message.into())
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;

    use hickory_net::proto::op::{Message, MessageType, OpCode};
    use hickory_net::proto::rr::rdata::{A, AAAA};
    use hickory_net::proto::rr::{RData, Record, RecordType};
    use hickory_net::proto::serialize::binary::{BinDecodable, BinEncodable};
    use microsandbox_types::SecretSource;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};
    use tokio::sync::watch;

    use super::{
        OutboundProxy, OutboundProxyBuildError, OutboundProxyBuilder, OutboundProxyConfig,
        OutboundProxyProtocol, ResolvedOutboundProxy, ResolvedSocks5Credentials,
    };
    use crate::dns::forwarder::DnsForwarder;
    use crate::netstack::poll::GatewayIps;
    use crate::netstack::shared::SharedState;

    async fn responding_dns(relay_ipv6: Ipv6Addr, source_ipv4: Ipv4Addr) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = [0u8; 4096];
            loop {
                let Ok((length, source)) = socket.recv_from(&mut buffer).await else {
                    continue;
                };
                let Ok(query) = Message::from_bytes(&buffer[..length]) else {
                    continue;
                };
                let mut response =
                    Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                response.metadata.recursion_desired = query.metadata.recursion_desired;
                response.metadata.recursion_available = true;
                if let Some(question) = query.queries.first() {
                    response.add_query(question.clone());
                    let domain = question.name().to_string();
                    let answer = match (domain.trim_end_matches('.'), question.query_type()) {
                        ("relay.example.com", RecordType::AAAA) => {
                            Some(RData::AAAA(AAAA::from(relay_ipv6)))
                        }
                        ("source.example.com", RecordType::A) => {
                            Some(RData::A(A::from(source_ipv4)))
                        }
                        _ => None,
                    };
                    if let Some(answer) = answer {
                        response.add_answer(Record::from_rdata(
                            question.name().clone(),
                            60,
                            answer,
                        ));
                    }
                }
                if let Ok(bytes) = response.to_bytes() {
                    let _ = socket.send_to(&bytes, source).await;
                }
            }
        });
        address
    }

    #[test]
    fn builder_creates_socks4_proxy_with_optional_user_id() {
        let address = "127.0.0.1:1080".parse().unwrap();
        let without_user_id = OutboundProxyBuilder::new()
            .socks4("127.0.0.1:1080")
            .build()
            .unwrap();
        let with_user_id = OutboundProxyBuilder::new()
            .socks4("127.0.0.1:1080")
            .user_id("sandbox")
            .build()
            .unwrap();

        assert_eq!(
            without_user_id,
            OutboundProxy::Socks4 {
                address,
                user_id: None,
            }
        );
        assert_eq!(
            with_user_id,
            OutboundProxy::Socks4 {
                address,
                user_id: Some("sandbox".to_string()),
            }
        );
    }

    #[test]
    fn builder_creates_socks5_proxy() {
        let proxy = OutboundProxyBuilder::new()
            .socks5("127.0.0.1:1080")
            .build()
            .unwrap();

        assert_eq!(
            proxy,
            OutboundProxy::Socks5 {
                address: "127.0.0.1:1080".parse().unwrap(),
                credentials: None,
            }
        );
    }

    #[test]
    fn builder_creates_socks5_proxy_with_password_source() {
        let proxy = OutboundProxyBuilder::new()
            .socks5("127.0.0.1:1080")
            .credentials(
                "sandbox",
                SecretSource::Env {
                    var: "SOCKS5_PASSWORD".into(),
                },
            )
            .build()
            .unwrap();

        let debug = format!("{proxy:?}");
        assert!(debug.contains("sandbox"));
        assert!(debug.contains("SOCKS5_PASSWORD"));

        let json = serde_json::to_value(&proxy).unwrap();
        assert_eq!(json["credentials"]["username"], "sandbox");
        assert_eq!(json["credentials"]["password"]["kind"], "env");
        assert_eq!(json["credentials"]["password"]["var"], "SOCKS5_PASSWORD");
        assert!(json["credentials"].get("value").is_none());
    }

    #[test]
    fn builder_rejects_invalid_socks5_credentials() {
        for (username, password_env) in [
            (String::new(), "SOCKS5_PASSWORD".to_string()),
            ("username".to_string(), String::new()),
            ("u".repeat(256), "SOCKS5_PASSWORD".to_string()),
        ] {
            assert!(
                OutboundProxyBuilder::new()
                    .socks5("127.0.0.1:1080")
                    .credentials(username, SecretSource::Env { var: password_env })
                    .build()
                    .is_err()
            );
        }

        assert!(
            OutboundProxyBuilder::new()
                .socks5("127.0.0.1:1080")
                .credentials(
                    "username",
                    SecretSource::Store {
                        reference: "production/socks5-password".into(),
                    },
                )
                .build()
                .is_err()
        );
    }

    #[test]
    fn resolved_proxy_build_validates_resolved_socks5_password() {
        let proxy = OutboundProxyBuilder::new()
            .socks5("127.0.0.1:1080")
            .credentials(
                "sandbox",
                SecretSource::Env {
                    var: "SOCKS5_PASSWORD".into(),
                },
            )
            .build()
            .unwrap();
        assert!(
            ResolvedOutboundProxy::build(
                Some(&proxy),
                Some(ResolvedSocks5Credentials::new("sandbox", "")),
            )
            .is_err()
        );
        assert!(
            ResolvedOutboundProxy::build(
                Some(&proxy),
                Some(ResolvedSocks5Credentials::new("sandbox", "p".repeat(256),)),
            )
            .is_err()
        );
        ResolvedOutboundProxy::build(
            Some(&proxy),
            Some(ResolvedSocks5Credentials::new("sandbox", "password")),
        )
        .unwrap();
    }

    #[test]
    fn resolved_proxy_build_requires_matching_resolved_credentials() {
        let authenticated = OutboundProxyBuilder::new()
            .socks5("127.0.0.1:1080")
            .credentials("sandbox", SecretSource::env("SOCKS5_PASSWORD"))
            .build()
            .unwrap();
        let unauthenticated = OutboundProxyBuilder::new()
            .socks5("127.0.0.1:1080")
            .build()
            .unwrap();
        let resolved = || ResolvedSocks5Credentials::new("sandbox", "password");

        assert!(ResolvedOutboundProxy::build(Some(&authenticated), None).is_err());
        assert!(ResolvedOutboundProxy::build(Some(&unauthenticated), Some(resolved())).is_err());
        assert!(ResolvedOutboundProxy::build(None, Some(resolved())).is_err());
        assert!(
            ResolvedOutboundProxy::build(
                Some(&authenticated),
                Some(ResolvedSocks5Credentials::new("different-user", "password")),
            )
            .is_err()
        );
    }

    #[test]
    fn uri_parses_and_formats_for_cli() {
        let socks4: OutboundProxy = "socks4://127.0.0.1:1080".parse().unwrap();
        let socks5: OutboundProxy = "socks5://127.0.0.1:1080".parse().unwrap();

        assert_eq!(
            socks4,
            OutboundProxy::Socks4 {
                address: "127.0.0.1:1080".parse().unwrap(),
                user_id: None,
            }
        );
        assert_eq!(socks4.to_string(), "socks4://127.0.0.1:1080");
        assert_eq!(
            socks5,
            OutboundProxy::Socks5 {
                address: "127.0.0.1:1080".parse().unwrap(),
                credentials: None,
            }
        );
        assert_eq!(socks5.to_string(), "socks5://127.0.0.1:1080");
    }

    #[test]
    fn uri_rejects_unsupported_forms() {
        for raw in [
            "127.0.0.1:1080",
            "http://127.0.0.1:1080",
            "socks4://user@127.0.0.1:1080",
            "socks5://user@127.0.0.1:1080",
            "socks5://127.0.0.1:1080/path",
            "socks5://127.0.0.1:1080?option=value",
            "socks5://127.0.0.1:1080#fragment",
        ] {
            assert!(raw.parse::<OutboundProxy>().is_err(), "accepted {raw:?}");
        }
    }

    #[test]
    fn builder_rejects_invalid_socks4_user_ids() {
        for user_id in [String::new(), "a\0b".to_string(), "a".repeat(256)] {
            assert!(
                OutboundProxyBuilder::new()
                    .socks4("127.0.0.1:1080")
                    .user_id(user_id)
                    .build()
                    .is_err()
            );
        }
    }

    #[test]
    fn outbound_proxy_rejects_invalid_socks4_user_ids() {
        for user_id in [String::new(), "a\0b".to_string(), "a".repeat(256)] {
            let proxy = OutboundProxy::Socks4 {
                address: "127.0.0.1:1080".parse().unwrap(),
                user_id: Some(user_id),
            };

            assert!(proxy.build().is_err());
        }
    }

    #[test]
    fn invalid_address_error_uses_typed_protocol() {
        let error = OutboundProxyBuilder::new()
            .socks5("not-an-address")
            .build()
            .unwrap_err();

        assert!(matches!(
            error,
            OutboundProxyBuildError::InvalidAddress {
                protocol: OutboundProxyProtocol::Socks5,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn connects_through_socks4_proxy_with_user_id() {
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut client, _) = proxy_listener.accept().await.unwrap();

            let mut request = [0u8; 16];
            client.read_exact(&mut request).await.unwrap();
            assert_eq!(request[0], 0x04, "SOCKS version");
            assert_eq!(request[1], 0x01, "CONNECT command");
            assert_eq!(u16::from_be_bytes([request[2], request[3]]), 443);
            assert_eq!(&request[4..8], &[93, 184, 216, 34]);
            assert_eq!(&request[8..], b"sandbox\0");

            client
                .write_all(&[0x00, 0x5a, 0x01, 0xbb, 93, 184, 216, 34])
                .await
                .unwrap();

            let mut buf = [0u8; 5];
            client.read_exact(&mut buf).await.unwrap();
            client.write_all(&buf).await.unwrap();
        });

        let mut stream = ResolvedOutboundProxy::Socks4 {
            address: proxy_addr,
            user_id: Some("sandbox".to_string()),
        }
        .connect(target)
        .await
        .unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");

        proxy_task.await.unwrap();
    }

    #[tokio::test]
    async fn connects_through_socks5_proxy() {
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut client, _) = proxy_listener.accept().await.unwrap();

            let mut greeting = [0u8; 3];
            client.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            client.write_all(&[0x05, 0x00]).await.unwrap();

            let mut request = [0u8; 10];
            client.read_exact(&mut request).await.unwrap();
            assert_eq!(request[0], 0x05, "SOCKS version");
            assert_eq!(request[1], 0x01, "CONNECT command");
            assert_eq!(request[3], 0x01, "IPv4 address type");
            assert_eq!(&request[4..8], &[93, 184, 216, 34]);
            assert_eq!(u16::from_be_bytes([request[8], request[9]]), 443);

            client
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();

            let mut buf = [0u8; 5];
            client.read_exact(&mut buf).await.unwrap();
            client.write_all(&buf).await.unwrap();
        });

        let mut stream = ResolvedOutboundProxy::Socks5 {
            address: proxy_addr,
            credentials: None,
        }
        .connect(target)
        .await
        .unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");

        proxy_task.await.unwrap();
    }

    #[tokio::test]
    async fn connect_does_not_resolve_domain_from_socks5_reply() {
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut client, _) = proxy_listener.accept().await.unwrap();

            let mut greeting = [0u8; 3];
            client.read_exact(&mut greeting).await.unwrap();
            client.write_all(&[0x05, 0x00]).await.unwrap();

            let mut request = [0u8; 10];
            client.read_exact(&mut request).await.unwrap();
            let domain = b"does-not-resolve.invalid";
            let mut response = vec![0x05, 0x00, 0x00, 0x03, domain.len() as u8];
            response.extend_from_slice(domain);
            response.extend_from_slice(&443u16.to_be_bytes());
            client.write_all(&response).await.unwrap();

            let mut buf = [0u8; 5];
            client.read_exact(&mut buf).await.unwrap();
            client.write_all(&buf).await.unwrap();
        });

        let mut stream = ResolvedOutboundProxy::Socks5 {
            address: proxy_addr,
            credentials: None,
        }
        .connect(target)
        .await
        .unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");

        proxy_task.await.unwrap();
    }

    #[tokio::test]
    async fn connects_through_authenticated_socks5_proxy() {
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut client, _) = proxy_listener.accept().await.unwrap();

            let mut greeting = [0u8; 4];
            client.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x02, 0x00, 0x02]);
            client.write_all(&[0x05, 0x02]).await.unwrap();

            let mut auth = [0u8; 18];
            client.read_exact(&mut auth).await.unwrap();
            assert_eq!(&auth, b"\x01\x07sandbox\x08password");
            client.write_all(&[0x01, 0x00]).await.unwrap();

            let mut request = [0u8; 10];
            client.read_exact(&mut request).await.unwrap();
            assert_eq!(request[1], 0x01, "CONNECT command");
            client
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });

        let configured = OutboundProxyBuilder::new()
            .socks5(proxy_addr.to_string())
            .credentials(
                "sandbox",
                SecretSource::Env {
                    var: "SOCKS5_PASSWORD".into(),
                },
            )
            .build()
            .unwrap();
        let proxy = ResolvedOutboundProxy::build(
            Some(&configured),
            Some(ResolvedSocks5Credentials::new("sandbox", "password")),
        )
        .unwrap()
        .unwrap();
        proxy.connect(target).await.unwrap();

        proxy_task.await.unwrap();
    }

    #[tokio::test]
    async fn associates_and_relays_socks5_udp() {
        let target: SocketAddr = "93.184.216.34:5353".parse().unwrap();
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        let proxy_task = tokio::spawn(async move {
            let (mut control, _) = proxy_listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            control.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            control.write_all(&[0x05, 0x00]).await.unwrap();

            let mut request = [0u8; 10];
            control.read_exact(&mut request).await.unwrap();
            assert_eq!(request[1], 0x03, "UDP ASSOCIATE command");

            let mut response = vec![0x05, 0x00, 0x00, 0x01];
            let SocketAddr::V4(relay_addr) = relay_addr else {
                unreachable!()
            };
            response.extend_from_slice(&relay_addr.ip().octets());
            response.extend_from_slice(&relay_addr.port().to_be_bytes());
            control.write_all(&response).await.unwrap();

            let mut datagram = [0u8; 64];
            let (received, client) = relay.recv_from(&mut datagram).await.unwrap();
            assert_eq!(&datagram[..10], &[0, 0, 0, 1, 93, 184, 216, 34, 0x14, 0xe9]);
            assert_eq!(&datagram[10..received], b"hello");
            relay.send_to(&datagram[..received], client).await.unwrap();
        });

        let configured = OutboundProxyBuilder::new()
            .socks5(proxy_addr.to_string())
            .build()
            .unwrap();
        let proxy = ResolvedOutboundProxy::build(Some(&configured), None)
            .unwrap()
            .unwrap();
        let association = proxy.associate_udp(None).await.unwrap();
        association.send_to(b"hello", target).await.unwrap();
        let mut response = [0u8; 64];
        let (received, sources) = association.recv_from(&mut response).await.unwrap();
        assert_eq!(sources, vec![target]);
        assert_eq!(&response[..received], b"hello");

        proxy_task.await.unwrap();
    }

    #[tokio::test]
    async fn udp_association_supports_domain_relay_in_another_address_family() {
        let target: SocketAddr = "93.184.216.34:5353".parse().unwrap();
        let relay = UdpSocket::bind("[::1]:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let dns_upstream =
            responding_dns(Ipv6Addr::LOCALHOST, Ipv4Addr::new(93, 184, 216, 34)).await;
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut control, _) = proxy_listener.accept().await.unwrap();

            let mut greeting = [0u8; 3];
            control.read_exact(&mut greeting).await.unwrap();
            control.write_all(&[0x05, 0x00]).await.unwrap();

            let mut request = [0u8; 10];
            control.read_exact(&mut request).await.unwrap();
            assert_eq!(request[1], 0x03, "UDP ASSOCIATE command");

            let domain = b"relay.example.com";
            let mut response = vec![0x05, 0x00, 0x00, 0x03, domain.len() as u8];
            response.extend_from_slice(domain);
            response.extend_from_slice(&relay_addr.port().to_be_bytes());
            control.write_all(&response).await.unwrap();

            let mut datagram = [0u8; 64];
            let (_, client) = relay.recv_from(&mut datagram).await.unwrap();
            let source_domain = b"source.example.com";
            let mut response = vec![0x00, 0x00, 0x00, 0x03, source_domain.len() as u8];
            response.extend_from_slice(source_domain);
            response.extend_from_slice(&target.port().to_be_bytes());
            response.extend_from_slice(b"hello");
            relay.send_to(&response, client).await.unwrap();
        });

        let proxy = ResolvedOutboundProxy::Socks5 {
            address: proxy_addr,
            credentials: None,
        };
        let forwarder = DnsForwarder::for_proxy_test(
            Arc::new(SharedState::new(4)),
            GatewayIps {
                ipv4: Some("127.0.0.1".parse().unwrap()),
                ipv6: None,
            },
            Some(dns_upstream),
        )
        .await;
        let (_dns_tx, dns_forwarder) = watch::channel(Some(forwarder));
        let association = proxy.associate_udp(Some(dns_forwarder)).await.unwrap();
        association.send_to(b"hello", target).await.unwrap();
        let mut response = [0u8; 64];
        let (received, sources) = association.recv_from(&mut response).await.unwrap();
        assert_eq!(sources, vec![target]);
        assert_eq!(&response[..received], b"hello");

        proxy_task.await.unwrap();
    }
}
