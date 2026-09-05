//! Guest-facing HTTP forward proxy.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::config::HttpProxyConfig;
use crate::netstack::shared::SharedState;
use crate::policy::{NetworkPolicy, Protocol};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_HEADERS: usize = 64 * 1024;
const CONNECT_RESPONSE_LIMIT: usize = 8192;
const CONNECT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct ParsedRequest {
    connect: bool,
    target: Target,
    request_line: Vec<u8>,
    header_tail: Vec<u8>,
    body: Vec<u8>,
}

struct Target {
    host: String,
    port: u16,
    path: String,
}

enum ConnectionTarget {
    Address(SocketAddr),
    Hostname(String, u16),
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Start HTTP proxy listeners on the host loopback addresses used by a guest.
pub(crate) fn spawn(
    listeners: Option<HttpProxyListeners>,
    upstream_proxy: Option<String>,
    network_policy: Arc<NetworkPolicy>,
    platform_policy: Option<Arc<NetworkPolicy>>,
    shared: Arc<SharedState>,
    handle: &tokio::runtime::Handle,
) {
    let Some(listeners) = listeners else {
        return;
    };

    for (address, listener) in [
        listeners
            .ipv4
            .map(|listener| (listener.local_addr().ok(), listener)),
        listeners
            .ipv6
            .map(|listener| (listener.local_addr().ok(), listener)),
    ]
    .into_iter()
    .flatten()
    {
        let Some(address) = address else {
            continue;
        };
        let upstream_proxy = upstream_proxy.clone();
        let network_policy = network_policy.clone();
        let platform_policy = platform_policy.clone();
        let shared = shared.clone();
        let handle = handle.clone();
        let listener = {
            let _guard = handle.enter();
            match TcpListener::from_std(listener) {
                Ok(listener) => listener,
                Err(error) => {
                    tracing::warn!(%address, %error, "HTTP proxy listener failed to bind");
                    continue;
                }
            }
        };
        let task_handle = handle.clone();
        handle.spawn(async move {
            tracing::debug!(%address, "HTTP proxy listener started");
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(value) => value,
                    Err(error) => {
                        tracing::debug!(%address, %error, "HTTP proxy accept failed");
                        continue;
                    }
                };
                let upstream_proxy = upstream_proxy.clone();
                let network_policy = network_policy.clone();
                let platform_policy = platform_policy.clone();
                let shared = shared.clone();
                task_handle.spawn(async move {
                    if let Err(error) = serve(
                        stream,
                        upstream_proxy.as_deref(),
                        &network_policy,
                        platform_policy.as_deref(),
                        &shared,
                    )
                    .await
                    {
                        tracing::debug!(%error, "HTTP proxy connection closed");
                    }
                });
            }
        });
    }
}

pub(crate) struct HttpProxyListeners {
    pub(crate) ipv4: Option<std::net::TcpListener>,
    pub(crate) ipv6: Option<std::net::TcpListener>,
}

pub(crate) fn prepare(
    config: &HttpProxyConfig,
    gateway_ipv4: Option<std::net::Ipv4Addr>,
    gateway_ipv6: Option<std::net::Ipv6Addr>,
) -> io::Result<Option<(HttpProxyListeners, u16)>> {
    if !config.enabled || (gateway_ipv4.is_none() && gateway_ipv6.is_none()) {
        return Ok(None);
    }

    let bind_ipv4 = gateway_ipv4.is_some();
    let bind_ipv6 = gateway_ipv6.is_some();
    let first_address = if bind_ipv4 {
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), config.port)
    } else {
        SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), config.port)
    };
    let first = std::net::TcpListener::bind(first_address)?;
    first.set_nonblocking(true)?;
    let port = first.local_addr()?.port();

    let second = if bind_ipv4 && bind_ipv6 {
        let address = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), port);
        let listener = std::net::TcpListener::bind(address)?;
        listener.set_nonblocking(true)?;
        Some(listener)
    } else {
        None
    };

    let (ipv4, ipv6) = match (bind_ipv4, bind_ipv6) {
        (true, true) => (Some(first), second),
        (true, false) => (Some(first), None),
        (false, true) => (None, Some(first)),
        (false, false) => unreachable!("proxy listener requires an active gateway family"),
    };
    Ok(Some((HttpProxyListeners { ipv4, ipv6 }, port)))
}

async fn serve(
    mut guest: TcpStream,
    upstream_proxy: Option<&str>,
    network_policy: &NetworkPolicy,
    platform_policy: Option<&NetworkPolicy>,
    shared: &SharedState,
) -> io::Result<()> {
    let request = read_headers(&mut guest).await?;
    let parsed = parse_request(&request)?;
    let target = parsed.target;
    let protocol = Protocol::Tcp;
    let Some(connect_target) = target_connection_target(
        &target.host,
        target.port,
        network_policy,
        platform_policy,
        protocol,
        shared,
    )
    .await
    else {
        guest
            .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
            .await?;
        return Ok(());
    };

    let upstream_result = match upstream_proxy {
        Some(proxy) => {
            let (host, port) = match &connect_target {
                ConnectionTarget::Address(address) => (address.ip().to_string(), address.port()),
                ConnectionTarget::Hostname(host, port) => (host.clone(), *port),
            };
            connect_upstream(proxy, &host, port).await
        }
        None => match connect_target {
            ConnectionTarget::Address(address) => TcpStream::connect(address).await,
            ConnectionTarget::Hostname(host, port) => TcpStream::connect((host, port)).await,
        }
        .map(|stream| (stream, Vec::new())),
    };
    let (mut upstream, upstream_initial) = match upstream_result {
        Ok(result) => result,
        Err(error) => {
            tracing::debug!(%error, target = %target.host, port = target.port, "HTTP proxy upstream connection failed");
            guest
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                .await?;
            return Ok(());
        }
    };

    if parsed.connect {
        let response = b"HTTP/1.1 200 Connection Established\r\n\r\n";
        guest.write_all(response).await?;
        if !upstream_initial.is_empty() {
            guest.write_all(&upstream_initial).await?;
        }
        if !parsed.body.is_empty() {
            upstream.write_all(&parsed.body).await?;
        }
    } else {
        let mut first_line = parsed.request_line;
        first_line = rewrite_request_line(&first_line, &target.path)?;
        upstream.write_all(&first_line).await?;
        upstream.write_all(&parsed.header_tail).await?;
        if !parsed.body.is_empty() {
            upstream.write_all(&parsed.body).await?;
        }
    }
    upstream.flush().await?;
    tokio::io::copy_bidirectional(&mut guest, &mut upstream).await?;
    Ok(())
}

async fn target_connection_target(
    host: &str,
    port: u16,
    network_policy: &NetworkPolicy,
    platform_policy: Option<&NetworkPolicy>,
    protocol: Protocol,
    shared: &SharedState,
) -> Option<ConnectionTarget> {
    let policies = [Some(network_policy), platform_policy];
    if let Ok(address) = host.parse::<IpAddr>() {
        return policies
            .into_iter()
            .flatten()
            .all(|policy| {
                policy
                    .evaluate_egress(SocketAddr::new(address, port), protocol, shared)
                    .is_allow()
            })
            .then_some(ConnectionTarget::Address(SocketAddr::new(address, port)));
    }

    if policies.into_iter().flatten().any(|policy| {
        !policy
            .evaluate_proxy_hostname(host, protocol, port)
            .is_allow()
    }) {
        return None;
    }

    Some(ConnectionTarget::Hostname(host.to_owned(), port))
}

async fn read_headers(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut data = Vec::with_capacity(4096);
    let mut buf = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(std::time::Duration::from_secs(10), stream.read(&mut buf))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "timed out reading proxy request")
            })??;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "proxy request ended before headers",
            ));
        }
        data.extend_from_slice(&buf[..n]);
        if data.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(data);
        }
        if data.len() > MAX_HEADERS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "proxy request headers too large",
            ));
        }
    }
}

fn parse_request(data: &[u8]) -> io::Result<ParsedRequest> {
    let end = data
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "incomplete proxy headers"))?;
    let header = &data[..end];
    let line_end = header
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP request line"))?;
    let line = &header[..line_end];
    let text = std::str::from_utf8(line)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "HTTP request is not UTF-8"))?;
    let mut parts = text.split_ascii_whitespace();
    let method = parts.next().unwrap_or_default();
    let uri = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if uri.is_empty() || !version.starts_with("HTTP/") || parts.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed HTTP request line",
        ));
    }

    let connect = method.eq_ignore_ascii_case("CONNECT");
    let target = if connect {
        let (host, port) = parse_authority(uri)?;
        Target {
            host,
            port,
            path: String::new(),
        }
    } else {
        let url = url::Url::parse(uri).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP proxy requires an absolute-form request target",
            )
        })?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported HTTP proxy request scheme",
            ));
        }
        let host = url
            .host_str()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "request target has no host")
            })?
            .to_string();
        let port = url.port_or_known_default().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "request target has no port")
        })?;
        let mut path = if url.path().is_empty() {
            "/".to_string()
        } else {
            url.path().to_string()
        };
        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }
        Target { host, port, path }
    };

    let body = if connect {
        data[end..].to_vec()
    } else {
        data[line_end + 2..].to_vec()
    };
    Ok(ParsedRequest {
        connect,
        target,
        request_line: data[..line_end + 2].to_vec(),
        header_tail: data[line_end + 2..end].to_vec(),
        body,
    })
}

fn parse_authority(value: &str) -> io::Result<(String, u16)> {
    let value = value.trim();
    let (host, port) = if let Some(value) = value.strip_prefix('[') {
        let (host, rest) = value.split_once(']').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "malformed IPv6 proxy authority")
        })?;
        (
            host,
            rest.strip_prefix(':').ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "proxy authority has no port")
            })?,
        )
    } else {
        value.rsplit_once(':').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "proxy authority has no port")
        })?
    };
    if host.is_empty() || host.contains(':') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid proxy authority host",
        ));
    }
    let port = port
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid proxy authority port"))?;
    Ok((host.trim_end_matches('.').to_string(), port))
}

fn rewrite_request_line(line: &[u8], path: &str) -> io::Result<Vec<u8>> {
    let text = std::str::from_utf8(line)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "HTTP request is not UTF-8"))?;
    let mut parts = text.split_ascii_whitespace();
    let method = parts.next().unwrap_or_default();
    let _ = parts.next();
    let version = parts.next().unwrap_or_default();
    if method.is_empty() || version.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed HTTP request line",
        ));
    }
    Ok(format!("{method} {path} {version}\r\n").into_bytes())
}

async fn connect_upstream(proxy: &str, host: &str, port: u16) -> io::Result<(TcpStream, Vec<u8>)> {
    let url = url::Url::parse(proxy).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid upstream proxy URL: {error}"),
        )
    })?;
    if url.scheme() != "http" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "upstream proxy must use http",
        ));
    }
    let proxy_host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "upstream proxy has no host"))?;
    let proxy_port = url
        .port_or_known_default()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "upstream proxy has no port"))?;
    let mut stream = TcpStream::connect((proxy_host, proxy_port)).await?;
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    let response = read_response_headers(&mut stream).await?;
    let status = response
        .split(|byte| byte.is_ascii_whitespace())
        .nth(1)
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(|value| value.parse::<u16>().ok());
    if !response.starts_with(b"HTTP/") || !status.is_some_and(|status| (200..300).contains(&status))
    {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "upstream proxy rejected CONNECT",
        ));
    }
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response headers were checked by read_response_headers")
        + 4;
    Ok((stream, response[header_end..].to_vec()))
}

async fn read_response_headers(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut data = Vec::with_capacity(256);
    let mut buf = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(CONNECT_RESPONSE_TIMEOUT, stream.read(&mut buf))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for upstream CONNECT response",
                )
            })??;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "upstream proxy closed before CONNECT response",
            ));
        }
        data.extend_from_slice(&buf[..n]);
        if data.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(data);
        }
        if data.len() > CONNECT_RESPONSE_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "upstream proxy response headers too large",
            ));
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn parses_absolute_form() {
        let request =
            parse_request(b"GET http://example.com/a?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
                .unwrap();
        assert_eq!(request.target.host, "example.com");
        assert_eq!(request.target.port, 80);
        assert_eq!(request.target.path, "/a?q=1");
        assert_eq!(request.header_tail, b"Host: example.com\r\n\r\n".to_vec());
        assert!(!request.connect);
    }

    #[test]
    fn parses_connect_authority() {
        let request = parse_request(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(request.target.host, "example.com");
        assert_eq!(request.target.port, 443);
        assert!(request.connect);
    }

    #[test]
    fn rewrites_absolute_form_to_origin_form() {
        assert_eq!(
            rewrite_request_line(b"GET http://example.com/a HTTP/1.1\r\n", "/a").unwrap(),
            b"GET /a HTTP/1.1\r\n"
        );
    }

    #[tokio::test]
    async fn upstream_connect_preserves_destination_hostname() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_headers(&mut stream).await.unwrap();
            assert!(request.starts_with(b"CONNECT example.com:443 HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
        });

        let proxy = format!("http://{address}");
        let (_stream, initial) = connect_upstream(&proxy, "example.com", 443).await.unwrap();
        assert!(initial.is_empty());
        task.await.unwrap();
    }
}
