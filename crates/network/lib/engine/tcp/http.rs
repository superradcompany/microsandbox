//! Guest-facing HTTP forward proxy.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
#[cfg(test)]
use std::time::Duration;

use bytes::Bytes;
use futures::FutureExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::engine::tls::{proxy::TlsProxy, state::TlsState};
use crate::netstack::shared::SharedState;
use crate::policy::{NetworkPolicy, Protocol};
use crate::proxy::HttpConnectProtocol;
use crate::secrets::config::{SecretViolationAction, SecretsConfig};
use crate::secrets::handler::SecretsHandler;
use crate::tcp::connection::ProxyConnectState;
use crate::tcp::upstream::UpstreamTcpTarget;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_HEADERS: usize = 64 * 1024;
/// Stable guest-facing proxy port for snapshot-safe environment defaults.
pub(crate) const GUEST_HTTP_PROXY_PORT: u16 = 3128;
#[cfg(test)]
const CONNECT_RESPONSE_LIMIT: usize = 8192;
#[cfg(test)]
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
    body_framing: RequestBodyFraming,
    expect_continue: bool,
}

#[derive(Clone)]
struct Target {
    host: String,
    port: u16,
    path: String,
}

#[derive(Clone, Copy)]
enum RequestBodyFraming {
    None,
    Length(usize),
    Chunked,
}

#[derive(Debug, PartialEq, Eq)]
enum ResponseBodyFraming {
    None,
    Length(u64),
    Chunked,
    CloseDelimited,
}

#[derive(Debug, thiserror::Error)]
#[error("the HTTP proxy accepts only one request per connection")]
struct PipelinedRequest;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Serve a guest connection to the sandbox-local HTTP proxy.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_connection(
    from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    upstream_proxy: SocketAddr,
    network_policy: Arc<NetworkPolicy>,
    platform_policy: Option<Arc<NetworkPolicy>>,
    tls_state: Option<Arc<TlsState>>,
    secrets: Arc<SecretsConfig>,
    strict: bool,
    shared: Arc<SharedState>,
    handle: &tokio::runtime::Handle,
) {
    let runtime = handle.clone();
    handle.spawn(async move {
        let (proxy_stream, bridge_stream) = tokio::io::duplex(128 * 1024);
        let (mut proxy_read, mut proxy_write) = tokio::io::split(proxy_stream);
        let mut proxy_guest_rx = from_smoltcp;
        let proxy_guest_tx = to_smoltcp;
        let guest_shared = shared.clone();
        let guest_to_proxy = runtime.spawn(async move {
            while let Some(bytes) = proxy_guest_rx.recv().await {
                proxy_write.write_all(&bytes).await?;
            }
            proxy_write.shutdown().await
        });
        let proxy_to_guest = runtime.spawn(async move {
            let mut buffer = [0u8; 16 * 1024];
            loop {
                let count = proxy_read.read(&mut buffer).await?;
                if count == 0 {
                    return Ok::<(), io::Error>(());
                }
                if proxy_guest_tx
                    .send(Bytes::copy_from_slice(&buffer[..count]))
                    .await
                    .is_err()
                {
                    return Ok(());
                }
                guest_shared.proxy_wake.wake();
            }
        });

        let result = serve(
            bridge_stream,
            upstream_proxy,
            network_policy,
            platform_policy,
            tls_state,
            secrets,
            strict,
            shared,
        )
        .await;
        if let Err(error) = result {
            tracing::debug!(%error, "HTTP proxy connection closed");
        }
        guest_to_proxy.abort();
        let _ = guest_to_proxy.await;
        let _ = proxy_to_guest.await;
    });
}

#[allow(clippy::too_many_arguments)]
async fn serve<S>(
    mut guest: S,
    upstream_proxy: SocketAddr,
    network_policy: Arc<NetworkPolicy>,
    platform_policy: Option<Arc<NetworkPolicy>>,
    tls_state: Option<Arc<TlsState>>,
    secrets: Arc<SecretsConfig>,
    strict: bool,
    shared: Arc<SharedState>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let request = read_headers(&mut guest).await?;
    let parsed = parse_request(&request)?;
    if !parsed.connect
        && !parsed.body.is_empty()
        && match parsed.body_framing {
            RequestBodyFraming::None => true,
            RequestBodyFraming::Length(length) => parsed.body.len() > length,
            RequestBodyFraming::Chunked => false,
        }
        && !headers_have_upgrade(&parsed.header_tail)?
    {
        guest
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            )
            .await?;
        return Ok(());
    }
    let target = parsed.target.clone();
    let protocol = Protocol::Tcp;
    if !hostname_allowed(
        &target.host,
        target.port,
        &network_policy,
        platform_policy.as_deref(),
        protocol,
        &shared,
    ) {
        guest
            .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
            .await?;
        return Ok(());
    }

    let intercepts_tls = tls_state
        .as_ref()
        .is_some_and(|state| state.config.intercepted_ports.contains(&target.port));
    if parsed.connect
        && !secrets.secrets.is_empty()
        && (!intercepts_tls
            || tls_state.as_ref().is_some_and(|state| {
                state.should_bypass(&target.host.trim_end_matches('.').to_ascii_lowercase())
            }))
    {
        let body = "CONNECT tunnels require TLS interception when secrets are configured because unchecked tunnel payloads cannot be checked for secret violations.\n";
        let response = format!(
            "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
            body.len(),
        );
        guest.write_all(response.as_bytes()).await?;
        guest.shutdown().await?;
        return Ok(());
    }
    if parsed.connect
        && strict
        && !intercepts_tls
        && target.host.parse::<IpAddr>().is_err()
        && network_policy.allows_proxy_hostname_via_domain(&target.host, Protocol::Tcp, target.port)
    {
        guest
            .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
            .await?;
        return Ok(());
    }

    if !parsed.connect && !secrets.secrets.is_empty() && headers_have_upgrade(&parsed.header_tail)?
    {
        // Upgraded protocols can mask, compress, or otherwise encode their
        // payloads. The HTTP secret handler cannot enforce their violations,
        // so refuse the upgrade before opening an upstream connection.
        let body = "HTTP upgrades are unavailable when secrets are configured because upgraded payloads cannot be checked for secret violations.\n";
        let response = format!(
            "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
            body.len(),
        );
        guest.write_all(response.as_bytes()).await?;
        guest.shutdown().await?;
        return Ok(());
    }

    let upstream_result = if parsed.connect {
        HttpConnectProtocol::connect_host(upstream_proxy, &target.host, target.port).await
    } else {
        TcpStream::connect(upstream_proxy).await
    };
    let mut upstream = match upstream_result {
        Ok(stream) => stream,
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
        if let Some(tls_state) = tls_state.filter(|_| intercepts_tls) {
            return run_tls_mitm(
                guest,
                upstream,
                target.host,
                target.port,
                parsed.body,
                network_policy,
                tls_state,
                strict,
                shared,
            )
            .await;
        }
        if !parsed.body.is_empty() {
            upstream.write_all(&parsed.body).await?;
        }
    } else {
        return serve_plain_http_request(guest, upstream, parsed, secrets, network_policy, shared)
            .await;
    }
    upstream.flush().await?;
    tokio::io::copy_bidirectional(&mut guest, &mut upstream).await?;
    Ok(())
}

async fn serve_plain_http_request<S>(
    mut guest: S,
    mut upstream: TcpStream,
    parsed: ParsedRequest,
    secrets: Arc<SecretsConfig>,
    network_policy: Arc<NetworkPolicy>,
    shared: Arc<SharedState>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ParsedRequest {
        target,
        request_line,
        header_tail,
        body,
        body_framing,
        expect_continue,
        ..
    } = parsed;
    let head_request = request_line.starts_with(b"HEAD ");
    let mut request_headers = request_line;
    request_headers.extend_from_slice(&header_tail);
    let upgrade_request = headers_have_upgrade(&header_tail)?;
    if upgrade_request
        && !matches!(
            body_framing,
            RequestBodyFraming::None | RequestBodyFraming::Length(0)
        )
    {
        guest
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            )
            .await?;
        return Ok(());
    }
    let mut secrets_handler = (!secrets.secrets.is_empty()).then(|| {
        SecretsHandler::new_plain_http_proxy_dns(
            &secrets,
            &target.host,
            target.port,
            network_policy,
            shared.clone(),
        )
    });
    let outgoing_headers = match secrets_handler.as_mut() {
        Some(handler) => substitute_secret_bytes(handler, &request_headers, &shared)?,
        None => request_headers,
    };

    if upgrade_request {
        write_upstream_request_headers(&outgoing_headers, &mut upstream).await?;
        loop {
            let (response, status) = read_upstream_response_headers(&mut upstream).await?;
            if status == 101 {
                if !headers_have_upgrade(
                    &response[response
                        .windows(2)
                        .position(|bytes| bytes == b"\r\n")
                        .unwrap()
                        + 2..],
                )? {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "upstream returned 101 without upgrade headers",
                    ));
                }
                guest.write_all(&response).await?;
                break;
            }
            if status < 200 {
                guest.write_all(&response).await?;
                continue;
            }
            forward_rejected_upgrade(&mut upstream, &mut guest, &response, status, head_request)
                .await?;
            guest.shutdown().await?;
            return Ok(());
        }
        if !body.is_empty() {
            upstream.write_all(&body).await?;
        }
        upstream.flush().await?;
        // Once the upstream accepts the upgrade, both directions carry the upgraded protocol.
        tokio::io::copy_bidirectional(&mut guest, &mut upstream).await?;
        return Ok(());
    }

    let (mut guest_read, mut guest_write) = tokio::io::split(guest);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let mut headers_sent = !outgoing_headers.is_empty();
    if headers_sent {
        write_upstream_request_headers(&outgoing_headers, &mut upstream_write).await?;
    }
    if expect_continue {
        guest_write
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await?;
    }

    let mut response_started = false;
    let request_error = {
        let response_task = async {
            let mut buffer = [0; 16 * 1024];
            loop {
                let count = upstream_read.read(&mut buffer).await?;
                if count == 0 {
                    return guest_write.shutdown().await;
                }
                response_started = true;
                guest_write.write_all(&buffer[..count]).await?;
            }
        };
        tokio::pin!(response_task);
        let request_result = {
            let mut body_offset = 0;
            let request_task = forward_request_body(
                &mut guest_read,
                &body,
                &mut body_offset,
                body_framing,
                &mut secrets_handler,
                &mut headers_sent,
                &shared,
                &mut upstream_write,
            );
            tokio::pin!(request_task);
            tokio::select! {
                biased;
                request = &mut request_task => request,
                response = &mut response_task => return response,
            }
        };
        match request_result {
            Err(error)
                if !matches!(
                    error.kind(),
                    io::ErrorKind::BrokenPipe
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::NotConnected
                ) =>
            {
                Some(error)
            }
            _ => {
                let mut extra = [0; 1];
                tokio::select! {
                    biased;
                    result = guest_read.read(&mut extra) => {
                        if result? != 0 {
                            Some(io::Error::new(io::ErrorKind::InvalidData, PipelinedRequest))
                        } else {
                            response_task.await?;
                            None
                        }
                    }
                    response = &mut response_task => { response?; None }
                }
            }
        }
    };
    if let Some(error) = request_error {
        if !response_started
            && error
                .get_ref()
                .is_some_and(|source| source.is::<PipelinedRequest>())
        {
            guest_write
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                )
                .await?;
            guest_write.shutdown().await?;
        } else {
            return Err(error);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn forward_request_body<R, W>(
    guest: &mut R,
    initial: &[u8],
    initial_offset: &mut usize,
    framing: RequestBodyFraming,
    secrets_handler: &mut Option<SecretsHandler>,
    headers_sent: &mut bool,
    shared: &SharedState,
    upstream: &mut W,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match framing {
        RequestBodyFraming::None => {}
        RequestBodyFraming::Length(mut remaining) => {
            let mut buffer = [0u8; 16 * 1024];
            while remaining > 0 {
                let count = remaining.min(buffer.len());
                read_request_exact(guest, initial, initial_offset, &mut buffer[..count]).await?;
                forward_request_data(
                    &buffer[..count],
                    secrets_handler,
                    headers_sent,
                    shared,
                    upstream,
                )
                .await?;
                remaining -= count;
            }
        }
        RequestBodyFraming::Chunked => {
            let mut trailer_bytes = 0;
            'body: loop {
                let line = read_request_line(guest, initial, initial_offset).await?;
                let size_text = line
                    .strip_suffix(b"\r\n")
                    .unwrap_or(&line)
                    .split(|byte| *byte == b';')
                    .next()
                    .unwrap_or_default();
                let size = std::str::from_utf8(trim_ascii(size_text))
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP chunk size")
                    })
                    .and_then(|size| {
                        u64::from_str_radix(size, 16).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP chunk size")
                        })
                    })?;
                forward_request_data(&line, secrets_handler, headers_sent, shared, upstream)
                    .await?;
                if size == 0 {
                    loop {
                        let trailer = read_request_line(guest, initial, initial_offset).await?;
                        trailer_bytes += trailer.len();
                        if trailer_bytes > MAX_HEADERS {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "HTTP chunk trailers too large",
                            ));
                        }
                        forward_request_data(
                            &trailer,
                            secrets_handler,
                            headers_sent,
                            shared,
                            upstream,
                        )
                        .await?;
                        if trailer == b"\r\n" {
                            break 'body;
                        }
                    }
                }

                let mut remaining = usize::try_from(size).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "HTTP chunk size is too large")
                })?;
                let mut buffer = [0u8; 16 * 1024];
                while remaining > 0 {
                    let count = remaining.min(buffer.len());
                    read_request_exact(guest, initial, initial_offset, &mut buffer[..count])
                        .await?;
                    forward_request_data(
                        &buffer[..count],
                        secrets_handler,
                        headers_sent,
                        shared,
                        upstream,
                    )
                    .await?;
                    remaining -= count;
                }
                let mut terminator = [0u8; 2];
                read_request_exact(guest, initial, initial_offset, &mut terminator).await?;
                if terminator != *b"\r\n" {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid HTTP chunk terminator",
                    ));
                }
                forward_request_data(&terminator, secrets_handler, headers_sent, shared, upstream)
                    .await?;
            }
        }
    }
    if !*headers_sent {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secret handler did not produce a complete HTTP request",
        ));
    }
    let mut extra = [0; 1];
    if *initial_offset < initial.len()
        || guest
            .read(&mut extra)
            .now_or_never()
            .transpose()?
            .is_some_and(|count| count > 0)
    {
        return Err(io::Error::new(io::ErrorKind::InvalidData, PipelinedRequest));
    }
    upstream.flush().await?;
    upstream.shutdown().await
}

async fn read_upstream_response_headers<R>(upstream: &mut R) -> io::Result<(Vec<u8>, u16)>
where
    R: AsyncRead + Unpin,
{
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            if headers.len() >= MAX_HEADERS {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "upstream response headers too large",
                ));
            }
            headers.push(upstream.read_u8().await?);
        }
        let line_end = headers
            .windows(2)
            .position(|bytes| bytes == b"\r\n")
            .unwrap();
        let status_line = std::str::from_utf8(&headers[..line_end]).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid upstream status line")
        })?;
        let mut fields = status_line.split_ascii_whitespace();
        let version = fields.next().unwrap_or_default();
        let status = fields
            .next()
            .and_then(|value| value.parse::<u16>().ok())
            .filter(|status| (100..600).contains(status));
        if !matches!(version, "HTTP/1.0" | "HTTP/1.1") || status.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid upstream status line",
            ));
        }
        Ok((headers, status.unwrap()))
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "timed out reading upstream response headers",
        )
    })?
}

async fn forward_rejected_upgrade<R, W>(
    upstream: &mut R,
    guest: &mut W,
    response: &[u8],
    status: u16,
    head_request: bool,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let line_end = response
        .windows(2)
        .position(|bytes| bytes == b"\r\n")
        .unwrap()
        + 2;
    let headers = &response[line_end..];
    let framing = parse_response_body_framing(headers, status, head_request)?;
    let has_transfer_encoding = headers.split(|byte| *byte == b'\n').any(|line| {
        line.split(|byte| *byte == b':')
            .next()
            .is_some_and(|name| name.eq_ignore_ascii_case(b"transfer-encoding"))
    });
    guest.write_all(&response[..line_end]).await?;
    for line in headers.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let name = line.split(|byte| *byte == b':').next().unwrap_or_default();
        if !name.eq_ignore_ascii_case(b"connection")
            && !name.eq_ignore_ascii_case(b"proxy-connection")
            && !(has_transfer_encoding && name.eq_ignore_ascii_case(b"content-length"))
        {
            guest.write_all(line).await?;
            guest.write_all(b"\r\n").await?;
        }
    }
    guest.write_all(b"Connection: close\r\n\r\n").await?;
    match framing {
        ResponseBodyFraming::None => {}
        ResponseBodyFraming::CloseDelimited => {
            tokio::io::copy(upstream, guest).await?;
        }
        ResponseBodyFraming::Length(length) => {
            let count = tokio::io::copy(&mut upstream.take(length), guest).await?;
            if count != length {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incomplete upstream response body",
                ));
            }
        }
        ResponseBodyFraming::Chunked => {
            let mut trailer_bytes = 0;
            loop {
                let line = read_request_line(upstream, &[], &mut 0).await?;
                let size_text = line[..line.len() - 2]
                    .split(|byte| *byte == b';')
                    .next()
                    .unwrap_or_default();
                let size = std::str::from_utf8(size_text)
                    .ok()
                    .and_then(|text| u64::from_str_radix(text, 16).ok())
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid upstream chunk size")
                    })?;
                guest.write_all(&line).await?;
                if size == 0 {
                    loop {
                        let trailer = read_request_line(upstream, &[], &mut 0).await?;
                        trailer_bytes += trailer.len();
                        if trailer_bytes > MAX_HEADERS {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "upstream trailers too large",
                            ));
                        }
                        guest.write_all(&trailer).await?;
                        if trailer == b"\r\n" {
                            return Ok(());
                        }
                    }
                }
                let count = tokio::io::copy(&mut (&mut *upstream).take(size), guest).await?;
                if count != size {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "incomplete upstream chunk",
                    ));
                }
                let mut terminator = [0; 2];
                upstream.read_exact(&mut terminator).await?;
                if terminator != *b"\r\n" {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid upstream chunk terminator",
                    ));
                }
                guest.write_all(&terminator).await?;
            }
        }
    }
    Ok(())
}

fn parse_response_body_framing(
    headers: &[u8],
    status: u16,
    head_request: bool,
) -> io::Result<ResponseBodyFraming> {
    // RFC 9112 section 6.3: bodyless responses take precedence over framing
    // fields. A response's final non-chunked transfer coding is delimited by
    // connection close, unlike a request, which must be rejected in that case.
    if head_request || (100..200).contains(&status) || matches!(status, 204 | 304) {
        return Ok(ResponseBodyFraming::None);
    }
    let mut content_lengths = Vec::new();
    let mut transfer_codings = Vec::new();
    for line in headers.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let colon = line.iter().position(|byte| *byte == b':').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed upstream response header",
            )
        })?;
        let name = &line[..colon];
        let value = trim_ascii(&line[colon + 1..]);
        if name.eq_ignore_ascii_case(b"content-length") {
            content_lengths.push(value);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            let value = std::str::from_utf8(value).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid response Transfer-Encoding",
                )
            })?;
            for coding in value.split(',') {
                let coding = coding.trim();
                if coding.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "empty response transfer coding",
                    ));
                }
                transfer_codings.push(coding);
            }
        }
    }
    if let Some(final_coding) = transfer_codings.last() {
        if transfer_codings
            .iter()
            .filter(|coding| coding.eq_ignore_ascii_case("chunked"))
            .count()
            > 1
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunked cannot be applied more than once to a response",
            ));
        }
        return Ok(if final_coding.eq_ignore_ascii_case("chunked") {
            ResponseBodyFraming::Chunked
        } else {
            ResponseBodyFraming::CloseDelimited
        });
    }
    let mut length = None;
    for value in content_lengths {
        let value = std::str::from_utf8(value).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid response Content-Length",
            )
        })?;
        for value in value.split(',') {
            let value = value.trim();
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid response Content-Length",
                ));
            }
            let parsed = value.parse::<u64>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid response Content-Length",
                )
            })?;
            if length.is_some_and(|previous| previous != parsed) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "conflicting response Content-Length headers",
                ));
            }
            length = Some(parsed);
        }
    }
    Ok(length.map_or(
        ResponseBodyFraming::CloseDelimited,
        ResponseBodyFraming::Length,
    ))
}

async fn forward_request_data<W>(
    data: &[u8],
    secrets_handler: &mut Option<SecretsHandler>,
    headers_sent: &mut bool,
    shared: &SharedState,
    upstream: &mut W,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let output = match secrets_handler.as_mut() {
        Some(handler) => substitute_secret_bytes(handler, data, shared)?,
        None => data.to_vec(),
    };
    if output.is_empty() {
        return Ok(());
    }
    if !*headers_sent {
        let parsed = parse_request(&output)?;
        write_upstream_request_headers(&output, upstream).await?;
        upstream.write_all(&parsed.body).await?;
        *headers_sent = true;
    } else {
        upstream.write_all(&output).await?;
    }
    Ok(())
}

async fn write_upstream_request_headers<W>(request: &[u8], upstream: &mut W) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let parsed = parse_request(request)?;
    let authority_host = if parsed.target.host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{}]", parsed.target.host)
    } else {
        parsed.target.host.clone()
    };
    let authority = format!("{authority_host}:{}", parsed.target.port);
    let absolute_uri = format!("http://{authority}{}", parsed.target.path);
    upstream
        .write_all(&rewrite_request_line(&parsed.request_line, &absolute_uri)?)
        .await?;
    upstream
        .write_all(&upstream_request_headers(&parsed.header_tail, &authority)?)
        .await?;
    upstream.flush().await
}

fn headers_have_upgrade(headers: &[u8]) -> io::Result<bool> {
    let mut connection_upgrade = false;
    let mut upgrade_header = false;
    for line in headers
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .filter(|line| !line.is_empty())
    {
        let colon = line.iter().position(|byte| *byte == b':').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "malformed HTTP proxy header")
        })?;
        let name = &line[..colon];
        let value = trim_ascii(&line[colon + 1..]);
        if name.eq_ignore_ascii_case(b"connection")
            && value
                .split(|byte| *byte == b',')
                .map(trim_ascii)
                .any(|option| option.eq_ignore_ascii_case(b"upgrade"))
        {
            connection_upgrade = true;
        } else if name.eq_ignore_ascii_case(b"upgrade") && !value.is_empty() {
            upgrade_header = true;
        }
    }
    Ok(connection_upgrade && upgrade_header)
}

fn substitute_secret_bytes(
    handler: &mut SecretsHandler,
    data: &[u8],
    shared: &SharedState,
) -> io::Result<Vec<u8>> {
    match handler.substitute(data) {
        Ok(output) => Ok(output.into_owned()),
        Err(action) => {
            if matches!(action, SecretViolationAction::BlockAndTerminate) {
                shared.trigger_termination();
            }
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "secret violation: request blocked by secret policy",
            ))
        }
    }
}

fn hostname_allowed(
    host: &str,
    port: u16,
    network_policy: &NetworkPolicy,
    platform_policy: Option<&NetworkPolicy>,
    protocol: Protocol,
    shared: &SharedState,
) -> bool {
    let policies = [Some(network_policy), platform_policy];
    if let Ok(address) = host.parse::<IpAddr>() {
        return policies.into_iter().flatten().all(|policy| {
            policy
                .evaluate_egress(SocketAddr::new(address, port), protocol, shared)
                .is_allow()
        });
    }

    !policies.into_iter().flatten().any(|policy| {
        !policy
            .evaluate_proxy_hostname(host, protocol, port)
            .is_allow()
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_tls_mitm<S>(
    guest: S,
    upstream: TcpStream,
    hostname: String,
    port: u16,
    initial_buf: Vec<u8>,
    network_policy: Arc<NetworkPolicy>,
    tls_state: Arc<TlsState>,
    strict: bool,
    shared: Arc<SharedState>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let literal_address = hostname.parse::<IpAddr>().ok();
    let guest_dst = SocketAddr::new(
        literal_address.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port,
    );
    let proxy_connect = Arc::new(ProxyConnectState::new());
    proxy_connect.mark_connected();
    let (guest_tx, guest_rx) = mpsc::channel(32);
    let (proxy_tx, mut proxy_rx) = mpsc::channel(32);
    let mut proxy = TlsProxy::new(
        guest_dst,
        UpstreamTcpTarget::direct(guest_dst),
        guest_rx,
        proxy_tx,
        shared,
        tls_state,
        network_policy,
        strict,
        proxy_connect,
        None,
    )
    .with_upstream(upstream)
    .with_initial_buf(initial_buf);
    proxy = if literal_address.is_some() {
        proxy.with_proxy_dns_address()
    } else {
        proxy
            .with_expected_sni(Some(hostname))
            .with_proxy_dns_hostname()
    };

    let (mut guest_read, mut guest_write) = tokio::io::split(guest);
    let input_task = tokio::spawn(async move {
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let count = guest_read.read(&mut buffer).await?;
            if count == 0 {
                return Ok::<(), io::Error>(());
            }
            if guest_tx
                .send(Bytes::copy_from_slice(&buffer[..count]))
                .await
                .is_err()
            {
                return Ok(());
            }
        }
    });
    let output_task = tokio::spawn(async move {
        while let Some(bytes) = proxy_rx.recv().await {
            guest_write.write_all(&bytes).await?;
        }
        guest_write.shutdown().await
    });
    let mut proxy_task = tokio::spawn(proxy.try_run());
    let mut output_task = output_task;
    let result = tokio::select! {
        proxy_result = &mut proxy_task => {
            input_task.abort();
            // Drain already-produced TLS output before closing the guest.
            let output_result = output_task.await;
            proxy_result.map_err(io::Error::other).and_then(|result| result)
                .and(output_result.map_err(io::Error::other).and_then(|result| result))
        }
        output_result = &mut output_task => {
            match output_result {
                Ok(Ok(())) => {
                    // A clean output EOF means the TLS proxy dropped its sender.
                    proxy_task.await.map_err(io::Error::other).and_then(|result| result)
                }
                result => {
                    proxy_task.abort();
                    let _ = proxy_task.await;
                    result.map_err(io::Error::other).and_then(|result| result)
                }
            }
        }
    };
    input_task.abort();
    let _ = input_task.await;
    result
}

async fn read_headers<S>(stream: &mut S) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
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
        if let Some(header_end) = data.windows(4).position(|window| window == b"\r\n\r\n") {
            if header_end + 4 > MAX_HEADERS {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "proxy request headers too large",
                ));
            }
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
        if url.scheme() != "http" {
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
            })?;
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host)
            .to_string();
        let port = url.port_or_known_default().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "request target has no port")
        })?;
        if port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid request target port",
            ));
        }
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

    let header_tail = data[line_end + 2..end].to_vec();
    let (body_framing, expect_continue) = if connect {
        (RequestBodyFraming::None, false)
    } else {
        parse_request_body_framing(&header_tail)?
    };
    Ok(ParsedRequest {
        connect,
        target,
        request_line: data[..line_end + 2].to_vec(),
        header_tail,
        body: data[end..].to_vec(),
        body_framing,
        expect_continue,
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
    if host.is_empty() || (host.contains(':') && host.parse::<std::net::Ipv6Addr>().is_err()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid proxy authority host",
        ));
    }
    let host = if let Ok(address) = host.parse::<IpAddr>() {
        address.to_string()
    } else {
        let url = url::Url::parse(&format!("http://{host}/")).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid proxy authority host")
        })?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid proxy authority host",
            ));
        }
        url.host_str()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "proxy authority has no host")
            })?
            .trim_end_matches('.')
            .to_string()
    };
    let port = port
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid proxy authority port"))?;
    if port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid proxy authority port",
        ));
    }
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

fn upstream_request_headers(headers: &[u8], authority: &str) -> io::Result<Vec<u8>> {
    let (framing, _) = parse_request_body_framing(headers)?;
    let mut rewritten = Vec::with_capacity(headers.len() + authority.len() + 32);
    let lines = headers
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let upgrade = headers_have_upgrade(headers)?;
    let mut connection_options = Vec::new();
    let mut transfer_encoding = None;
    for line in &lines {
        let colon = line.iter().position(|byte| *byte == b':').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "malformed HTTP proxy header")
        })?;
        let name = &line[..colon];
        if name.eq_ignore_ascii_case(b"transfer-encoding") {
            transfer_encoding = Some(trim_ascii(&line[colon + 1..]));
        }
        if name.eq_ignore_ascii_case(b"connection")
            || name.eq_ignore_ascii_case(b"proxy-connection")
        {
            connection_options.extend(
                line[colon + 1..]
                    .split(|byte| *byte == b',')
                    .map(trim_ascii)
                    .map(|option| {
                        option
                            .iter()
                            .map(|byte| byte.to_ascii_lowercase())
                            .collect::<Vec<_>>()
                    }),
            );
        }
    }
    rewritten.extend_from_slice(b"Host: ");
    rewritten.extend_from_slice(authority.as_bytes());
    rewritten.extend_from_slice(b"\r\n");
    for line in lines {
        let colon = line.iter().position(|byte| *byte == b':').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "malformed HTTP proxy header")
        })?;
        let name = &line[..colon];
        if name.eq_ignore_ascii_case(b"host")
            || name.eq_ignore_ascii_case(b"content-length")
            || name.eq_ignore_ascii_case(b"transfer-encoding")
            || name.eq_ignore_ascii_case(b"connection")
            || name.eq_ignore_ascii_case(b"proxy-connection")
            || name.eq_ignore_ascii_case(b"proxy-authorization")
            || name.eq_ignore_ascii_case(b"expect")
            || name.eq_ignore_ascii_case(b"keep-alive")
            || name.eq_ignore_ascii_case(b"te")
            || (name.eq_ignore_ascii_case(b"upgrade") && !upgrade)
            || connection_options.iter().any(|option| {
                name.eq_ignore_ascii_case(option)
                    && !(upgrade && option.eq_ignore_ascii_case(b"upgrade"))
            })
        {
            continue;
        }
        rewritten.extend_from_slice(line);
        rewritten.extend_from_slice(b"\r\n");
    }
    // Regenerate framing after removing hop-by-hop fields. The forwarded body
    // must have the same boundaries even if Connection nominated these fields.
    match framing {
        RequestBodyFraming::None => {}
        RequestBodyFraming::Length(length) => {
            rewritten.extend_from_slice(format!("Content-Length: {length}\r\n").as_bytes());
        }
        RequestBodyFraming::Chunked => {
            rewritten.extend_from_slice(b"Transfer-Encoding: ");
            rewritten.extend_from_slice(
                transfer_encoding.expect("chunked request framing requires Transfer-Encoding"),
            );
            rewritten.extend_from_slice(b"\r\n");
        }
    }
    if upgrade {
        rewritten.extend_from_slice(b"Connection: Upgrade\r\n\r\n");
    } else {
        rewritten.extend_from_slice(b"Connection: close\r\n\r\n");
    }
    Ok(rewritten)
}

fn parse_request_body_framing(headers: &[u8]) -> io::Result<(RequestBodyFraming, bool)> {
    let mut content_length = None;
    let mut transfer_encoding = None;
    let mut expect_continue = false;
    for line in headers.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let colon = line.iter().position(|byte| *byte == b':').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "malformed HTTP proxy header")
        })?;
        let name = &line[..colon];
        let value = trim_ascii(&line[colon + 1..]);
        if name.eq_ignore_ascii_case(b"content-length") {
            let value = std::str::from_utf8(value).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid Content-Length header")
            })?;
            for value in value.split(',') {
                let value = value.trim();
                if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid Content-Length header",
                    ));
                }
                let length = value.parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid Content-Length header")
                })?;
                if content_length.is_some_and(|previous| previous != length) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "conflicting Content-Length headers",
                    ));
                }
                content_length = Some(length);
            }
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            if transfer_encoding.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "multiple Transfer-Encoding headers are unsupported",
                ));
            }
            let value = std::str::from_utf8(value).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid Transfer-Encoding header",
                )
            })?;
            transfer_encoding = Some(value.to_ascii_lowercase());
        } else if name.eq_ignore_ascii_case(b"expect") {
            if !value.eq_ignore_ascii_case(b"100-continue") {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported HTTP expectation",
                ));
            }
            expect_continue = true;
        }
    }

    if content_length.is_some() && transfer_encoding.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "request cannot combine Content-Length and Transfer-Encoding",
        ));
    }
    let framing = if let Some(encoding) = transfer_encoding {
        if !encoding
            .split(',')
            .next_back()
            .is_some_and(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported HTTP request Transfer-Encoding",
            ));
        }
        RequestBodyFraming::Chunked
    } else if let Some(length) = content_length {
        RequestBodyFraming::Length(length)
    } else {
        RequestBodyFraming::None
    };
    if expect_continue
        && matches!(
            framing,
            RequestBodyFraming::None | RequestBodyFraming::Length(0)
        )
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "100-continue requires a framed HTTP request body",
        ));
    }
    Ok((framing, expect_continue))
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(|byte| byte.is_ascii_whitespace()) {
        value = &value[1..];
    }
    while value.last().is_some_and(|byte| byte.is_ascii_whitespace()) {
        value = &value[..value.len() - 1];
    }
    value
}

async fn read_request_line<S>(
    guest: &mut S,
    initial: &[u8],
    initial_offset: &mut usize,
) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut line = Vec::with_capacity(128);
    loop {
        let byte = if *initial_offset < initial.len() {
            let byte = initial[*initial_offset];
            *initial_offset += 1;
            byte
        } else {
            let mut byte = [0u8; 1];
            guest.read_exact(&mut byte).await?;
            byte[0]
        };
        line.push(byte);
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
        if line.len() >= MAX_HEADERS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP chunk header too large",
            ));
        }
    }
}

async fn read_request_exact<S>(
    guest: &mut S,
    initial: &[u8],
    initial_offset: &mut usize,
    output: &mut [u8],
) -> io::Result<()>
where
    S: AsyncRead + Unpin,
{
    let mut offset = 0;
    if *initial_offset < initial.len() {
        let count = output.len().min(initial.len() - *initial_offset);
        output[..count].copy_from_slice(&initial[*initial_offset..*initial_offset + count]);
        *initial_offset += count;
        offset += count;
    }
    if offset < output.len() {
        guest.read_exact(&mut output[offset..]).await?;
    }
    Ok(())
}

#[cfg(test)]
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

#[cfg(test)]
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
mod regression_tests;

#[cfg(test)]
mod tls_regression_tests;

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
    async fn upstream_connect_writes_destination_target() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_headers(&mut stream).await.unwrap();
            assert!(request.starts_with(b"CONNECT 203.0.113.10:443 HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
        });

        let proxy = format!("http://{address}");
        let (_stream, initial) = connect_upstream(&proxy, "203.0.113.10", 443).await.unwrap();
        assert!(initial.is_empty());
        task.await.unwrap();
    }
}
