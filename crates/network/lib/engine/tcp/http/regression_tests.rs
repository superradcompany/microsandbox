//! Regression coverage for the guest-facing HTTP proxy.

use tokio::net::TcpListener;

use super::*;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn start_proxy() -> (
    tokio::io::DuplexStream,
    TcpListener,
    tokio::task::JoinHandle<io::Result<()>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (client, server) = tokio::io::duplex(128 * 1024);
    let policy = serde_json::from_value(serde_json::json!({
        "default_egress": "deny",
        "default_ingress": "allow",
        "rules": [{
            "direction": "egress",
            "destination": { "domain": "example.com" },
            "action": "allow",
        }],
    }))
    .unwrap();
    let task = tokio::spawn(serve(
        server,
        address,
        Arc::new(policy),
        None,
        None,
        Arc::new(SecretsConfig::default()),
        true,
        Arc::new(SharedState::new(32)),
    ));
    (client, listener, task)
}

async fn ordinary_response(request: Vec<u8>) -> Vec<u8> {
    let (mut client, listener, proxy) = start_proxy().await;
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut forwarded = Vec::new();
        stream.read_to_end(&mut forwarded).await.unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    });
    client.write_all(&request).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    proxy.await.unwrap().unwrap();
    upstream.abort();
    response
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn checked_host_replaces_duplicate_client_hosts() {
    for authority in ["example.com:80", "example.com:8080", "[2001:db8::1]:8080"] {
        let output = upstream_request_headers(
            b"Host: wrong.example\r\nhOsT: another.example\r\nConnection: Host\r\n\r\n",
            authority,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();
        assert_eq!(
            text.lines()
                .filter(|line| line.to_ascii_lowercase().starts_with("host:"))
                .count(),
            1
        );
        assert!(text.contains(&format!("Host: {authority}\r\n")));
        assert!(!text.contains("wrong.example"));
        assert!(!text.contains("another.example"));
    }
}

#[test]
fn forwarded_headers_regenerate_body_framing() {
    for connection in ["Connection", "Proxy-Connection"] {
        let headers = format!(
            "Host: wrong.example\r\n{connection}: Content-Length, X-Hop\r\nContent-Length: 4, 4\r\nContent-Length: 4\r\nX-Hop: drop\r\n\r\n"
        );
        let output = upstream_request_headers(headers.as_bytes(), "example.com:80").unwrap();
        let text = String::from_utf8(output.clone()).unwrap();
        assert!(matches!(
            parse_request_body_framing(&output).unwrap().0,
            RequestBodyFraming::Length(4)
        ));
        assert_eq!(text.matches("Content-Length:").count(), 1);
        assert!(!text.contains("X-Hop:"));
        assert!(text.contains("Host: example.com:80\r\n"));
        for encoding in ["chunked", "gzip, chunked"] {
            let headers =
                format!("{connection}: Transfer-Encoding\r\nTransfer-Encoding: {encoding}\r\n\r\n");
            let output = upstream_request_headers(headers.as_bytes(), "example.com:80").unwrap();
            assert!(matches!(
                parse_request_body_framing(&output).unwrap().0,
                RequestBodyFraming::Chunked
            ));
            assert!(
                String::from_utf8(output)
                    .unwrap()
                    .contains(&format!("Transfer-Encoding: {encoding}\r\n"))
            );
        }
    }
}

#[tokio::test]
async fn connection_options_preserve_forwarded_body_boundaries() {
    let payload = b"GET http://blocked.example/ HTTP/1.1\r\nHost: blocked.example\r\n\r\n";
    for connection in ["Connection", "Proxy-Connection"] {
        for chunked in [false, true] {
            let (mut client, listener, proxy) = start_proxy().await;
            let upstream = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut forwarded = Vec::new();
                stream.read_to_end(&mut forwarded).await.unwrap();
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
                forwarded
            });
            let (field, value, body) = if chunked {
                let mut body = format!("{:x}\r\n", payload.len()).into_bytes();
                body.extend_from_slice(payload);
                body.extend_from_slice(b"\r\n0\r\n\r\n");
                ("Transfer-Encoding", "chunked".to_string(), body)
            } else {
                (
                    "Content-Length",
                    payload.len().to_string(),
                    payload.to_vec(),
                )
            };
            let mut request = format!("POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\n{connection}: {field}\r\n{field}: {value}\r\n\r\n").into_bytes();
            request.extend_from_slice(&body);
            client.write_all(&request).await.unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert!(response.starts_with(b"HTTP/1.1 200"));
            proxy.await.unwrap().unwrap();
            let forwarded = parse_request(&upstream.await.unwrap()).unwrap();
            assert_eq!(forwarded.target.host, "example.com");
            assert_eq!(forwarded.body, body);
            assert!(if chunked {
                matches!(forwarded.body_framing, RequestBodyFraming::Chunked)
            } else {
                matches!(forwarded.body_framing, RequestBodyFraming::Length(length) if length == payload.len())
            });
        }
    }
}

#[tokio::test]
async fn coalesced_bodyless_pipeline_is_rejected() {
    let (mut client, _listener, proxy) = start_proxy().await;
    client.write_all(b"GET http://example.com/first HTTP/1.1\r\nHost: example.com\r\n\r\nGET http://example.com/second HTTP/1.1\r\nHost: example.com\r\n\r\n").await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 400"));
    proxy.await.unwrap().unwrap();
}

#[tokio::test]
async fn pipeline_after_framed_body_is_rejected() {
    let response = ordinary_response(b"POST http://example.com/first HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\n\r\nXGET http://example.com/second HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec()).await;
    assert!(
        response.starts_with(b"HTTP/1.1 400"),
        "received: {}",
        String::from_utf8_lossy(&response)
    );
}

#[tokio::test]
async fn pipeline_across_header_read_boundary_is_rejected() {
    let prefix = "GET http://example.com/first HTTP/1.1\r\nHost: example.com\r\nX-Pad: ";
    let suffix = "\r\n\r\n";
    let mut request = format!(
        "{prefix}{}{suffix}",
        "x".repeat(4096 - prefix.len() - suffix.len())
    )
    .into_bytes();
    assert_eq!(request.len(), 4096);
    request
        .extend_from_slice(b"GET http://example.com/second HTTP/1.1\r\nHost: example.com\r\n\r\n");
    let response = ordinary_response(request).await;
    assert!(
        response.starts_with(b"HTTP/1.1 400"),
        "received: {}",
        String::from_utf8_lossy(&response)
    );
}

#[tokio::test]
async fn successful_upgrade_relays_both_directions() {
    let (mut client, listener, proxy) = start_proxy().await;
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let headers = read_headers(&mut stream).await.unwrap();
        let text = String::from_utf8(headers).unwrap();
        assert!(text.contains("Upgrade: websocket\r\n"));
        assert!(text.contains("Connection: Upgrade\r\n"));
        stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n").await.unwrap();
        let mut ping = [0; 4];
        stream.read_exact(&mut ping).await.unwrap();
        assert_eq!(&ping, b"ping");
        stream.write_all(b"pong").await.unwrap();
        stream.shutdown().await.unwrap();
    });
    client.write_all(b"GET http://example.com/ws HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").await.unwrap();
    let response = tokio::time::timeout(Duration::from_secs(3), read_headers(&mut client))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 101"));
    client.write_all(b"ping").await.unwrap();
    let mut pong = [0; 4];
    tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut pong))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&pong, b"pong");
    client.shutdown().await.unwrap();
    upstream.await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), proxy)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn rejected_upgrade_does_not_relay_unchecked_followup() {
    let (mut client, listener, proxy) = start_proxy().await;
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = read_headers(&mut stream).await.unwrap();
        stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let mut followup = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut followup))
            .await
            .unwrap()
            .unwrap();
        followup
    });
    client.write_all(b"GET http://example.com/ws HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").await.unwrap();
    let response = tokio::time::timeout(Duration::from_secs(3), read_headers(&mut client))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 400"));
    let _ = client
        .write_all(b"GET http://blocked.example/ HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
        .await;
    let _ = client.shutdown().await;
    let forwarded = upstream.await.unwrap();
    proxy.abort();
    assert!(
        forwarded.is_empty(),
        "unchecked followup forwarded after failed upgrade: {}",
        String::from_utf8_lossy(&forwarded)
    );
}

#[tokio::test]
async fn upgrade_detection_preserves_buffered_secret_uploads() {
    use crate::secrets::config::{HostPattern, SecretEntry, SecretSubstitution};
    let config = SecretsConfig {
        secrets: vec![SecretEntry {
            env_var: "API_KEY".into(),
            value: zeroize::Zeroizing::new("real-value".into()),
            source: None,
            placeholder: "$TOKEN".into(),
            allowed_hosts: vec![HostPattern::Any],
            substitution: SecretSubstitution {
                headers: false,
                query: false,
                body: true,
            },
            passthrough_hosts: Vec::new(),
            violation_action: None,
            require_tls_identity: false,
        }],
        ..Default::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (mut client, server) = tokio::io::duplex(128 * 1024);
    let proxy = tokio::spawn(serve(
        server,
        address,
        Arc::new(NetworkPolicy::allow_all()),
        None,
        None,
        Arc::new(config),
        true,
        Arc::new(SharedState::new(32)),
    ));
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await.unwrap();
        if !request.is_empty() {
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        }
        request
    });
    client.write_all(b"POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\n\r\n$TOKEN").await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let result = proxy.await.unwrap();
    let request = upstream.await.unwrap();
    assert!(
        result.is_ok(),
        "buffered secret request rejected before body forwarding: {result:?}; forwarded {} bytes",
        request.len()
    );
    assert!(String::from_utf8_lossy(&request).contains("real-value"));
}

#[tokio::test]
async fn pipeline_after_chunked_body_is_rejected() {
    let response = ordinary_response(b"POST http://example.com/first HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nX\r\n0\r\n\r\nGET http://example.com/second HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec()).await;
    assert!(response.starts_with(b"HTTP/1.1 400"));
}

#[tokio::test]
async fn followup_while_waiting_for_response_is_rejected() {
    let (mut client, listener, proxy) = start_proxy().await;
    let (request_done_tx, request_done_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await.unwrap();
        request_done_tx.send(request).unwrap();
        let _ = release_rx.await;
    });
    client
        .write_all(b"GET http://example.com/first HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let forwarded = tokio::time::timeout(Duration::from_secs(3), request_done_rx)
        .await
        .unwrap()
        .unwrap();
    assert!(!String::from_utf8_lossy(&forwarded).contains("second"));
    client
        .write_all(b"GET http://example.com/second HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 400"));
    proxy.await.unwrap().unwrap();
    drop(release_tx);
    upstream.await.unwrap();
}

#[tokio::test]
async fn early_upload_rejection_is_returned_without_waiting_for_body() {
    let (mut client, listener, proxy) = start_proxy().await;
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_headers(&mut stream).await.unwrap();
        assert!(request.starts_with(b"POST http://example.com:80/upload"));
        stream
            .write_all(
                b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
    });
    client.write_all(b"POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 100000\r\n\r\nX").await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 413"));
    proxy.await.unwrap().unwrap();
    upstream.await.unwrap();
}

#[tokio::test]
async fn upgrade_waits_for_101_and_preserves_coalesced_data() {
    let (mut client, listener, proxy) = start_proxy().await;
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_headers(&mut stream).await.unwrap();
        assert!(
            parse_request(&request).unwrap().body.is_empty(),
            "upgrade bytes were forwarded before 101"
        );
        stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\npong").await.unwrap();
        let mut ping = [0; 4];
        stream.read_exact(&mut ping).await.unwrap();
        assert_eq!(&ping, b"ping");
        stream.shutdown().await.unwrap();
    });
    client.write_all(b"GET http://example.com/ws HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nping").await.unwrap();
    let response = tokio::time::timeout(
        Duration::from_secs(3),
        read_upstream_response_headers(&mut client),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.1, 100);
    let response = tokio::time::timeout(
        Duration::from_secs(3),
        read_upstream_response_headers(&mut client),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.1, 101);
    let mut pong = [0; 4];
    tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut pong))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&pong, b"pong");
    client.shutdown().await.unwrap();
    upstream.await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), proxy)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn rejected_upgrade_chunked_response_finishes_without_upstream_eof() {
    let (mut client, listener, proxy) = start_proxy().await;
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_headers(&mut stream).await.unwrap();
        assert!(parse_request(&request).unwrap().body.is_empty());
        stream.write_all(b"HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n4\r\ndeny\r\n0\r\nX-Trailer: ok\r\n\r\n").await.unwrap();
        let mut followup = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut followup))
            .await
            .unwrap()
            .unwrap();
        assert!(followup.is_empty());
    });
    client.write_all(b"GET http://example.com/ws HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nGET http://blocked.example/ HTTP/1.1\r\nHost: blocked.example\r\n\r\n").await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 403"));
    assert!(response.ends_with(b"4\r\ndeny\r\n0\r\nX-Trailer: ok\r\n\r\n"));
    assert!(String::from_utf8_lossy(&response).contains("Connection: close\r\n"));
    proxy.await.unwrap().unwrap();
    upstream.await.unwrap();
}

#[test]
fn response_framing_uses_final_transfer_coding() {
    for (headers, expected) in [
        (b"\r\n".as_slice(), ResponseBodyFraming::CloseDelimited),
        (b"Content-Length: 7\r\n\r\n", ResponseBodyFraming::Length(7)),
        (
            b"Content-Length: 7, 7\r\nContent-Length: 7\r\n\r\n",
            ResponseBodyFraming::Length(7),
        ),
        (
            b"Transfer-Encoding: chunked\r\n\r\n",
            ResponseBodyFraming::Chunked,
        ),
        (
            b"Transfer-Encoding: gzip, chunked\r\n\r\n",
            ResponseBodyFraming::Chunked,
        ),
        (
            b"Transfer-Encoding: gzip\r\n\r\n",
            ResponseBodyFraming::CloseDelimited,
        ),
        (
            b"Transfer-Encoding: chunked, gzip\r\n\r\n",
            ResponseBodyFraming::CloseDelimited,
        ),
        (
            b"Transfer-Encoding: Chunked\r\nTransfer-Encoding: GZip\r\n\r\n",
            ResponseBodyFraming::CloseDelimited,
        ),
        (
            b"Transfer-Encoding: gzip\r\nContent-Length: nonsense\r\n\r\n",
            ResponseBodyFraming::CloseDelimited,
        ),
    ] {
        assert_eq!(
            parse_response_body_framing(headers, 403, false).unwrap(),
            expected
        );
    }
    for status in [100, 204, 304] {
        assert_eq!(
            parse_response_body_framing(
                b"Transfer-Encoding: gzip\r\nContent-Length: 123\r\n\r\n",
                status,
                false
            )
            .unwrap(),
            ResponseBodyFraming::None
        );
    }
    assert_eq!(
        parse_response_body_framing(b"Transfer-Encoding: gzip\r\n\r\n", 403, true).unwrap(),
        ResponseBodyFraming::None
    );
    for headers in [
        b"Transfer-Encoding: chunked, chunked\r\n\r\n".as_slice(),
        b"Transfer-Encoding: chunked, gzip, chunked\r\n\r\n",
        b"Content-Length: 1\r\nContent-Length: 2\r\n\r\n",
    ] {
        assert!(parse_response_body_framing(headers, 403, false).is_err());
    }
    // Requests still require chunked to be the final transfer coding.
    assert!(parse_request_body_framing(b"Transfer-Encoding: chunked, gzip\r\n\r\n").is_err());
}

#[tokio::test]
async fn rejected_upgrade_forwards_close_delimited_transfer_codings() {
    // Deterministic gzip encodings of "refused" and "7\r\nrefused\r\n0\r\n\r\n".
    for (coding, body) in [
        ("gzip", b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff+JM+-NM\x01\x00|\xbe\xd3\xf0\x07\x00\x00\x00".as_slice()),
        ("chunked, gzip", b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff3\xe7\xe5*JM+-NM\xe1\xe52\xe0\xe5\xe2\xe5\x02\x00\x8bT\xcdz\x11\x00\x00\x00"),
    ] {
        let (mut client, listener, proxy) = start_proxy().await;
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_headers(&mut stream).await.unwrap();
            assert!(parse_request(&request).unwrap().body.is_empty());
            let response = format!("HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: {coding}\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n");
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut followup = Vec::new();
            stream.read_to_end(&mut followup).await.unwrap();
            assert!(followup.is_empty());
        });
        client.write_all(b"GET http://example.com/ws HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nGET http://blocked.example/ HTTP/1.1\r\nHost: blocked.example\r\n\r\n").await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut response)).await.unwrap().unwrap();
        assert!(response.starts_with(b"HTTP/1.1 403"));
        assert!(response.ends_with(body));
        let headers = &response[..response.windows(4).position(|bytes| bytes == b"\r\n\r\n").unwrap() + 4];
        let headers = String::from_utf8_lossy(headers);
        assert!(headers.contains(&format!("Transfer-Encoding: {coding}\r\n")));
        assert!(!headers.to_ascii_lowercase().contains("content-length:"));
        assert!(headers.contains("Connection: close\r\n"));
        proxy.await.unwrap().unwrap();
        upstream.await.unwrap();
    }
}

#[tokio::test]
async fn secret_policies_reject_upgrades_before_connecting_upstream() {
    use crate::secrets::config::{HostPattern, SecretEntry, SecretSubstitution};

    for action in [
        SecretViolationAction::Block,
        SecretViolationAction::BlockAndTerminate,
    ] {
        for buffered_payload in [false, true] {
            let secrets = SecretsConfig {
                secrets: vec![SecretEntry {
                    env_var: "API_KEY".into(),
                    value: zeroize::Zeroizing::new("real-value".into()),
                    source: None,
                    placeholder: "$TOKEN".into(),
                    allowed_hosts: vec![HostPattern::Exact("secret.example".into())],
                    substitution: SecretSubstitution::default(),
                    passthrough_hosts: Vec::new(),
                    violation_action: Some(action.clone()),
                    require_tls_identity: true,
                }],
                ..Default::default()
            };
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let (mut client, server) = tokio::io::duplex(128 * 1024);
            let proxy = tokio::spawn(serve(
                server,
                address,
                Arc::new(NetworkPolicy::allow_all()),
                None,
                None,
                Arc::new(secrets),
                true,
                Arc::new(SharedState::new(32)),
            ));
            let mut request = b"GET http://example.com/ws HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".to_vec();
            if buffered_payload {
                // A masked WebSocket text frame containing the forbidden placeholder.
                let mask = [1u8, 2, 3, 4];
                request.extend_from_slice(&[0x81, 0x86]);
                request.extend_from_slice(&mask);
                request.extend(
                    b"$TOKEN"
                        .iter()
                        .enumerate()
                        .map(|(index, byte)| byte ^ mask[index % 4]),
                );
            }
            client.write_all(&request).await.unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert!(response.starts_with(b"HTTP/1.1 403"));
            assert!(
                String::from_utf8_lossy(&response)
                    .contains("upgraded payloads cannot be checked for secret violations")
            );
            proxy.await.unwrap().unwrap();
            // A completed refusal must not have opened even an empty upstream tunnel.
            assert!(listener.accept().now_or_never().is_none());
            let _ = client.write_all(b"$TOKEN").await;
            assert!(listener.accept().now_or_never().is_none());
        }
    }
}
