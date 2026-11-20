//! Exercise cloud streaming timeouts through public SDK APIs against local HTTP responses.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use futures::{StreamExt, stream};
use reqwest::Method;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::task::AbortOnDropHandle;

use super::{RemoteContext, http::FileTransfer};
use crate::MicrosandboxError;
use crate::config::layers::BackendConfig;
use crate::logs::{LogCursor, LogStreamOptions};
use crate::volume::VolumeFs;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const REQUEST_TIMEOUT: Duration = Duration::from_millis(300);
const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const SANDBOX_ID: &str = "00000000-0000-0000-0000-000000000002";
const VOLUME_ID: &str = "00000000-0000-0000-0000-000000000003";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn backend(url: String) -> RemoteContext {
    RemoteContext::builder()
        .url(url)
        .api_key("test-key")
        .request_timeout(REQUEST_TIMEOUT)
        .config_sources(BackendConfig::new(Default::default(), Default::default()))
        .build()
        .unwrap()
}

fn sandbox_response() -> Value {
    json!({
        "id": SANDBOX_ID,
        "org_id": "00000000-0000-0000-0000-000000000001",
        "name": "stream-test",
        "slug": "stream-test",
        "status": "running",
        "ephemeral": false,
        "created_at": "2026-11-18T00:00:00Z"
    })
}

fn volume_response() -> Value {
    json!([{
        "id": VOLUME_ID,
        "name": "stream-test",
        "kind": "managed",
        "status": "active",
        "labels": {},
        "created_at": "2026-11-18T00:00:00Z",
        "updated_at": "2026-11-18T00:00:00Z"
    }])
}

async fn accept_request(listener: &TcpListener) -> (String, BufReader<TcpStream>) {
    let (stream, _) = listener.accept().await.unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    let target = line.split_whitespace().nth(1).unwrap().to_string();
    loop {
        line.clear();
        assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
        if line == "\r\n" {
            break;
        }
    }
    (target, reader)
}

async fn write_json(mut reader: BufReader<TcpStream>, body: Value) {
    let body = body.to_string();
    reader
        .get_mut()
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
}

async fn write_chunk(stream: &mut TcpStream, chunk: &[u8]) {
    stream
        .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
        .await
        .unwrap();
    stream.write_all(chunk).await.unwrap();
    stream.write_all(b"\r\n").await.unwrap();
    stream.flush().await.unwrap();
}

async fn read_chunked_body(reader: &mut BufReader<TcpStream>) -> Vec<u8> {
    let mut received = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let size = usize::from_str_radix(line.trim(), 16).unwrap();
        if size == 0 {
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            return received;
        }
        let start = received.len();
        received.resize(start + size, 0);
        reader.read_exact(&mut received[start..]).await.unwrap();
        reader.read_exact(&mut [0; 2]).await.unwrap();
    }
}

async fn serve_volume_lookup(listener: &TcpListener) {
    let (target, reader) = accept_request(listener).await;
    assert_eq!(target, "/v1/volumes");
    write_json(reader, volume_response()).await;
}

async fn serve_download(listener: &TcpListener, chunks: usize) {
    serve_volume_lookup(listener).await;
    let (target, mut reader) = accept_request(listener).await;
    assert_eq!(target, format!("/v1/volumes/{VOLUME_ID}/files/content"));
    reader
        .get_mut()
        .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
        .await
        .unwrap();
    for index in 0..chunks {
        write_chunk(reader.get_mut(), &[index as u8]).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    reader.get_mut().write_all(b"0\r\n\r\n").await.unwrap();
}

async fn collect_log_text(backend: &RemoteContext) -> Vec<String> {
    let options = LogStreamOptions {
        follow: true,
        ..Default::default()
    };
    let mut stream = backend.log_stream("stream-test", &options).await.unwrap();
    let mut entries = Vec::new();
    while let Some(entry) = stream.next().await {
        entries.push(String::from_utf8(entry.unwrap().data.to_vec()).unwrap());
    }
    entries
}

async fn serve_log_stream(listener: TcpListener, delays: Vec<Duration>) {
    let (target, reader) = accept_request(&listener).await;
    assert_eq!(target, "/v1/sandboxes/by-name/stream-test");
    write_json(reader, sandbox_response()).await;

    let (target, mut reader) = accept_request(&listener).await;
    assert_eq!(
        target,
        format!("/v1/sandboxes/{SANDBOX_ID}/logs?sources=stdout,stderr,output")
    );
    reader
        .get_mut()
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
        )
        .await
        .unwrap();
    let cursor = LogCursor::empty();
    for (index, delay) in delays.into_iter().enumerate() {
        let event = format!(
            "id: {cursor}\nevent: log\ndata: {{\"source\":\"stdout\",\"ts\":\"2026-11-18T00:00:00Z\",\"text\":\"entry-{index}\"}}\n\n"
        );
        write_chunk(reader.get_mut(), event.as_bytes()).await;
        tokio::time::sleep(delay).await;
    }
    write_chunk(reader.get_mut(), b"event: end\n\n").await;
    reader.get_mut().write_all(b"0\r\n\r\n").await.unwrap();
}

fn assert_request_timeout(error: MicrosandboxError) {
    assert!(
        matches!(&error, MicrosandboxError::Http(error) if error.is_timeout()),
        "expected the HTTP client's total request timeout, got {error:?}",
    );
}

async fn upload_to_slow_http2_receiver(streaming: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        // Custom clients own upload deadlines, even when the context's timeout
        // is shorter than the time needed to drain one body chunk.
        .timeout(TEST_TIMEOUT)
        .http2_prior_knowledge()
        .build()
        .unwrap();
    let backend = backend(format!("http://{}", listener.local_addr().unwrap()))
        .to_builder()
        .client(client)
        .build()
        .unwrap();
    let fs = VolumeFs::with_backend(Arc::new(backend), "stream-test");
    let data: Vec<u8> = (0..512 * 1024).map(|index| index as u8).collect();
    let received_len = Arc::new(AtomicUsize::new(0));
    let counted = received_len.clone();
    let (received_tx, received_rx) = tokio::sync::oneshot::channel();
    let _server = AbortOnDropHandle::new(tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        // HTTP/2 flow control makes the backpressure independent of OS socket
        // buffer sizes. Each window update permits another real network write,
        // but a 256-KiB body piece takes longer than the request timeout to drain.
        let mut connection = h2::server::Builder::new()
            .initial_window_size(1024)
            .handshake::<_, Bytes>(socket)
            .await
            .unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.uri().path(), "/v1/volumes");
        let response = http::Response::builder()
            .header("content-type", "application/json")
            .body(())
            .unwrap();
        respond
            .send_response(response, false)
            .unwrap()
            .send_data(Bytes::from(volume_response().to_string()), true)
            .unwrap();

        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(
            request.uri().path(),
            format!("/v1/volumes/{VOLUME_ID}/files/content")
        );
        let _driver = AbortOnDropHandle::new(tokio::spawn(async move {
            // Polling the connection drives DATA and WINDOW_UPDATE frames while
            // the handler deliberately replenishes the receive window slowly.
            assert!(connection.accept().await.is_none());
        }));
        let mut body = request.into_body();
        let slow_until = tokio::time::Instant::now() + REQUEST_TIMEOUT * 3;
        let mut received = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            received.extend_from_slice(&chunk);
            counted.fetch_add(chunk.len(), Ordering::Relaxed);
            if tokio::time::Instant::now() < slow_until {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            body.flow_control().release_capacity(chunk.len()).unwrap();
        }
        respond
            .send_response(http::Response::new(()), true)
            .unwrap();
        received_tx.send(received).unwrap();
        // Keep driving the connection until the client has received the response.
        // The request owns this server task and cancels it when the test finishes.
        std::future::pending::<()>().await;
    }));

    let result = if streaming {
        let mut sink = fs.write_stream("/file").await.unwrap();
        sink.write(data.clone()).await.unwrap();
        sink.close().await
    } else {
        fs.write("/file", &data).await
    };
    assert!(
        result.is_ok(),
        "an upload must survive while the peer keeps receiving data ({} bytes received): {result:?}",
        received_len.load(Ordering::Relaxed),
    );
    assert_eq!(received_rx.await.unwrap(), data);
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn volume_write_preserves_custom_timeout_with_slow_receiver() {
    tokio::time::timeout(TEST_TIMEOUT, upload_to_slow_http2_receiver(false))
        .await
        .expect("slow receiver test timed out");
}

#[tokio::test]
async fn volume_write_stream_preserves_custom_timeout_with_slow_receiver() {
    tokio::time::timeout(TEST_TIMEOUT, upload_to_slow_http2_receiver(true))
        .await
        .expect("slow receiver test timed out");
}

#[tokio::test]
async fn log_follow_keeps_delivering_past_request_timeout() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = backend(format!("http://{}", listener.local_addr().unwrap()));
        let server = tokio::spawn(serve_log_stream(
            listener,
            vec![Duration::from_millis(100); 16],
        ));

        let entries = collect_log_text(&backend).await;

        assert_eq!(
            entries,
            (0..16)
                .map(|index| format!("entry-{index}"))
                .collect::<Vec<_>>()
        );
        server.await.unwrap();
    })
    .await
    .expect("log follow test timed out");
}

#[tokio::test]
async fn log_follow_stays_open_while_quiet() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = backend(format!("http://{}", listener.local_addr().unwrap()));
        let server = tokio::spawn(serve_log_stream(
            listener,
            vec![Duration::from_secs(1), Duration::ZERO],
        ));

        let entries = collect_log_text(&backend).await;

        assert_eq!(entries, ["entry-0", "entry-1"]);
        server.await.unwrap();
    })
    .await
    .expect("quiet log follow test timed out");
}

#[tokio::test]
async fn log_follow_drop_closes_connection() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = backend(format!("http://{}", listener.local_addr().unwrap()));
        let server = tokio::spawn(async move {
            let (target, reader) = accept_request(&listener).await;
            assert_eq!(target, "/v1/sandboxes/by-name/stream-test");
            write_json(reader, sandbox_response()).await;

            let (_, mut reader) = accept_request(&listener).await;
            reader
                .get_mut()
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
                )
                .await
                .unwrap();
            let event = format!(
                "id: {}\nevent: log\ndata: {{\"source\":\"stdout\",\"ts\":\"2026-11-18T00:00:00Z\",\"text\":\"entry\"}}\n\n",
                LogCursor::empty()
            );
            write_chunk(reader.get_mut(), event.as_bytes()).await;

            let mut byte = [0];
            let read = tokio::time::timeout(
                Duration::from_secs(1),
                reader.get_mut().read(&mut byte),
            )
            .await
            .expect("log connection stayed open")
            .unwrap();
            assert_eq!(read, 0);
        });

        let options = LogStreamOptions {
            follow: true,
            ..Default::default()
        };
        let mut stream = backend.log_stream("stream-test", &options).await.unwrap();
        assert_eq!(stream.next().await.unwrap().unwrap().data, "entry");
        drop(stream);

        server.await.unwrap();
    })
    .await
    .expect("log follow drop test timed out");
}

#[tokio::test]
async fn volume_download_keeps_delivering_past_request_timeout() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = backend(format!("http://{}", listener.local_addr().unwrap()));
        let fs = VolumeFs::with_backend(Arc::new(backend), "stream-test");
        let server = tokio::spawn(async move {
            serve_download(&listener, 16).await;
            serve_download(&listener, 16).await;
        });

        let mut stream = fs.read_stream("/file").await.unwrap();
        let mut streamed = Vec::new();
        while let Some(chunk) = stream.recv().await.unwrap() {
            streamed.extend_from_slice(&chunk);
        }
        let read = fs.read("/file").await.unwrap();

        let expected = (0..16).collect::<Vec<u8>>();
        assert_eq!(streamed, expected);
        assert_eq!(read.as_ref(), expected);
        server.await.unwrap();
    })
    .await
    .expect("volume download test timed out");
}

#[tokio::test]
async fn volume_download_reports_stall() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = backend(format!("http://{}", listener.local_addr().unwrap()));
        let fs = VolumeFs::with_backend(Arc::new(backend), "stream-test");
        let server = tokio::spawn(async move {
            serve_volume_lookup(&listener).await;
            let (_, mut reader) = accept_request(&listener).await;
            reader
                .get_mut()
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .unwrap();
            write_chunk(reader.get_mut(), b"first").await;
            tokio::time::sleep(Duration::from_secs(2)).await;
        });

        let mut stream = fs.read_stream("/file").await.unwrap();
        assert_eq!(stream.recv().await.unwrap().unwrap(), "first");
        let error = stream.recv().await.unwrap_err().to_string();

        assert!(error.contains("volume read stalled: no data"), "{error}");
        server.abort();
    })
    .await
    .expect("volume stall test timed out");
}

#[tokio::test]
async fn volume_upload_total_timeout_includes_caller_delays() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = backend(format!("http://{}", listener.local_addr().unwrap()));
        let fs = VolumeFs::with_backend(Arc::new(backend), "stream-test");
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let _server = AbortOnDropHandle::new(tokio::spawn(async move {
            serve_volume_lookup(&listener).await;
            let (_, _reader) = accept_request(&listener).await;
            started_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        }));

        let sink = fs.write_stream("/file").await.unwrap();
        started_rx.await.unwrap();
        // Uploads retain their total deadline while the caller prepares data.
        tokio::time::sleep(REQUEST_TIMEOUT * 2).await;
        let started = tokio::time::Instant::now();
        assert_request_timeout(sink.close().await.unwrap_err());
        assert!(
            started.elapsed() < REQUEST_TIMEOUT,
            "close restarted the total deadline"
        );
    })
    .await
    .expect("volume upload producer timeout test timed out");
}

#[tokio::test]
async fn volume_upload_progress_does_not_restart_total_timeout() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = backend(format!("http://{}", listener.local_addr().unwrap()));
        let fs = VolumeFs::with_backend(Arc::new(backend), "stream-test");
        let (progress_tx, mut progress_rx) = tokio::sync::mpsc::channel(1);
        let _server = AbortOnDropHandle::new(tokio::spawn(async move {
            serve_volume_lookup(&listener).await;
            let (_, mut reader) = accept_request(&listener).await;
            // Acknowledge each chunk in the test so it cannot mistake buffered
            // caller writes for actual network progress.
            loop {
                let mut size = String::new();
                if reader.read_line(&mut size).await.unwrap_or(0) == 0 {
                    return;
                }
                let size = usize::from_str_radix(size.trim(), 16).unwrap();
                if size == 0 {
                    return;
                }
                let mut data = vec![0; size + 2];
                if reader.read_exact(&mut data).await.is_err() {
                    return;
                }
                if progress_tx.send(()).await.is_err() {
                    return;
                }
            }
        }));

        let mut sink = fs.write_stream("/file").await.unwrap();
        let mut received = 0;
        for _ in 0..12 {
            if sink.write([7]).await.is_err() || progress_rx.recv().await.is_none() {
                break;
            }
            received += 1;
            tokio::time::sleep(REQUEST_TIMEOUT / 4).await;
        }
        assert!(received > 0, "the upload never reached the server");
        assert_request_timeout(sink.close().await.unwrap_err());
    })
    .await
    .expect("progressing upload timeout test timed out");
}

#[tokio::test]
async fn volume_write_fails_when_reply_never_comes() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = backend(format!("http://{}", listener.local_addr().unwrap()));
        let fs = VolumeFs::with_backend(Arc::new(backend), "stream-test");
        let (received_tx, received_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            serve_volume_lookup(&listener).await;
            let (_, mut reader) = accept_request(&listener).await;
            let received = read_chunked_body(&mut reader).await;
            received_tx.send(received).unwrap();
            std::future::pending::<()>().await;
        });

        let mut sink = fs.write_stream("/file").await.unwrap();
        for index in 0..8u8 {
            sink.write([index]).await.unwrap();
        }
        assert_request_timeout(sink.close().await.unwrap_err());
        assert_eq!(received_rx.await.unwrap(), (0..8).collect::<Vec<u8>>());
        server.abort();
    })
    .await
    .expect("volume upload reply timeout test timed out");
}

#[tokio::test]
async fn empty_volume_write_fails_when_reply_never_comes() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = backend(format!("http://{}", listener.local_addr().unwrap()));
        let fs = VolumeFs::with_backend(Arc::new(backend), "stream-test");
        let server = tokio::spawn(async move {
            serve_volume_lookup(&listener).await;
            let (target, _reader) = accept_request(&listener).await;
            assert_eq!(target, format!("/v1/volumes/{VOLUME_ID}/files/content"));
            std::future::pending::<()>().await;
        });

        assert_request_timeout(fs.write("/file", b"").await.unwrap_err());
        server.abort();
    })
    .await
    .expect("empty volume write reply timeout test timed out");
}

#[tokio::test]
async fn volume_read_error_body_is_bounded() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = backend(format!("http://{}", listener.local_addr().unwrap()));
        let fs = VolumeFs::with_backend(Arc::new(backend), "stream-test");
        let server = tokio::spawn(async move {
            serve_volume_lookup(&listener).await;
            let (_, mut reader) = accept_request(&listener).await;
            reader
                .get_mut()
                .write_all(
                    b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 100\r\n\r\n{\"partial",
                )
                .await
                .unwrap();
            std::future::pending::<()>().await;
        });

        assert!(fs.read("/file").await.is_err());
        server.abort();
    })
    .await
    .expect("volume read error-body test timed out");
}

#[tokio::test]
async fn volume_upload_fails_when_server_stops_reading() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = backend(format!("http://{}", listener.local_addr().unwrap()));
        let fs = VolumeFs::with_backend(Arc::new(backend), "stream-test");
        let server = tokio::spawn(async move {
            serve_volume_lookup(&listener).await;
            let (_, _reader) = accept_request(&listener).await;
            std::future::pending::<()>().await;
        });

        let mut sink = fs.write_stream("/file").await.unwrap();
        let chunk = vec![7u8; 1 << 20];
        let mut write_failed = false;
        for _ in 0..256 {
            if sink.write(chunk.clone()).await.is_err() {
                write_failed = true;
                break;
            }
        }
        let error = sink.close().await.unwrap_err();

        assert!(
            write_failed,
            "writes kept succeeding after the upload stalled"
        );
        assert_request_timeout(error);
        server.abort();
    })
    .await
    .expect("stalled volume upload test timed out");
}

#[tokio::test]
async fn volume_upload_sends_a_large_chunk_intact() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = backend(format!("http://{}", listener.local_addr().unwrap()));
        let fs = VolumeFs::with_backend(Arc::new(backend), "stream-test");
        let server = tokio::spawn(async move {
            serve_volume_lookup(&listener).await;
            let (_, mut reader) = accept_request(&listener).await;
            let received = read_chunked_body(&mut reader).await;
            reader
                .get_mut()
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            received
        });

        let data: Vec<u8> = (0..(1 << 20) + 3).map(|index| index as u8).collect();
        let mut sink = fs.write_stream("/file").await.unwrap();
        sink.write(data.clone()).await.unwrap();
        sink.close().await.unwrap();

        assert_eq!(server.await.unwrap(), data);
    })
    .await
    .expect("large volume upload test timed out");
}

#[tokio::test]
async fn volume_upload_times_out_during_tls_handshake() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = backend(format!("https://{}", listener.local_addr().unwrap()));
        // Use a derived timeout to ensure this deadline belongs to the request,
        // even when contexts share their underlying connection pool.
        let backend = backend
            .to_builder()
            .request_timeout(Duration::from_millis(100))
            .build()
            .unwrap();
        let server = AbortOnDropHandle::new(tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.unwrap();
            let mut header = [0; 5];
            connection.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], 22, "expected a TLS handshake record");
            // Accept TCP but never answer ClientHello. The HTTP client cannot
            // poll the pending upload body until this handshake completes.
            let mut remaining = Vec::new();
            let _ = connection.read_to_end(&mut remaining).await;
        }));

        let error = backend
            .volume_file_request(
                Method::PUT,
                VOLUME_ID,
                "/content",
                &[],
                None,
                FileTransfer::Upload(reqwest::Body::wrap_stream(stream::pending::<
                    Result<Bytes, std::io::Error>,
                >())),
            )
            .await
            .unwrap_err();

        assert_request_timeout(error);
        server.await.unwrap();
    })
    .await
    .expect("upload connection test timed out");
}
