//! Exercise cloud streaming timeouts through public SDK APIs against local HTTP responses.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use super::CloudBackend;
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

fn backend(url: String) -> CloudBackend {
    CloudBackend::builder()
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

async fn collect_log_text(backend: &CloudBackend) -> Vec<String> {
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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

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
async fn volume_upload_keeps_accepting_past_request_timeout() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = backend(format!("http://{}", listener.local_addr().unwrap()));
        let fs = VolumeFs::with_backend(Arc::new(backend), "stream-test");
        let server = tokio::spawn(async move {
            serve_volume_lookup(&listener).await;
            let (target, mut reader) = accept_request(&listener).await;
            assert_eq!(target, format!("/v1/volumes/{VOLUME_ID}/files/content"));
            let received = read_chunked_body(&mut reader).await;
            reader
                .get_mut()
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            received
        });

        let mut sink = fs.write_stream("/file").await.unwrap();
        for index in 0..16u8 {
            sink.write([index]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        sink.close().await.unwrap();

        assert_eq!(server.await.unwrap(), (0..16).collect::<Vec<u8>>());
    })
    .await
    .expect("volume upload test timed out");
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
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let error = sink.close().await.unwrap_err().to_string();

        assert!(error.contains("no response within"), "{error}");
        assert_eq!(received_rx.await.unwrap(), (0..8).collect::<Vec<u8>>());
        server.abort();
    })
    .await
    .expect("volume upload reply timeout test timed out");
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
