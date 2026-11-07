//! A scripted local HTTP/1.1 server that records each request it answers.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};

use crate::backend::Backend;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One request as the server read it.
#[derive(Clone, Debug)]
pub(crate) struct Captured {
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) body: String,
}

/// What the server does after reading a request.
pub(crate) enum Reply {
    /// Write these raw response bytes.
    Respond(String),
    /// Close the connection without answering.
    Reset,
    /// Keep the connection open and never answer.
    Hang,
}

/// A scripted HTTP server that records every request and handles each with one reply.
pub(crate) struct FakeServer {
    pub(crate) url: String,
    requests: Arc<Mutex<Vec<Captured>>>,
    task: JoinHandle<()>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl FakeServer {
    /// Listen on a loopback port and answer every connection with `reply`.
    pub(crate) async fn start(reply: Reply) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let reply = Arc::new(reply);
        let captured = requests.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                connections.spawn(answer(stream, reply.clone(), captured.clone()));
            }
        });
        Self {
            url,
            requests,
            task,
        }
    }

    /// A cloud backend pointed at this server.
    pub(crate) fn backend(&self) -> Arc<dyn Backend> {
        Arc::new(super::cloud_backend(&self.url, "test-key").unwrap())
    }

    /// Every request read so far, in arrival order.
    pub(crate) fn requests(&self) -> Vec<Captured> {
        self.requests.lock().unwrap().clone()
    }

    /// The single request read so far; fails the test if there were more or none.
    pub(crate) fn only_request(&self) -> Captured {
        let requests = self.requests();
        assert_eq!(requests.len(), 1, "expected exactly one request");
        requests.into_iter().next().unwrap()
    }
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// A `Connection: close` reply with `status`, an optional `Retry-After`, and a JSON
/// body unless the status is 204.
pub(crate) fn respond(status: u16, retry_after: Option<&str>, body: &str) -> Reply {
    let mut head = format!("HTTP/1.1 {status} Status\r\nConnection: close\r\n");
    if let Some(seconds) = retry_after {
        head.push_str(&format!("Retry-After: {seconds}\r\n"));
    }
    if status != 204 {
        head.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    Reply::Respond(format!("{head}\r\n{body}"))
}

async fn answer(stream: TcpStream, reply: Arc<Reply>, captured: Arc<Mutex<Vec<Captured>>>) {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await.unwrap();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap().to_owned();
    let target = parts.next().unwrap().to_owned();

    let mut content_length = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        if line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().unwrap();
        }
    }
    let mut body = vec![0; content_length];
    reader.read_exact(&mut body).await.unwrap();
    let body = String::from_utf8(body).unwrap();
    captured.lock().unwrap().push(Captured {
        method,
        target,
        body,
    });

    match reply.as_ref() {
        Reply::Respond(raw) => reader.get_mut().write_all(raw.as_bytes()).await.unwrap(),
        Reply::Reset => {}
        Reply::Hang => std::future::pending().await,
    }
}
