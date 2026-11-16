//! Byte-stream adapter over a WebSocket connection.
//!
//! The cloud exposes a sandbox's agent relay as a WebSocket route that pipes
//! raw bytes to and from the guest agent. The agent client, however, speaks
//! over any `AsyncRead + AsyncWrite`. This adapter bridges the two: binary
//! WebSocket messages become the byte stream's contents, and writes are sent
//! as binary messages.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::{self, protocol::Message as WsMessage};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Exposes a WebSocket connection as a plain byte stream.
///
/// Reads drain binary messages in arrival order; message boundaries are not
/// preserved (the relay is a byte pipe, so they carry no meaning). Text
/// messages are ignored. A close message or end of stream reads as EOF.
/// Each write is sent as one binary message.
pub(super) struct WsByteStream<S> {
    inner: S,
    read_buf: Vec<u8>,
    read_pos: usize,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<S> WsByteStream<S> {
    /// Wrap a connected WebSocket.
    pub(super) fn new(inner: S) -> Self {
        Self {
            inner,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<S> AsyncRead for WsByteStream<S>
where
    S: Stream<Item = Result<WsMessage, tungstenite::Error>> + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            // Serve buffered bytes from the last binary message first.
            if self.read_pos < self.read_buf.len() {
                let available = &self.read_buf[self.read_pos..];
                let n = available.len().min(buf.remaining());
                buf.put_slice(&available[..n]);
                self.read_pos += n;
                if self.read_pos == self.read_buf.len() {
                    self.read_buf.clear();
                    self.read_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            match Pin::new(&mut self.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(WsMessage::Binary(data)))) => {
                    self.read_buf = data.into();
                    self.read_pos = 0;
                }
                // Ping/pong are handled by the WebSocket layer; text frames
                // carry nothing on this route.
                Poll::Ready(Some(Ok(WsMessage::Close(_)))) | Poll::Ready(None) => {
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Ok(_))) => {}
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Err(io::Error::other(error)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for WsByteStream<S>
where
    S: Sink<WsMessage, Error = tungstenite::Error> + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut self.inner)
            .start_send(WsMessage::Binary(buf.to_vec().into()))
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(io::Error::other)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner)
            .poll_close(cx)
            .map_err(io::Error::other)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use futures::stream;
    use tokio::io::AsyncReadExt;

    use super::*;

    /// A test double that yields scripted messages and records writes.
    struct ScriptedWs {
        incoming: stream::Iter<std::vec::IntoIter<Result<WsMessage, tungstenite::Error>>>,
        sent: Vec<WsMessage>,
    }

    impl ScriptedWs {
        fn new(messages: Vec<Result<WsMessage, tungstenite::Error>>) -> Self {
            Self {
                incoming: stream::iter(messages),
                sent: Vec::new(),
            }
        }
    }

    impl Stream for ScriptedWs {
        type Item = Result<WsMessage, tungstenite::Error>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Pin::new(&mut self.incoming).poll_next(cx)
        }
    }

    impl Sink<WsMessage> for ScriptedWs {
        type Error = tungstenite::Error;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(mut self: Pin<&mut Self>, item: WsMessage) -> Result<(), Self::Error> {
            self.sent.push(item);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn reads_concatenate_binary_messages() {
        let ws = ScriptedWs::new(vec![
            Ok(WsMessage::Binary(b"hel".to_vec().into())),
            Ok(WsMessage::Binary(b"lo".to_vec().into())),
        ]);
        let mut io = WsByteStream::new(ws);

        let mut out = Vec::new();
        io.read_to_end(&mut out).await.unwrap();

        assert_eq!(out, b"hello");
    }

    #[tokio::test]
    async fn read_skips_text_and_ends_on_close() {
        let ws = ScriptedWs::new(vec![
            Ok(WsMessage::Text("ignored".into())),
            Ok(WsMessage::Binary(b"data".to_vec().into())),
            Ok(WsMessage::Close(None)),
            Ok(WsMessage::Binary(b"after-close".to_vec().into())),
        ]);
        let mut io = WsByteStream::new(ws);

        let mut out = Vec::new();
        io.read_to_end(&mut out).await.unwrap();

        assert_eq!(out, b"data");
    }

    #[tokio::test]
    async fn writes_are_sent_as_binary_messages() {
        use tokio::io::AsyncWriteExt;

        let ws = ScriptedWs::new(Vec::new());
        let mut io = WsByteStream::new(ws);

        io.write_all(b"abc").await.unwrap();
        io.flush().await.unwrap();

        assert_eq!(io.inner.sent.len(), 1);
        assert!(matches!(
            &io.inner.sent[0],
            WsMessage::Binary(data) if data.as_ref() == b"abc"
        ));
    }

    #[tokio::test]
    async fn partial_reads_resume_within_a_message() {
        let ws = ScriptedWs::new(vec![Ok(WsMessage::Binary(b"abcdef".to_vec().into()))]);
        let mut io = WsByteStream::new(ws);

        let mut first = [0u8; 4];
        io.read_exact(&mut first).await.unwrap();
        let mut rest = Vec::new();
        io.read_to_end(&mut rest).await.unwrap();

        assert_eq!(&first, b"abcd");
        assert_eq!(rest, b"ef");
    }
}
