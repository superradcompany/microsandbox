//! Windows named-pipe transport adapter.
//!
//! Enable the `named-pipe` crate feature to use this module. It is intended for
//! local microsandbox relay pipes on Windows hosts.

use std::ffi::OsStr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};

use crate::AgentClientResult;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Agent transport backed by a Windows named pipe.
///
/// This adapter implements the byte transport accepted by the shared client. Most SDK code
/// should use [`AgentClient::connect`](crate::AgentClient::connect), which
/// performs the relay handshake and starts request routing.
pub struct NamedPipeTransport {
    stream: NamedPipeClient,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl NamedPipeTransport {
    /// Connect to a Windows named-pipe path.
    ///
    /// The returned transport is connected but not handshaken. Pass it to a
    /// `AgentClient::connect_stream`, or use [`AgentClient::connect`](crate::AgentClient::connect)
    /// for the built-in path.
    pub async fn connect(path: impl AsRef<OsStr>) -> AgentClientResult<Self> {
        let stream = ClientOptions::new().open(path)?;
        Ok(Self { stream })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl AsyncRead for NamedPipeTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for NamedPipeTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
