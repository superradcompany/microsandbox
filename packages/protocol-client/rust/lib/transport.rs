//! Exclusively owned byte transports and repeatable dialers.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;

use crate::{ClientError, ClientResult, ErrorKind};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Owned transport; reader and writer progress independently after splitting.
pub trait ByteTransport: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

/// Erased byte transport for external protocol and connector implementations.
pub type BoxTransport = Box<dyn ByteTransport>;

/// Owned Send future used at the public protocol/connector boundary.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Opens independent transports, without negotiation or application parsing.
pub trait Connector: Send + Sync {
    /// Dial before the remaining absolute setup deadline; dropping cancels dial.
    fn connect(&self, deadline: Instant) -> BoxFuture<'_, ClientResult<BoxTransport>>;
}

/// Native local endpoint supplied by the caller's existing endpoint helper.
#[derive(Debug, Clone)]
pub struct LocalConnector {
    path: PathBuf,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LocalConnector {
    /// Store an endpoint without altering Unix or Windows naming.
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_owned(),
        }
    }

    /// The exact endpoint passed by the caller.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> ByteTransport for T {}

impl Connector for LocalConnector {
    fn connect(&self, deadline: Instant) -> BoxFuture<'_, ClientResult<BoxTransport>> {
        Box::pin(async move {
            tokio::time::timeout_at(deadline, async {
                #[cfg(all(unix, feature = "uds"))]
                {
                    let stream = tokio::net::UnixStream::connect(&self.path).await?;
                    Ok(Box::new(stream) as BoxTransport)
                }
                #[cfg(all(windows, feature = "named-pipe"))]
                {
                    loop {
                        match tokio::net::windows::named_pipe::ClientOptions::new().open(&self.path)
                        {
                            Ok(stream) => return Ok(Box::new(stream) as BoxTransport),
                            Err(error)
                                if error.kind() == std::io::ErrorKind::NotFound
                                    || error.raw_os_error() == Some(231) =>
                            {
                                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                            }
                            Err(error) => return Err(ClientError::from(error)),
                        }
                    }
                }
                #[cfg(not(any(all(unix, feature = "uds"), all(windows, feature = "named-pipe"))))]
                Err(ClientError::new(ErrorKind::UnsupportedOperation))
            })
            .await
            .map_err(|_| ClientError::new(ErrorKind::Timeout))?
        })
    }
}
