use std::sync::Arc;

use microsandbox::{AgentBridge, BridgeFrame};
use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::error::to_napi_error;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A raw protocol frame: correlation id, flags, and CBOR-encoded body bytes.
///
/// The body is the CBOR-encoded `Message` body (`v`, `t`, `p`) as it
/// appeared on the wire — decode with any CBOR library (e.g. `cbor-x`).
#[napi(object)]
pub struct RawFrame {
    /// Correlation ID from the frame header.
    pub id: u32,
    /// Frame flags from the frame header.
    pub flags: u8,
    /// Raw CBOR bytes of the message body.
    pub body: Buffer,
}

/// Result of opening a stream: the protocol correlation id (for follow-up
/// sends) and an opaque stream handle (for `streamNext` / `streamClose`).
#[napi(object)]
pub struct StreamOpenResult {
    /// Protocol correlation ID. Pass to `send()` for follow-up frames.
    pub id: u32,
    /// Opaque stream handle. Pass to `streamNext()` and `streamClose()`.
    pub handle: BigInt,
}

/// Low-level client for talking to agentd through the sandbox relay socket.
///
/// All bodies are raw CBOR bytes — encode and decode in JS userland with a
/// library like `cbor-x`. For ergonomic typed access, build a higher layer
/// on top of this class.
#[napi]
pub struct AgentClient {
    inner: Arc<AgentBridge>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl AgentClient {
    /// Connect to a sandbox by name. Resolves the agent socket from the
    /// SDK's configured sandboxes directory.
    #[napi(factory, js_name = "connectSandbox")]
    pub async fn connect_sandbox(name: String) -> Result<AgentClient> {
        let bridge = AgentBridge::connect_sandbox(&name)
            .await
            .map_err(to_napi_error_agent)?;
        Ok(AgentClient {
            inner: Arc::new(bridge),
        })
    }

    /// Connect to an agentd relay socket by path.
    #[napi(factory)]
    pub async fn connect(path: String) -> Result<AgentClient> {
        let bridge = AgentBridge::connect_path(&path)
            .await
            .map_err(to_napi_error_agent)?;
        Ok(AgentClient {
            inner: Arc::new(bridge),
        })
    }

    /// Send one frame and await a single response frame.
    ///
    /// Use for request/response RPCs that produce exactly one terminal
    /// response (e.g. an `FsRequest` → `FsResponse`).
    #[napi]
    pub async fn request(&self, flags: u8, body: Buffer) -> Result<RawFrame> {
        let frame = self
            .inner
            .request(flags, body.to_vec())
            .await
            .map_err(to_napi_error_agent)?;
        Ok(frame_to_js(frame))
    }

    /// Open a streaming session. Returns `{id, handle}`:
    /// - `id`: pass to `send()` for follow-up frames within the session.
    /// - `handle`: pass to `streamNext()` / `streamClose()`.
    #[napi(js_name = "streamOpen")]
    pub async fn stream_open(&self, flags: u8, body: Buffer) -> Result<StreamOpenResult> {
        let (id, handle) = self
            .inner
            .stream_open(flags, body.to_vec())
            .await
            .map_err(to_napi_error_agent)?;
        Ok(StreamOpenResult {
            id,
            handle: BigInt::from(handle),
        })
    }

    /// Pull the next frame from a stream. Resolves with `null` when the
    /// stream has ended (terminal frame delivered, or stream closed).
    #[napi(js_name = "streamNext")]
    pub async fn stream_next(&self, handle: BigInt) -> Result<Option<RawFrame>> {
        let (_signed, h, _lossless) = handle.get_u64();
        match self
            .inner
            .stream_next(h)
            .await
            .map_err(to_napi_error_agent)?
        {
            Some(frame) => Ok(Some(frame_to_js(frame))),
            None => Ok(None),
        }
    }

    /// Close a stream handle. Idempotent.
    #[napi(js_name = "streamClose")]
    pub async fn stream_close(&self, handle: BigInt) -> Result<()> {
        let (_signed, h, _lossless) = handle.get_u64();
        self.inner.stream_close(h).await;
        Ok(())
    }

    /// Send a follow-up frame on an existing correlation id (e.g. stdin,
    /// signal, resize, or data chunks on an open session).
    #[napi]
    pub async fn send(&self, id: u32, flags: u8, body: Buffer) -> Result<()> {
        self.inner
            .send(id, flags, body.to_vec())
            .await
            .map_err(to_napi_error_agent)
    }

    /// The cached handshake `core.ready` frame body bytes (CBOR-encoded).
    #[napi(js_name = "readyBytes")]
    pub fn ready_bytes(&self) -> Result<Buffer> {
        Ok(self
            .inner
            .ready_bytes()
            .map_err(to_napi_error_agent)?
            .into())
    }

    /// Close the connection. Idempotent.
    #[napi]
    pub async fn close(&self) -> Result<()> {
        self.inner.close().await;
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn frame_to_js(frame: BridgeFrame) -> RawFrame {
    RawFrame {
        id: frame.id,
        flags: frame.flags,
        body: frame.body.into(),
    }
}

fn to_napi_error_agent(err: microsandbox::AgentClientError) -> napi::Error {
    // Route through the existing error mapper by wrapping in MicrosandboxError.
    to_napi_error(microsandbox::MicrosandboxError::AgentClient(err))
}
