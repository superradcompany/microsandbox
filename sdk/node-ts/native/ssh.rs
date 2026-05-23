use std::sync::Arc;

use napi::bindgen_prelude::*;
use napi_derive::napi;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::error::to_napi_error;
use crate::types::{
    SshAttachOptions, SshClientOptions, SshExecOptions, SshOutput, SshServerOptions,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Native in-process SSH client session.
#[napi(js_name = "SshClient")]
pub struct JsSshClient {
    inner: Arc<Mutex<Option<microsandbox::sandbox::SshClient>>>,
}

/// High-level SFTP client session.
#[napi(js_name = "SftpClient")]
pub struct JsSftpClient {
    inner: Arc<Mutex<Option<microsandbox::sandbox::SftpClient>>>,
}

/// Reusable SSH server endpoint for a sandbox.
#[napi(js_name = "SshServer")]
pub struct JsSshServer {
    inner: Arc<Mutex<Option<microsandbox::sandbox::SshServer>>>,
}

//--------------------------------------------------------------------------------------------------
// Methods: SshClient
//--------------------------------------------------------------------------------------------------

impl JsSshClient {
    pub fn from_rust(inner: microsandbox::sandbox::SshClient) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(inner))),
        }
    }
}

#[napi]
impl JsSshClient {
    /// Run an SSH exec request and collect stdout, stderr, and exit status.
    #[napi]
    pub async fn exec(
        &self,
        command: String,
        options: Option<SshExecOptions>,
    ) -> Result<SshOutput> {
        let guard = self.inner.lock().await;
        let client = guard.as_ref().ok_or_else(consumed_error)?;
        let output = client
            .exec_with(command, |builder| apply_exec_options(options, builder))
            .await
            .map_err(to_napi_error)?;
        Ok(SshOutput {
            status: output.status,
            stdout: output.stdout.to_vec().into(),
            stderr: output.stderr.to_vec().into(),
        })
    }

    /// Attach the local terminal to an interactive SSH shell.
    #[napi]
    pub async fn attach(&self, options: Option<SshAttachOptions>) -> Result<i32> {
        let guard = self.inner.lock().await;
        let client = guard.as_ref().ok_or_else(consumed_error)?;
        client
            .attach_with(|builder| apply_attach_options(options, builder))
            .await
            .map_err(to_napi_error)
    }

    /// Open an SFTP session over this SSH connection.
    #[napi]
    pub async fn sftp(&self) -> Result<JsSftpClient> {
        let guard = self.inner.lock().await;
        let client = guard.as_ref().ok_or_else(consumed_error)?;
        let sftp = client.sftp().await.map_err(to_napi_error)?;
        Ok(JsSftpClient::from_rust(sftp))
    }

    /// Close this SSH client session.
    #[napi]
    pub async fn close(&self) -> Result<()> {
        let client = {
            let mut guard = self.inner.lock().await;
            guard.take().ok_or_else(consumed_error)?
        };
        client.close().await.map_err(to_napi_error)
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: SftpClient
//--------------------------------------------------------------------------------------------------

impl JsSftpClient {
    pub fn from_rust(inner: microsandbox::sandbox::SftpClient) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(inner))),
        }
    }
}

#[napi]
impl JsSftpClient {
    /// Read a file into memory.
    #[napi]
    pub async fn read(&self, path: String) -> Result<Buffer> {
        let guard = self.inner.lock().await;
        let sftp = guard.as_ref().ok_or_else(consumed_error)?;
        sftp.read(path).await.map(Buffer::from).map_err(sftp_error)
    }

    /// Write a file, creating or truncating it.
    #[napi]
    pub async fn write(&self, path: String, data: Buffer) -> Result<()> {
        let guard = self.inner.lock().await;
        let sftp = guard.as_ref().ok_or_else(consumed_error)?;
        let mut file = sftp.create(path).await.map_err(sftp_error)?;
        file.write_all(&data).await.map_err(sftp_error)?;
        file.shutdown().await.map_err(sftp_error)
    }

    /// Create a directory.
    #[napi(js_name = "mkdir")]
    pub async fn mkdir(&self, path: String) -> Result<()> {
        let guard = self.inner.lock().await;
        let sftp = guard.as_ref().ok_or_else(consumed_error)?;
        sftp.create_dir(path).await.map_err(sftp_error)
    }

    /// Remove a file.
    #[napi(js_name = "removeFile")]
    pub async fn remove_file(&self, path: String) -> Result<()> {
        let guard = self.inner.lock().await;
        let sftp = guard.as_ref().ok_or_else(consumed_error)?;
        sftp.remove_file(path).await.map_err(sftp_error)
    }

    /// Remove an empty directory.
    #[napi(js_name = "removeDir")]
    pub async fn remove_dir(&self, path: String) -> Result<()> {
        let guard = self.inner.lock().await;
        let sftp = guard.as_ref().ok_or_else(consumed_error)?;
        sftp.remove_dir(path).await.map_err(sftp_error)
    }

    /// Rename a file or directory.
    #[napi]
    pub async fn rename(&self, old_path: String, new_path: String) -> Result<()> {
        let guard = self.inner.lock().await;
        let sftp = guard.as_ref().ok_or_else(consumed_error)?;
        sftp.rename(old_path, new_path).await.map_err(sftp_error)
    }

    /// Resolve a path to its canonical absolute form.
    #[napi(js_name = "realPath")]
    pub async fn real_path(&self, path: String) -> Result<String> {
        let guard = self.inner.lock().await;
        let sftp = guard.as_ref().ok_or_else(consumed_error)?;
        sftp.canonicalize(path).await.map_err(sftp_error)
    }

    /// Read a symlink target.
    #[napi(js_name = "readLink")]
    pub async fn read_link(&self, path: String) -> Result<String> {
        let guard = self.inner.lock().await;
        let sftp = guard.as_ref().ok_or_else(consumed_error)?;
        sftp.read_link(path).await.map_err(sftp_error)
    }

    /// Create a symlink.
    #[napi]
    pub async fn symlink(&self, target: String, link_path: String) -> Result<()> {
        let guard = self.inner.lock().await;
        let sftp = guard.as_ref().ok_or_else(consumed_error)?;
        sftp.symlink(target, link_path).await.map_err(sftp_error)
    }

    /// Close this SFTP session.
    #[napi]
    pub async fn close(&self) -> Result<()> {
        let sftp = {
            let mut guard = self.inner.lock().await;
            guard.take().ok_or_else(consumed_error)?
        };
        sftp.close().await.map_err(sftp_error)
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: SshServer
//--------------------------------------------------------------------------------------------------

impl JsSshServer {
    pub fn from_rust(inner: microsandbox::sandbox::SshServer) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(inner))),
        }
    }
}

#[napi]
impl JsSshServer {
    /// Serve one SSH transport over this process's stdin/stdout.
    #[napi(js_name = "serveStdio")]
    pub async fn serve_stdio(&self) -> Result<()> {
        let server = {
            let guard = self.inner.lock().await;
            guard.as_ref().ok_or_else(consumed_error)?.clone()
        };
        server
            .serve(microsandbox::sandbox::SshStdioStream::new())
            .await
            .map_err(to_napi_error)
    }

    /// Release this prepared server endpoint.
    #[napi]
    pub async fn close(&self) -> Result<()> {
        let mut guard = self.inner.lock().await;
        guard.take().ok_or_else(consumed_error)?;
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub fn apply_client_options(
    options: Option<SshClientOptions>,
    builder: microsandbox::sandbox::SshClientOptionsBuilder,
) -> microsandbox::sandbox::SshClientOptionsBuilder {
    let Some(options) = options else {
        return builder;
    };
    let mut builder = builder;
    if let Some(user) = options.user {
        builder = builder.user(user);
    }
    if let Some(term) = options.term {
        builder = builder.term(term);
    }
    if let Some(sftp) = options.sftp {
        builder = builder.sftp(sftp);
    }
    builder
}

pub fn apply_server_options(
    options: Option<SshServerOptions>,
    builder: microsandbox::sandbox::SshServerOptionsBuilder,
) -> microsandbox::sandbox::SshServerOptionsBuilder {
    let Some(options) = options else {
        return builder;
    };
    let mut builder = builder;
    if let Some(path) = options.host_key_path {
        builder = builder.host_key_path(path);
    }
    if let Some(path) = options.authorized_keys_path {
        builder = builder.authorized_keys_path(path);
    }
    if let Some(user) = options.user {
        builder = builder.user(user);
    }
    if let Some(sftp) = options.sftp {
        builder = builder.sftp(sftp);
    }
    builder
}

fn apply_exec_options(
    options: Option<SshExecOptions>,
    builder: microsandbox::sandbox::SshExecOptionsBuilder,
) -> microsandbox::sandbox::SshExecOptionsBuilder {
    let Some(options) = options else {
        return builder;
    };
    let mut builder = builder;
    if let Some(tty) = options.tty {
        builder = builder.tty(tty);
    }
    builder
}

fn apply_attach_options(
    options: Option<SshAttachOptions>,
    builder: microsandbox::sandbox::SshAttachOptionsBuilder,
) -> microsandbox::sandbox::SshAttachOptionsBuilder {
    let Some(options) = options else {
        return builder;
    };
    let mut builder = builder;
    if let Some(term) = options.term {
        builder = builder.term(term);
    }
    if let Some(detach_keys) = options.detach_keys {
        builder = builder.detach_keys(detach_keys);
    }
    builder
}

fn consumed_error() -> napi::Error {
    napi::Error::from_reason("SSH handle has been consumed")
}

fn sftp_error(error: impl std::fmt::Display) -> napi::Error {
    napi::Error::from_reason(format!("SFTP error: {error}"))
}
