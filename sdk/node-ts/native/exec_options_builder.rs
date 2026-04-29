use std::time::Duration;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use microsandbox::sandbox::{
    ExecOptionsBuilder as RustExecOptionsBuilder, RlimitResource as RustRlimitResource,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fluent builder for per-execution overrides.
#[napi(js_name = "ExecOptionsBuilder")]
pub struct JsExecOptionsBuilder {
    inner: Option<RustExecOptionsBuilder>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsExecOptionsBuilder {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Some(RustExecOptionsBuilder::default()),
        }
    }

    /// Append a single command argument.
    #[napi]
    pub fn arg(&mut self, arg: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.arg(arg));
        self
    }

    /// Append a list of command arguments.
    #[napi]
    pub fn args(&mut self, args: Vec<String>) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.args(args));
        self
    }

    /// Override the working directory for this exec.
    #[napi]
    pub fn cwd(&mut self, cwd: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.cwd(cwd));
        self
    }

    /// Override the running user for this exec.
    #[napi]
    pub fn user(&mut self, user: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.user(user));
        self
    }

    /// Set a single environment variable.
    #[napi]
    pub fn env(&mut self, key: String, value: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.env(key, value));
        self
    }

    /// Set environment variables from an object.
    #[napi]
    pub fn envs(&mut self, vars: std::collections::HashMap<String, String>) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.envs(vars));
        self
    }

    /// Kill the process if it hasn't exited within `ms` milliseconds.
    #[napi]
    pub fn timeout(&mut self, ms: u32) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.timeout(Duration::from_millis(ms as u64)));
        self
    }

    /// Connect stdin to /dev/null (default).
    #[napi(js_name = "stdinNull")]
    pub fn stdin_null(&mut self) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.stdin_null());
        self
    }

    /// Open a writable stdin pipe (use `ExecHandle.takeStdin()`).
    #[napi(js_name = "stdinPipe")]
    pub fn stdin_pipe(&mut self) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.stdin_pipe());
        self
    }

    /// Pipe a fixed byte payload as stdin.
    #[napi(js_name = "stdinBytes")]
    pub fn stdin_bytes(&mut self, data: Buffer) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.stdin_bytes(data.to_vec()));
        self
    }

    /// Allocate a pseudo-terminal (default: false).
    #[napi]
    pub fn tty(&mut self, enabled: bool) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.tty(enabled));
        self
    }

    /// Set a hard rlimit (soft = hard).
    #[napi]
    pub fn rlimit(&mut self, resource: String, limit: u32) -> Result<&Self> {
        let res = parse_rlimit_resource(&resource)?;
        let prev = self.take_inner();
        self.inner = Some(prev.rlimit(res, limit as u64));
        Ok(self)
    }

    /// Set a separate soft and hard rlimit.
    #[napi(js_name = "rlimitRange")]
    pub fn rlimit_range(&mut self, resource: String, soft: u32, hard: u32) -> Result<&Self> {
        let res = parse_rlimit_resource(&resource)?;
        let prev = self.take_inner();
        self.inner = Some(prev.rlimit_range(res, soft as u64, hard as u64));
        Ok(self)
    }
}

impl JsExecOptionsBuilder {
    fn take_inner(&mut self) -> RustExecOptionsBuilder {
        self.inner
            .take()
            .expect("ExecOptionsBuilder used after consumption")
    }

    /// Internal: extract the underlying Rust builder. Used by
    /// `Sandbox.execWith()` / `execStreamWith()` to route through the
    /// public closure callback in the core SDK.
    #[allow(dead_code)]
    pub(crate) fn take_inner_builder(&mut self) -> Result<RustExecOptionsBuilder> {
        self.inner
            .take()
            .ok_or_else(|| napi::Error::from_reason("ExecOptionsBuilder already consumed"))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn parse_rlimit_resource(s: &str) -> Result<RustRlimitResource> {
    let r = match s {
        "cpu" => RustRlimitResource::Cpu,
        "fsize" => RustRlimitResource::Fsize,
        "data" => RustRlimitResource::Data,
        "stack" => RustRlimitResource::Stack,
        "core" => RustRlimitResource::Core,
        "rss" => RustRlimitResource::Rss,
        "nproc" => RustRlimitResource::Nproc,
        "nofile" => RustRlimitResource::Nofile,
        "memlock" => RustRlimitResource::Memlock,
        "as" => RustRlimitResource::As,
        "locks" => RustRlimitResource::Locks,
        "sigpending" => RustRlimitResource::Sigpending,
        "msgqueue" => RustRlimitResource::Msgqueue,
        "nice" => RustRlimitResource::Nice,
        "rtprio" => RustRlimitResource::Rtprio,
        "rttime" => RustRlimitResource::Rttime,
        other => {
            return Err(napi::Error::from_reason(format!(
                "unknown rlimit resource `{other}`"
            )));
        }
    };
    Ok(r)
}
