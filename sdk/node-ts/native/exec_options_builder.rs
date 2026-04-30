use std::collections::HashMap;
use std::time::Duration;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use microsandbox::sandbox::{
    ExecOptionsBuilder as RustExecOptionsBuilder, RlimitResource as RustRlimitResource,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Stdin mode for an exec.
#[derive(Clone)]
#[napi(object, js_name = "StdinMode")]
pub struct JsStdinMode {
    /// `"null" | "pipe" | "bytes"`.
    pub kind: String,
    /// Raw bytes piped as stdin (only for kind `"bytes"`).
    pub data: Option<Vec<u8>>,
}

/// A single rlimit entry.
#[derive(Clone)]
#[napi(object, js_name = "Rlimit")]
pub struct JsRlimit {
    pub resource: String,
    pub soft: u32,
    pub hard: u32,
}

/// Built exec options produced by `ExecOptionsBuilder.build()`.
#[derive(Clone)]
#[napi(object, js_name = "ExecOptions")]
pub struct JsExecOptions {
    pub args: Vec<String>,
    pub cwd: Option<String>,
    pub user: Option<String>,
    pub env: HashMap<String, String>,
    pub timeout_ms: Option<u32>,
    pub stdin: JsStdinMode,
    pub tty: bool,
    pub rlimits: Vec<JsRlimit>,
}

/// Fluent builder for per-execution overrides.
#[napi(js_name = "ExecOptionsBuilder")]
pub struct JsExecOptionsBuilder {
    inner: Option<RustExecOptionsBuilder>,
    args: Vec<String>,
    cwd: Option<String>,
    user: Option<String>,
    env: Vec<(String, String)>,
    timeout_ms: Option<u32>,
    stdin: JsStdinMode,
    tty: bool,
    rlimits: Vec<JsRlimit>,
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
            args: Vec::new(),
            cwd: None,
            user: None,
            env: Vec::new(),
            timeout_ms: None,
            stdin: JsStdinMode {
                kind: "null".into(),
                data: None,
            },
            tty: false,
            rlimits: Vec::new(),
        }
    }

    /// Append a single command argument.
    #[napi]
    pub fn arg(&mut self, arg: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.arg(&arg));
        self.args.push(arg);
        self
    }

    /// Append a list of command arguments.
    #[napi]
    pub fn args(&mut self, args: Vec<String>) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.args(args.clone()));
        self.args.extend(args);
        self
    }

    /// Override the working directory.
    #[napi]
    pub fn cwd(&mut self, cwd: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.cwd(&cwd));
        self.cwd = Some(cwd);
        self
    }

    /// Override the running user.
    #[napi]
    pub fn user(&mut self, user: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.user(&user));
        self.user = Some(user);
        self
    }

    /// Set a single environment variable.
    #[napi]
    pub fn env(&mut self, key: String, value: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.env(&key, &value));
        self.env.push((key, value));
        self
    }

    /// Set environment variables from an object.
    #[napi]
    pub fn envs(&mut self, vars: HashMap<String, String>) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.envs(vars.clone()));
        for (k, v) in vars {
            self.env.push((k, v));
        }
        self
    }

    /// Kill the process if it hasn't exited within `ms` milliseconds.
    #[napi]
    pub fn timeout(&mut self, ms: u32) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.timeout(Duration::from_millis(ms as u64)));
        self.timeout_ms = Some(ms);
        self
    }

    #[napi(js_name = "stdinNull")]
    pub fn stdin_null(&mut self) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.stdin_null());
        self.stdin = JsStdinMode {
            kind: "null".into(),
            data: None,
        };
        self
    }

    #[napi(js_name = "stdinPipe")]
    pub fn stdin_pipe(&mut self) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.stdin_pipe());
        self.stdin = JsStdinMode {
            kind: "pipe".into(),
            data: None,
        };
        self
    }

    #[napi(js_name = "stdinBytes")]
    pub fn stdin_bytes(&mut self, data: Buffer) -> &Self {
        let bytes = data.to_vec();
        let prev = self.take_inner();
        self.inner = Some(prev.stdin_bytes(bytes.clone()));
        self.stdin = JsStdinMode {
            kind: "bytes".into(),
            data: Some(bytes),
        };
        self
    }

    #[napi]
    pub fn tty(&mut self, enabled: bool) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.tty(enabled));
        self.tty = enabled;
        self
    }

    #[napi]
    pub fn rlimit(&mut self, resource: String, limit: u32) -> Result<&Self> {
        let res = parse_rlimit_resource(&resource)?;
        let prev = self.take_inner();
        self.inner = Some(prev.rlimit(res, limit as u64));
        self.rlimits.push(JsRlimit {
            resource,
            soft: limit,
            hard: limit,
        });
        Ok(self)
    }

    #[napi(js_name = "rlimitRange")]
    pub fn rlimit_range(&mut self, resource: String, soft: u32, hard: u32) -> Result<&Self> {
        let res = parse_rlimit_resource(&resource)?;
        let prev = self.take_inner();
        self.inner = Some(prev.rlimit_range(res, soft as u64, hard as u64));
        self.rlimits.push(JsRlimit {
            resource,
            soft,
            hard,
        });
        Ok(self)
    }

    /// Snapshot the accumulated configuration.
    #[napi]
    pub fn build(&self) -> JsExecOptions {
        JsExecOptions {
            args: self.args.clone(),
            cwd: self.cwd.clone(),
            user: self.user.clone(),
            env: self.env.iter().cloned().collect(),
            timeout_ms: self.timeout_ms,
            stdin: self.stdin.clone(),
            tty: self.tty,
            rlimits: self.rlimits.clone(),
        }
    }
}

impl JsExecOptionsBuilder {
    fn take_inner(&mut self) -> RustExecOptionsBuilder {
        self.inner
            .take()
            .expect("ExecOptionsBuilder used after consumption")
    }

    /// Internal: extract the underlying Rust builder. Used by
    /// `Sandbox.execWithBuilder` / `execStreamWithBuilder`.
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
