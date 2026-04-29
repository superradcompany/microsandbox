use std::collections::HashMap;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use microsandbox::sandbox::AttachOptionsBuilder as RustAttachOptionsBuilder;

use crate::exec_options_builder::{JsRlimit, parse_rlimit_resource};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Built attach options produced by `AttachOptionsBuilder.build()`.
#[derive(Clone)]
#[napi(object, js_name = "AttachOptions")]
pub struct JsAttachOptions {
    pub args: Vec<String>,
    pub cwd: Option<String>,
    pub user: Option<String>,
    pub env: HashMap<String, String>,
    pub detach_keys: Option<String>,
    pub rlimits: Vec<JsRlimit>,
}

/// Fluent builder for interactive attach options.
#[napi(js_name = "AttachOptionsBuilder")]
pub struct JsAttachOptionsBuilder {
    inner: Option<RustAttachOptionsBuilder>,
    args: Vec<String>,
    cwd: Option<String>,
    user: Option<String>,
    env: Vec<(String, String)>,
    detach_keys: Option<String>,
    rlimits: Vec<JsRlimit>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsAttachOptionsBuilder {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Some(RustAttachOptionsBuilder::default()),
            args: Vec::new(),
            cwd: None,
            user: None,
            env: Vec::new(),
            detach_keys: None,
            rlimits: Vec::new(),
        }
    }

    #[napi]
    pub fn arg(&mut self, arg: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.arg(&arg));
        self.args.push(arg);
        self
    }

    #[napi]
    pub fn args(&mut self, args: Vec<String>) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.args(args.clone()));
        self.args.extend(args);
        self
    }

    #[napi]
    pub fn cwd(&mut self, cwd: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.cwd(&cwd));
        self.cwd = Some(cwd);
        self
    }

    #[napi]
    pub fn user(&mut self, user: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.user(&user));
        self.user = Some(user);
        self
    }

    #[napi]
    pub fn env(&mut self, key: String, value: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.env(&key, &value));
        self.env.push((key, value));
        self
    }

    #[napi]
    pub fn envs(&mut self, vars: HashMap<String, String>) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.envs(vars.clone()));
        for (k, v) in vars {
            self.env.push((k, v));
        }
        self
    }

    /// Override the detach key sequence (Docker-style spec, e.g.
    /// `"ctrl-]"` or `"ctrl-p,ctrl-q"`). Default: `Ctrl+]`.
    #[napi(js_name = "detachKeys")]
    pub fn detach_keys(&mut self, keys: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.detach_keys(&keys));
        self.detach_keys = Some(keys);
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
    pub fn build(&self) -> JsAttachOptions {
        JsAttachOptions {
            args: self.args.clone(),
            cwd: self.cwd.clone(),
            user: self.user.clone(),
            env: self.env.iter().cloned().collect(),
            detach_keys: self.detach_keys.clone(),
            rlimits: self.rlimits.clone(),
        }
    }
}

impl JsAttachOptionsBuilder {
    fn take_inner(&mut self) -> RustAttachOptionsBuilder {
        self.inner
            .take()
            .expect("AttachOptionsBuilder used after consumption")
    }

    /// Internal: extract the underlying Rust builder. Used by
    /// `Sandbox.attachWithBuilder`.
    pub(crate) fn take_inner_builder(&mut self) -> Result<RustAttachOptionsBuilder> {
        self.inner
            .take()
            .ok_or_else(|| napi::Error::from_reason("AttachOptionsBuilder already consumed"))
    }
}
