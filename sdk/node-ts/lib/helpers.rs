use napi_derive::napi;

use crate::types::*;

//--------------------------------------------------------------------------------------------------
// Types: Enums
//--------------------------------------------------------------------------------------------------

/// Image pull policy.
#[napi(string_enum)]
pub enum PullPolicy {
    #[napi(value = "always")]
    Always,
    #[napi(value = "if-missing")]
    IfMissing,
    #[napi(value = "never")]
    Never,
}

/// Log level for sandbox process output.
#[napi(string_enum)]
pub enum LogLevel {
    #[napi(value = "trace")]
    Trace,
    #[napi(value = "debug")]
    Debug,
    #[napi(value = "info")]
    Info,
    #[napi(value = "warn")]
    Warn,
    #[napi(value = "error")]
    Error,
}

//--------------------------------------------------------------------------------------------------
// Types: Helper Option Objects
//--------------------------------------------------------------------------------------------------

/// Options for bind and named volume mounts.
#[napi(object)]
pub struct MountOptions {
    /// Read-only mount.
    pub readonly: Option<bool>,
}

/// Options for tmpfs mounts.
#[napi(object)]
pub struct TmpfsOptions {
    /// Size limit in MiB.
    pub size_mib: Option<u32>,
    /// Read-only mount.
    pub readonly: Option<bool>,
}

/// Options for `Secret.env()`.
#[napi(object)]
pub struct SecretEnvOptions {
    /// The secret value (never enters the sandbox).
    pub value: String,
    /// Allowed hosts (exact match, e.g. `["api.openai.com"]`).
    pub allow_hosts: Option<Vec<String>>,
    /// Allowed host patterns (wildcard, e.g. `["*.openai.com"]`).
    pub allow_host_patterns: Option<Vec<String>>,
    /// Custom placeholder (auto-generated as `$MSB_<ENV_VAR>` if omitted).
    pub placeholder: Option<String>,
    /// Require verified TLS identity before substitution (default: true).
    pub require_tls: Option<bool>,
    /// Violation action: "block", "block-and-log" (default), "block-and-terminate".
    pub on_violation: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Types: Helper Classes
//--------------------------------------------------------------------------------------------------

/// Factory for creating volume mount configurations.
///
/// ```js
/// import { Mount, Sandbox } from 'microsandbox'
///
/// const sb = await Sandbox.create({
///     name: "worker",
///     image: "python:3.12",
///     volumes: {
///         "/app/src": Mount.bind("./src", { readonly: true }),
///         "/data": Mount.named("my-data"),
///         "/tmp": Mount.tmpfs({ sizeMib: 100 }),
///     },
/// })
/// ```
#[napi]
pub struct Mount;

/// Factory for creating network policy configurations.
///
/// ```js
/// import { NetworkPolicy, Sandbox } from 'microsandbox'
///
/// const sb = await Sandbox.create({
///     name: "worker",
///     image: "python:3.12",
///     network: NetworkPolicy.publicOnly(),
/// })
/// ```
#[napi(js_name = "NetworkPolicy")]
pub struct JsNetworkPolicy;

/// Factory for creating secret entries.
///
/// ```js
/// import { Secret, Sandbox } from 'microsandbox'
///
/// const sb = await Sandbox.create({
///     name: "agent",
///     image: "python:3.12",
///     secrets: [
///         Secret.env("OPENAI_API_KEY", {
///             value: process.env.OPENAI_API_KEY,
///             allowHosts: ["api.openai.com"],
///         }),
///     ],
/// })
/// ```
#[napi]
pub struct Secret;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl Mount {
    /// Create a bind mount (host directory → guest path).
    #[napi]
    pub fn bind(path: String, opts: Option<MountOptions>) -> MountConfig {
        let readonly = opts.and_then(|o| o.readonly);
        MountConfig {
            bind: Some(path),
            named: None,
            tmpfs: None,
            readonly,
            size_mib: None,
        }
    }

    /// Create a named volume mount.
    #[napi]
    pub fn named(name: String, opts: Option<MountOptions>) -> MountConfig {
        let readonly = opts.and_then(|o| o.readonly);
        MountConfig {
            bind: None,
            named: Some(name),
            tmpfs: None,
            readonly,
            size_mib: None,
        }
    }

    /// Create a tmpfs (in-memory) mount.
    #[napi]
    pub fn tmpfs(opts: Option<TmpfsOptions>) -> MountConfig {
        let (size_mib, readonly) = opts
            .map(|o| (o.size_mib, o.readonly))
            .unwrap_or((None, None));
        MountConfig {
            bind: None,
            named: None,
            tmpfs: Some(true),
            readonly,
            size_mib,
        }
    }
}

#[napi]
impl JsNetworkPolicy {
    /// No network access at all.
    #[napi]
    pub fn none() -> NetworkConfig {
        NetworkConfig {
            policy: Some("none".to_string()),
            rules: None,
            default_action: None,
            block_domains: None,
            block_domain_suffixes: None,
            dns_rebind_protection: None,
            tls: None,
            max_connections: None,
        }
    }

    /// Public internet only — blocks private ranges (default).
    #[napi]
    pub fn public_only() -> NetworkConfig {
        NetworkConfig {
            policy: Some("public-only".to_string()),
            rules: None,
            default_action: None,
            block_domains: None,
            block_domain_suffixes: None,
            dns_rebind_protection: None,
            tls: None,
            max_connections: None,
        }
    }

    /// Unrestricted network access.
    #[napi]
    pub fn allow_all() -> NetworkConfig {
        NetworkConfig {
            policy: Some("allow-all".to_string()),
            rules: None,
            default_action: None,
            block_domains: None,
            block_domain_suffixes: None,
            dns_rebind_protection: None,
            tls: None,
            max_connections: None,
        }
    }
}

#[napi]
impl Secret {
    /// Create a secret bound to an environment variable.
    #[napi]
    pub fn env(env_var: String, opts: SecretEnvOptions) -> SecretEntry {
        SecretEntry {
            env_var,
            value: opts.value,
            allow_hosts: opts.allow_hosts,
            allow_host_patterns: opts.allow_host_patterns,
            placeholder: opts.placeholder,
            require_tls: opts.require_tls,
            on_violation: opts.on_violation,
        }
    }
}
