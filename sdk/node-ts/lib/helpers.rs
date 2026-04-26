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

/// Action to take when a secret is sent to a disallowed host.
#[napi(string_enum)]
pub enum ViolationAction {
    /// Silently block the request.
    #[napi(value = "block")]
    Block,
    /// Block the request and log the violation.
    #[napi(value = "block-and-log")]
    BlockAndLog,
    /// Block the request and terminate the sandbox.
    #[napi(value = "block-and-terminate")]
    BlockAndTerminate,
}

/// Network policy rule action.
#[napi(string_enum)]
pub enum PolicyAction {
    #[napi(value = "allow")]
    Allow,
    #[napi(value = "deny")]
    Deny,
}

/// Network policy rule direction.
#[napi(string_enum)]
pub enum PolicyDirection {
    #[napi(value = "outbound")]
    Outbound,
    #[napi(value = "inbound")]
    Inbound,
}

/// Network policy rule protocol.
#[napi(string_enum)]
pub enum PolicyProtocol {
    #[napi(value = "tcp")]
    Tcp,
    #[napi(value = "udp")]
    Udp,
    #[napi(value = "icmpv4")]
    Icmpv4,
    #[napi(value = "icmpv6")]
    Icmpv6,
}

/// Sandbox status.
#[napi(string_enum)]
pub enum SandboxStatus {
    #[napi(value = "running")]
    Running,
    #[napi(value = "stopped")]
    Stopped,
    #[napi(value = "crashed")]
    Crashed,
    #[napi(value = "draining")]
    Draining,
}

/// Filesystem entry kind.
#[napi(string_enum)]
pub enum FsEntryKind {
    #[napi(value = "file")]
    File,
    #[napi(value = "directory")]
    Directory,
    #[napi(value = "symlink")]
    Symlink,
    #[napi(value = "other")]
    Other,
}

/// Execution event type.
#[napi(string_enum)]
pub enum ExecEventType {
    #[napi(value = "started")]
    Started,
    #[napi(value = "stdout")]
    Stdout,
    #[napi(value = "stderr")]
    Stderr,
    #[napi(value = "exited")]
    Exited,
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

/// Options for disk-image volume mounts.
#[napi(object)]
pub struct DiskOptions {
    /// Disk image format: `"qcow2"`, `"raw"`, or `"vmdk"`. When omitted,
    /// inferred from the file extension.
    pub format: Option<String>,
    /// Inner filesystem type the guest should mount (e.g. `"ext4"`). When
    /// omitted, agentd probes `/proc/filesystems`.
    pub fstype: Option<String>,
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
    /// Where in the HTTP request the secret can be injected. Defaults to
    /// headers + Basic Auth only; enable `queryParams` or `body` to widen scope.
    pub inject: Option<SecretInjection>,
}

/// Options for `Patch.text()` and `Patch.copyFile()`.
#[napi(object)]
pub struct PatchOptions {
    /// File permissions (e.g. 0o644).
    pub mode: Option<u32>,
    /// Allow replacing existing files.
    pub replace: Option<bool>,
}

/// Options for `Patch.copyDir()` and `Patch.symlink()`.
#[napi(object)]
pub struct PatchReplaceOptions {
    /// Allow replacing existing files/directories.
    pub replace: Option<bool>,
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
///     image: "python",
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
///     image: "python",
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
///     image: "python",
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

/// Factory for creating rootfs patch configurations.
///
/// ```js
/// import { Patch, Sandbox } from 'microsandbox'
///
/// const sb = await Sandbox.create({
///     name: "worker",
///     image: "alpine",
///     patches: [
///         Patch.text("/etc/greeting.txt", "Hello!\n"),
///         Patch.mkdir("/app", { mode: 0o755 }),
///         Patch.append("/etc/hosts", "127.0.0.1 myapp.local\n"),
///         Patch.copyFile("./config.json", "/app/config.json"),
///         Patch.copyDir("./scripts", "/app/scripts"),
///         Patch.symlink("/usr/bin/python3", "/usr/bin/python"),
///         Patch.remove("/etc/motd"),
///     ],
/// })
/// ```
#[napi]
pub struct Patch;

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
            disk: None,
            format: None,
            fstype: None,
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
            disk: None,
            format: None,
            fstype: None,
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
            disk: None,
            format: None,
            fstype: None,
            readonly,
            size_mib,
        }
    }

    /// Mount a host disk image as a virtio-blk device at a guest path.
    ///
    /// Format defaults to the file extension (`.qcow2` → Qcow2, `.vmdk` →
    /// Vmdk, anything else → Raw). Use `opts.format` to override. `fstype`
    /// (e.g. `"ext4"`) is the inner filesystem agentd will mount; when
    /// omitted, agentd probes `/proc/filesystems`.
    #[napi]
    pub fn disk(path: String, opts: Option<DiskOptions>) -> MountConfig {
        let (format, fstype, readonly) = opts
            .map(|o| (o.format, o.fstype, o.readonly))
            .unwrap_or((None, None, None));
        MountConfig {
            bind: None,
            named: None,
            tmpfs: None,
            disk: Some(path),
            format,
            fstype,
            readonly,
            size_mib: None,
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
            dns: None,
            tls: None,
            max_connections: None,
            trust_host_cas: None,
        }
    }

    /// Public internet only — blocks private ranges (default).
    #[napi]
    pub fn public_only() -> NetworkConfig {
        NetworkConfig {
            policy: Some("public-only".to_string()),
            rules: None,
            default_action: None,
            dns: None,
            tls: None,
            max_connections: None,
            trust_host_cas: None,
        }
    }

    /// Unrestricted network access.
    #[napi]
    pub fn allow_all() -> NetworkConfig {
        NetworkConfig {
            policy: Some("allow-all".to_string()),
            rules: None,
            default_action: None,
            dns: None,
            tls: None,
            max_connections: None,
            trust_host_cas: None,
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
            inject: opts.inject,
        }
    }
}

#[napi]
impl Patch {
    /// Write text content to a file in the guest filesystem.
    #[napi]
    pub fn text(path: String, content: String, opts: Option<PatchOptions>) -> PatchConfig {
        let (mode, replace) = opts.map(|o| (o.mode, o.replace)).unwrap_or((None, None));
        PatchConfig {
            kind: "text".to_string(),
            path: Some(path),
            content: Some(content),
            src: None,
            dst: None,
            target: None,
            link: None,
            mode,
            replace,
        }
    }

    /// Create a directory in the guest filesystem (idempotent).
    #[napi]
    pub fn mkdir(path: String, opts: Option<PatchOptions>) -> PatchConfig {
        let mode = opts.and_then(|o| o.mode);
        PatchConfig {
            kind: "mkdir".to_string(),
            path: Some(path),
            content: None,
            src: None,
            dst: None,
            target: None,
            link: None,
            mode,
            replace: None,
        }
    }

    /// Append content to an existing file in the guest filesystem.
    #[napi]
    pub fn append(path: String, content: String) -> PatchConfig {
        PatchConfig {
            kind: "append".to_string(),
            path: Some(path),
            content: Some(content),
            src: None,
            dst: None,
            target: None,
            link: None,
            mode: None,
            replace: None,
        }
    }

    /// Copy a file from the host into the guest filesystem.
    #[napi]
    pub fn copy_file(src: String, dst: String, opts: Option<PatchOptions>) -> PatchConfig {
        let (mode, replace) = opts.map(|o| (o.mode, o.replace)).unwrap_or((None, None));
        PatchConfig {
            kind: "copyFile".to_string(),
            path: None,
            content: None,
            src: Some(src),
            dst: Some(dst),
            target: None,
            link: None,
            mode,
            replace,
        }
    }

    /// Copy a directory from the host into the guest filesystem.
    #[napi]
    pub fn copy_dir(src: String, dst: String, opts: Option<PatchReplaceOptions>) -> PatchConfig {
        let replace = opts.and_then(|o| o.replace);
        PatchConfig {
            kind: "copyDir".to_string(),
            path: None,
            content: None,
            src: Some(src),
            dst: Some(dst),
            target: None,
            link: None,
            mode: None,
            replace,
        }
    }

    /// Create a symlink in the guest filesystem.
    #[napi]
    pub fn symlink(target: String, link: String, opts: Option<PatchReplaceOptions>) -> PatchConfig {
        let replace = opts.and_then(|o| o.replace);
        PatchConfig {
            kind: "symlink".to_string(),
            path: None,
            content: None,
            src: None,
            dst: None,
            target: Some(target),
            link: Some(link),
            mode: None,
            replace,
        }
    }

    /// Remove a file or directory from the guest filesystem (idempotent).
    #[napi]
    pub fn remove(path: String) -> PatchConfig {
        PatchConfig {
            kind: "remove".to_string(),
            path: Some(path),
            content: None,
            src: None,
            dst: None,
            target: None,
            link: None,
            mode: None,
            replace: None,
        }
    }
}
