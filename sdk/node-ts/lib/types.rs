use std::collections::HashMap;

use napi_derive::napi;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Configuration for creating a sandbox.
#[napi(object)]
pub struct SandboxConfig {
    /// Unique sandbox name.
    pub name: String,
    /// OCI image ref (e.g. "python:3.12"), host path, or disk image path.
    pub image: String,
    /// Guest memory in MiB (default: 512).
    pub memory_mib: Option<u32>,
    /// Virtual CPU count (default: 1).
    pub cpus: Option<u8>,
    /// Working directory inside the guest.
    pub workdir: Option<String>,
    /// Default shell binary path.
    pub shell: Option<String>,
    /// Override image entrypoint.
    pub entrypoint: Option<Vec<String>>,
    /// Override image cmd.
    pub cmd: Option<Vec<String>>,
    /// Guest hostname.
    pub hostname: Option<String>,
    /// User to run as (UID or name).
    pub user: Option<String>,
    /// Environment variables.
    pub env: Option<HashMap<String, String>>,
    /// Named scripts that can be run via `sandbox.run(name)`.
    pub scripts: Option<HashMap<String, String>>,
    /// Volume mounts keyed by guest path.
    pub volumes: Option<HashMap<String, MountConfig>>,
    /// Rootfs patches applied before boot.
    pub patches: Option<Vec<PatchConfig>>,
    /// Image pull policy: "always", "if-missing", or "never".
    pub pull_policy: Option<String>,
    /// Log level: "trace", "debug", "info", "warn", "error".
    pub log_level: Option<String>,
    /// Kill any existing sandbox with the same name before creating.
    pub replace: Option<bool>,
    /// Suppress log output.
    pub quiet_logs: Option<bool>,
    /// Arbitrary key-value labels.
    pub labels: Option<HashMap<String, String>>,
    /// Signal to send on stop (default: SIGTERM).
    pub stop_signal: Option<String>,
    /// Maximum run duration in seconds.
    pub max_duration_secs: Option<f64>,
    /// Registry connection settings (auth, TLS, insecure).
    pub registry: Option<RegistryConfig>,
    /// Port mappings: host_port → guest_port (TCP).
    pub ports: Option<HashMap<String, u32>>,
    /// Network configuration.
    pub network: Option<NetworkConfig>,
    /// Secret entries. Created with `Secret.env()`.
    ///
    /// ```js
    /// import { Secret } from 'microsandbox'
    /// secrets: [
    ///     Secret.env("OPENAI_API_KEY", { value: "sk-...", allowHosts: ["api.openai.com"] }),
    /// ]
    /// ```
    pub secrets: Option<Vec<SecretEntry>>,
}

/// Volume mount configuration.
#[napi(object)]
pub struct MountConfig {
    /// Mount a host directory. Mutually exclusive with `named` and `tmpfs`.
    pub bind: Option<String>,
    /// Mount a named volume. Mutually exclusive with `bind` and `tmpfs`.
    pub named: Option<String>,
    /// Use tmpfs (memory-backed). Mutually exclusive with `bind` and `named`.
    pub tmpfs: Option<bool>,
    /// Read-only mount.
    pub readonly: Option<bool>,
    /// Size limit in MiB (for tmpfs).
    pub size_mib: Option<u32>,
}

/// Rootfs patch applied before VM startup.
#[napi(object)]
pub struct PatchConfig {
    /// Patch kind: "text", "file", "copyFile", "copyDir", "symlink", "mkdir", "remove", "append".
    pub kind: String,
    /// Guest path (all kinds except symlink where it's `link`).
    pub path: Option<String>,
    /// Text content (for "text" and "append" kinds).
    pub content: Option<String>,
    /// Source host path (for "copyFile" and "copyDir" kinds).
    pub src: Option<String>,
    /// Destination guest path (for "copyFile" and "copyDir" kinds).
    pub dst: Option<String>,
    /// Symlink target path (for "symlink" kind).
    pub target: Option<String>,
    /// Symlink link path (for "symlink" kind).
    pub link: Option<String>,
    /// File permissions (e.g. 0o644).
    pub mode: Option<u32>,
    /// Allow replacing existing files.
    pub replace: Option<bool>,
}

/// Network configuration.
#[napi(object)]
pub struct NetworkConfig {
    /// Preset policy: "public-only" (default), "allow-all", or "none".
    /// Ignored if `rules` is provided.
    pub policy: Option<String>,
    /// Custom policy rules (first match wins). Overrides `policy` preset.
    pub rules: Option<Vec<PolicyRule>>,
    /// Default action when no rule matches: "allow" or "deny".
    pub default_action: Option<String>,
    /// DNS interception configuration.
    pub dns: Option<DnsConfig>,
    /// TLS interception configuration.
    pub tls: Option<TlsConfig>,
    /// Max concurrent connections (default: 256).
    pub max_connections: Option<u32>,
}

/// DNS interception configuration.
#[napi(object)]
pub struct DnsConfig {
    /// Block specific domains (returns REFUSED).
    pub block_domains: Option<Vec<String>>,
    /// Block domain suffixes (returns REFUSED).
    pub block_domain_suffixes: Option<Vec<String>>,
    /// Enable DNS rebinding protection (default: true).
    pub rebind_protection: Option<bool>,
    /// Nameservers to forward queries to. Accepts `IP`, `IP:PORT`,
    /// `HOST`, or `HOST:PORT`. When set, overrides the host's
    /// /etc/resolv.conf.
    pub nameservers: Option<Vec<String>>,
    /// Per-DNS-query timeout in milliseconds (default: 5000).
    pub query_timeout_ms: Option<u32>,
}

/// A network policy rule.
#[napi(object)]
pub struct PolicyRule {
    /// "allow" or "deny".
    pub action: String,
    /// "outbound" or "inbound".
    pub direction: Option<String>,
    /// Destination filter. One of:
    /// - "*" — any destination
    /// - "1.2.3.4/24" — CIDR notation
    /// - "example.com" — exact domain
    /// - ".example.com" — domain suffix
    /// - "loopback", "private", "link-local", "metadata", "multicast" — destination group
    pub destination: Option<String>,
    /// Protocol filter: "tcp", "udp", "icmpv4", "icmpv6".
    pub protocol: Option<String>,
    /// Port or port range (e.g. 443 or "8000-9000").
    pub port: Option<String>,
}

/// TLS interception configuration.
#[napi(object)]
pub struct TlsConfig {
    /// Domains to bypass (no interception). Supports "*.suffix" wildcards.
    pub bypass: Option<Vec<String>>,
    /// Verify upstream server certificates (default: true).
    pub verify_upstream: Option<bool>,
    /// Ports to intercept (default: [443]).
    pub intercepted_ports: Option<Vec<u32>>,
    /// Block QUIC on intercepted ports (default: false).
    pub block_quic: Option<bool>,
    /// Path to custom interception CA certificate PEM file.
    pub intercept_ca_cert: Option<String>,
    /// Path to custom interception CA private key PEM file.
    pub intercept_ca_key: Option<String>,
    /// Paths to additional CA certificate PEM files to trust for upstream verification.
    pub upstream_ca_cert: Option<Vec<String>>,
}

/// A secret entry for the `secrets` array on `SandboxConfig`.
///
/// Created via `Secret.env()`:
/// ```js
/// import { Secret } from 'microsandbox'
/// Secret.env("OPENAI_API_KEY", { value: "sk-...", allowHosts: ["api.openai.com"] })
/// ```
#[napi(object)]
pub struct SecretEntry {
    /// Environment variable name.
    pub env_var: String,
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

/// Registry connection settings.
#[napi(object)]
pub struct RegistryConfig {
    /// Authentication credentials.
    pub auth: Option<RegistryAuth>,
    /// Access the registry over plain HTTP instead of HTTPS.
    pub insecure: Option<bool>,
    /// Path to a PEM file containing additional CA root certificates to trust.
    pub ca_certs_path: Option<String>,
}

/// Registry authentication credentials.
#[napi(object)]
pub struct RegistryAuth {
    pub username: String,
    pub password: String,
}

/// Process exit status.
#[napi(object)]
pub struct ExitStatus {
    pub code: i32,
    pub success: bool,
}

/// Filesystem entry metadata returned by `fs.list()`.
#[napi(object)]
pub struct FsEntry {
    pub path: String,
    /// "file", "directory", "symlink", or "other".
    pub kind: String,
    pub size: f64,
    pub mode: u32,
    pub modified: Option<f64>,
}

/// Filesystem metadata returned by `fs.stat()`.
#[napi(object)]
pub struct FsMetadata {
    /// "file", "directory", "symlink", or "other".
    pub kind: String,
    pub size: f64,
    pub mode: u32,
    pub readonly: bool,
    pub modified: Option<f64>,
    pub created: Option<f64>,
}

/// Point-in-time resource metrics for a sandbox.
#[napi(object)]
pub struct SandboxMetrics {
    pub cpu_percent: f64,
    pub memory_bytes: f64,
    pub memory_limit_bytes: f64,
    pub disk_read_bytes: f64,
    pub disk_write_bytes: f64,
    pub net_rx_bytes: f64,
    pub net_tx_bytes: f64,
    /// Uptime in milliseconds.
    pub uptime_ms: f64,
    /// Timestamp as milliseconds since Unix epoch.
    pub timestamp_ms: f64,
}

/// Execution event emitted by `ExecHandle.recv()`.
#[napi(object)]
pub struct ExecEvent {
    /// "started", "stdout", "stderr", or "exited".
    pub event_type: String,
    /// Process ID (only for "started" events).
    pub pid: Option<u32>,
    /// Output data (only for "stdout" and "stderr" events).
    pub data: Option<napi::bindgen_prelude::Buffer>,
    /// Exit code (only for "exited" events).
    pub code: Option<i32>,
}

/// Image pull / materialize progress event emitted by `PullSession`.
///
/// The `eventType` string is the discriminator; only a subset of the other
/// fields is populated for each variant. The variants mirror the Rust
/// `microsandbox_image::PullProgress` enum:
///
/// - `"resolving"` — `reference`
/// - `"resolved"` — `reference`, `manifestDigest`, `layerCount`, `totalDownloadBytes`
/// - `"layer_download_progress"` — `layerIndex`, `digest`, `downloadedBytes`, `totalBytes`
/// - `"layer_download_complete"` — `layerIndex`, `digest`, `downloadedBytes`
/// - `"layer_download_verifying"` — `layerIndex`, `digest`
/// - `"layer_materialize_started"` — `layerIndex`, `diffId`
/// - `"layer_materialize_progress"` — `layerIndex`, `bytesRead`, `totalBytes`
/// - `"layer_materialize_writing"` — `layerIndex`
/// - `"layer_materialize_complete"` — `layerIndex`, `diffId`
/// - `"stitch_merging_trees"` — `layerCount`
/// - `"stitch_writing_fsmeta"` — (no fields)
/// - `"stitch_writing_vmdk"` — (no fields)
/// - `"stitch_complete"` — (no fields)
/// - `"complete"` — `reference`, `layerCount`
#[napi(object)]
pub struct PullEvent {
    pub event_type: String,
    pub reference: Option<String>,
    pub manifest_digest: Option<String>,
    pub layer_count: Option<u32>,
    /// Sum of compressed layer sizes. `null` if the manifest omits sizes.
    pub total_download_bytes: Option<f64>,
    pub layer_index: Option<u32>,
    pub digest: Option<String>,
    pub diff_id: Option<String>,
    pub downloaded_bytes: Option<f64>,
    /// Total bytes for the current layer. `null` if the manifest omits sizes.
    pub total_bytes: Option<f64>,
    pub bytes_read: Option<f64>,
}

/// Configuration for command execution.
#[napi(object)]
pub struct ExecConfig {
    /// Command to execute.
    pub cmd: String,
    /// Command arguments.
    pub args: Option<Vec<String>>,
    /// Working directory inside the sandbox.
    pub cwd: Option<String>,
    /// User to run as.
    pub user: Option<String>,
    /// Environment variables.
    pub env: Option<HashMap<String, String>>,
    /// Timeout in milliseconds.
    pub timeout_ms: Option<f64>,
    /// Stdin mode: "null" (default), "pipe", or a string to send as stdin bytes.
    pub stdin: Option<String>,
    /// Enable pseudo-TTY.
    pub tty: Option<bool>,
}

/// Configuration for interactive attach sessions.
#[napi(object)]
pub struct AttachConfig {
    /// Command to execute.
    pub cmd: String,
    /// Command arguments.
    pub args: Option<Vec<String>>,
    /// Working directory inside the sandbox.
    pub cwd: Option<String>,
    /// User to run as.
    pub user: Option<String>,
    /// Environment variables.
    pub env: Option<HashMap<String, String>>,
    /// Detach key sequence (default: "ctrl-]"). Uses Docker-style syntax.
    pub detach_keys: Option<String>,
}

/// Lightweight handle info for a sandbox from the database.
#[napi(object)]
pub struct SandboxInfo {
    pub name: String,
    /// "running", "stopped", "crashed", or "draining".
    pub status: String,
    pub config_json: String,
    pub created_at: Option<f64>,
    pub updated_at: Option<f64>,
}

/// Volume configuration for creation.
#[napi(object)]
pub struct VolumeConfig {
    pub name: String,
    /// Size quota in MiB.
    pub quota_mib: Option<u32>,
    /// Arbitrary key-value labels.
    pub labels: Option<HashMap<String, String>>,
}

/// Volume handle info from the database.
#[napi(object)]
pub struct VolumeInfo {
    pub name: String,
    pub quota_mib: Option<u32>,
    pub used_bytes: f64,
    pub labels: HashMap<String, String>,
    pub created_at: Option<f64>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Convert `chrono::DateTime<Utc>` to milliseconds since epoch for JS `Date`.
pub fn datetime_to_ms(dt: &chrono::DateTime<chrono::Utc>) -> f64 {
    dt.timestamp_millis() as f64
}

/// Convert optional datetime to optional ms.
pub fn opt_datetime_to_ms(dt: &Option<chrono::DateTime<chrono::Utc>>) -> Option<f64> {
    dt.as_ref().map(datetime_to_ms)
}
