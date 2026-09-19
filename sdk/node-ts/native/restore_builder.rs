use microsandbox::sandbox::{LogLevel as RustLogLevel, RestoreBuilder, SecurityProfile};
use microsandbox::size::Mebibytes;
use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::error::to_napi_error;
use crate::mount_builder::JsMountBuilder;
use crate::network_policy_builder::JsNetworkPolicyBuilder;
use crate::pull_progress::JsPullProgressStream;
use crate::sandbox::Sandbox;
use crate::sandbox_builder::{JsPullProgressCreate, parse_bind_addr};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Snapshot restoration with explicit destination resource bindings.
#[napi(js_name = "RestoreBuilder")]
pub struct JsRestoreBuilder {
    inner: Option<RestoreBuilder>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsRestoreBuilder {
    /// Select an installed snapshot or archive; this does not start a VM.
    #[napi(constructor)]
    pub fn new(snapshot: String, reference_kind: Option<String>) -> Result<Self> {
        // A remote path must stay a path even when it resembles a managed identifier.
        let reference = match reference_kind.as_deref() {
            None | Some("auto") => microsandbox::SnapshotReference::auto(snapshot),
            Some("id") => microsandbox::SnapshotReference::id(snapshot),
            Some("path") => microsandbox::SnapshotReference::path(snapshot),
            Some(kind) => {
                return Err(napi::Error::from_reason(format!(
                    "unknown snapshot reference kind: {kind}"
                )));
            }
        };
        Ok(Self {
            inner: Some(microsandbox::Sandbox::restore_ref(reference)),
        })
    }

    /// Choose the destination sandbox name.
    #[napi]
    pub fn name(&mut self, name: String) -> Result<&Self> {
        let inner = self.take_inner()?;
        self.inner = Some(inner.name(name));
        Ok(self)
    }

    /// Set destination CPUs; full execution restore requires the captured count.
    #[napi]
    pub fn cpus(&mut self, count: u32) -> Result<&Self> {
        let count =
            u8::try_from(count).map_err(|_| napi::Error::from_reason("cpus out of u8 range"))?;
        self.inner = Some(self.take_inner()?.cpus(count));
        Ok(self)
    }

    /// Set destination memory in MiB; full execution restore requires captured geometry.
    #[napi]
    pub fn memory(&mut self, mib: u32) -> Result<&Self> {
        self.inner = Some(self.take_inner()?.memory(Mebibytes::from(mib)));
        Ok(self)
    }

    /// Set only host-side network policy, without DNS, TLS, or guest bootstrap changes.
    #[napi(js_name = "networkPolicyJson")]
    pub fn network_policy_json(&mut self, json: String) -> Result<&Self> {
        let value: serde_json::Value = serde_json::from_str(&json)
            .map_err(|e| napi::Error::from_reason(format!("invalid policy JSON: {e}")))?;
        let fields = value
            .as_object()
            .ok_or_else(|| napi::Error::from_reason("restore network policy must be an object"))?;
        if fields
            .keys()
            .any(|key| !matches!(key.as_str(), "default_egress" | "default_ingress" | "rules"))
        {
            return Err(napi::Error::from_reason(
                "restore network policy accepts only default actions and rules",
            ));
        }
        let policy = serde_json::from_value(value)
            .map_err(|e| napi::Error::from_reason(format!("invalid policy JSON: {e}")))?;
        self.inner = Some(self.take_inner()?.network_policy(policy));
        Ok(self)
    }

    /// Set host-side policy from the existing policy builder.
    #[napi(js_name = "networkPolicyFromBuilder")]
    pub fn network_policy_from_builder(
        &mut self,
        builder: &JsNetworkPolicyBuilder,
    ) -> Result<&Self> {
        let policy = builder.build_rust_policy()?;
        self.inner = Some(self.take_inner()?.network_policy(policy));
        Ok(self)
    }

    /// @deprecated Use maxTcpConnections instead.
    #[napi(js_name = "maxConnections")]
    pub fn max_connections(&mut self, count: u32) -> Result<&Self> {
        self.max_tcp_connections(count)
    }

    /// Cap destination host-side TCP connections; zero selects unlimited.
    #[napi(js_name = "maxTcpConnections")]
    pub fn max_tcp_connections(&mut self, count: u32) -> Result<&Self> {
        self.inner = Some(self.take_inner()?.max_tcp_connections(count as usize));
        Ok(self)
    }

    /// Cap destination host-side UDP sessions; zero selects unlimited.
    #[napi(js_name = "maxUdpConnections")]
    pub fn max_udp_connections(&mut self, count: u32) -> Result<&Self> {
        self.inner = Some(self.take_inner()?.max_udp_connections(count as usize));
        Ok(self)
    }

    /// Disable networking; full restore rejects removal of a captured NIC.
    #[napi(js_name = "disableNetwork")]
    pub fn disable_network(&mut self) -> Result<&Self> {
        self.inner = Some(self.take_inner()?.disable_network());
        Ok(self)
    }

    /// Set guest security for disk boot; explicit changes are rejected by full restore.
    #[napi(ts_args_type = "profile: 'default' | 'restricted'")]
    pub fn security(&mut self, profile: String) -> Result<&Self> {
        let profile = match profile.as_str() {
            "default" => SecurityProfile::Default,
            "restricted" => SecurityProfile::Restricted,
            _ => {
                return Err(napi::Error::from_reason(
                    "invalid security profile (expected default | restricted)",
                ));
            }
        };
        self.inner = Some(self.take_inner()?.security(profile));
        Ok(self)
    }

    /// Apply the destination host's maximum runtime in seconds; zero expires immediately.
    #[napi(js_name = "maxDuration")]
    pub fn max_duration(&mut self, secs: f64) -> Result<&Self> {
        let seconds = duration_seconds(secs).map_err(napi::Error::from_reason)?;
        self.inner = Some(self.take_inner()?.max_duration(seconds));
        Ok(self)
    }

    /// Apply the destination host's idle timeout in seconds; zero expires immediately.
    #[napi(js_name = "idleTimeout")]
    pub fn idle_timeout(&mut self, secs: f64) -> Result<&Self> {
        let seconds = duration_seconds(secs).map_err(napi::Error::from_reason)?;
        self.inner = Some(self.take_inner()?.idle_timeout(seconds));
        Ok(self)
    }

    /// Accept missing restore resources without inheriting host resources.
    #[napi]
    pub fn allow_missing_resources(&mut self) -> Result<&Self> {
        self.inner = Some(self.take_inner()?.allow_missing_resources());
        Ok(self)
    }

    /// Explicitly reuse locally validated source resource bindings.
    #[napi]
    pub fn dangerously_inherit_resources(&mut self) -> Result<&Self> {
        let inner = self.take_inner()?;
        self.inner = Some(inner.dangerously_inherit_resources());
        Ok(self)
    }
    /// Supply the base for omitted disk layers and RAM objects in a snapshot archive.
    #[napi]
    pub fn snapshot_base(&mut self, base: String) -> Result<&Self> {
        let prev = self.take_inner()?;
        self.inner = Some(prev.snapshot_base(base));
        Ok(self)
    }

    /// Cold-boot only the disk state carried by a full snapshot.
    #[napi(js_name = "diskOnly")]
    pub fn disk_only(&mut self) -> Result<&Self> {
        let prev = self.take_inner()?;
        self.inner = Some(prev.disk_only());
        Ok(self)
    }

    /// Restore a full snapshot with private copy-on-write memory.
    #[napi]
    pub fn forked(&mut self) -> Result<&Self> {
        let prev = self
            .inner
            .take()
            .ok_or_else(|| napi::Error::from_reason("builder already consumed"))?;
        self.inner = Some(prev.forked());
        Ok(self)
    }

    /// Validate authorized filesystem mappings strictly (default) or allow supported mismatches.
    /// Neither policy inherits resources; unmapped filesystems remain unavailable.
    #[napi(ts_args_type = "policy: 'strict' | 'relaxed'")]
    pub fn external_mount_policy(&mut self, policy: String) -> Result<&Self> {
        let policy = match policy.as_str() {
            "strict" => microsandbox::sandbox::ExternalMountRestorePolicy::Strict,
            "relaxed" => microsandbox::sandbox::ExternalMountRestorePolicy::Relaxed,
            _ => {
                return Err(napi::Error::from_reason(
                    "external mount policy must be strict or relaxed",
                ));
            }
        };
        let previous = self.take_inner()?;
        self.inner = Some(previous.external_mount_policy(policy));
        Ok(self)
    }

    /// Override log verbosity: `"trace" | "debug" | "info" | "warn" | "error"`.
    #[napi(js_name = "logLevel")]
    pub fn log_level(&mut self, level: String) -> Result<&Self> {
        let l = match level.as_str() {
            "trace" => RustLogLevel::Trace,
            "debug" => RustLogLevel::Debug,
            "info" => RustLogLevel::Info,
            "warn" => RustLogLevel::Warn,
            "error" => RustLogLevel::Error,
            other => {
                return Err(napi::Error::from_reason(format!(
                    "invalid log level `{other}`"
                )));
            }
        };
        let prev = self.take_inner()?;
        self.inner = Some(prev.log_level(l));
        Ok(self)
    }

    /// Default running user.
    #[napi]
    pub fn user(&mut self, user: String) -> Result<&Self> {
        let prev = self.take_inner()?;
        self.inner = Some(prev.user(user));
        Ok(self)
    }

    /// Configure a volume mount via a callback. The callback receives a
    /// `MountBuilder` already pre-bound to `guestPath`.
    #[napi]
    pub fn volume(
        &mut self,
        env: &Env,
        guest_path: String,
        configure: Function<ClassInstance<JsMountBuilder>, ClassInstance<JsMountBuilder>>,
    ) -> Result<&Self> {
        let initial = JsMountBuilder::new(guest_path.clone()).into_instance(env)?;
        let mut returned = configure.call(initial)?;
        let mount_builder = returned.take_inner_builder()?;
        let prev = self.take_inner()?;
        // The core's volume() signature is volume(guest_path, FnOnce(MountBuilder) -> MountBuilder).
        // The MountBuilder we hand back already encodes the guest path
        // (we constructed it that way above); the default supplied by
        // the core is discarded.
        self.inner = Some(prev.volume(guest_path, |_default| mount_builder));
        Ok(self)
    }

    /// Publish a TCP port from host -> guest.
    #[napi]
    pub fn port(&mut self, host_port: u32, guest_port: u32) -> Result<&Self> {
        let h = u16::try_from(host_port)
            .map_err(|_| napi::Error::from_reason("host port out of range"))?;
        let g = u16::try_from(guest_port)
            .map_err(|_| napi::Error::from_reason("guest port out of range"))?;
        let prev = self.take_inner()?;
        self.inner = Some(prev.port(h, g));
        Ok(self)
    }

    /// Publish a TCP port from host -> guest on a specific host bind address.
    #[napi(js_name = "portBind")]
    pub fn port_bind(&mut self, bind: String, host_port: u32, guest_port: u32) -> Result<&Self> {
        let bind = parse_bind_addr(&bind)?;
        let h = u16::try_from(host_port)
            .map_err(|_| napi::Error::from_reason("host port out of range"))?;
        let g = u16::try_from(guest_port)
            .map_err(|_| napi::Error::from_reason("guest port out of range"))?;
        let prev = self.take_inner()?;
        self.inner = Some(prev.port_bind(bind, h, g));
        Ok(self)
    }

    /// Publish a UDP port from host -> guest.
    #[napi(js_name = "portUdp")]
    pub fn port_udp(&mut self, host_port: u32, guest_port: u32) -> Result<&Self> {
        let h = u16::try_from(host_port)
            .map_err(|_| napi::Error::from_reason("host port out of range"))?;
        let g = u16::try_from(guest_port)
            .map_err(|_| napi::Error::from_reason("guest port out of range"))?;
        let prev = self.take_inner()?;
        self.inner = Some(prev.port_udp(h, g));
        Ok(self)
    }

    /// Publish a UDP port from host -> guest on a specific host bind address.
    #[napi(js_name = "portUdpBind")]
    pub fn port_udp_bind(
        &mut self,
        bind: String,
        host_port: u32,
        guest_port: u32,
    ) -> Result<&Self> {
        let bind = parse_bind_addr(&bind)?;
        let h = u16::try_from(host_port)
            .map_err(|_| napi::Error::from_reason("host port out of range"))?;
        let g = u16::try_from(guest_port)
            .map_err(|_| napi::Error::from_reason("guest port out of range"))?;
        let prev = self.take_inner()?;
        self.inner = Some(prev.port_udp_bind(bind, h, g));
        Ok(self)
    }

    /// Expose a host Unix stream socket or local Windows named pipe on a guest-to-host vsock port.
    #[napi]
    pub fn vsock(&mut self, host_path: String, port: u32) -> Result<&Self> {
        let prev = self.take_inner()?;
        self.inner = Some(prev.vsock(host_path, port));
        Ok(self)
    }

    /// Expose a host Unix datagram socket on a guest-to-host vsock port.
    #[napi(js_name = "vsockDgram")]
    pub fn vsock_dgram(&mut self, host_path: String, port: u32) -> Result<&Self> {
        let prev = self.take_inner()?;
        self.inner = Some(prev.vsock_dgram(host_path, port));
        Ok(self)
    }

    /// Restore a detached sandbox and wait until ready.
    ///
    /// # Safety
    /// The builder is consumed before suspension; callers must not reuse it.
    #[napi]
    pub async unsafe fn restore(&mut self) -> Result<Sandbox> {
        let inner = self.take_inner()?;
        Ok(Sandbox::from_rust(
            inner.restore().await.map_err(to_napi_error)?,
        ))
    }

    /// Restore with image, snapshot preparation and activation progress.
    ///
    /// # Safety
    /// The builder is consumed before suspension; callers must not reuse it.
    #[napi]
    pub async unsafe fn restore_with_progress(&mut self) -> Result<JsPullProgressCreate> {
        let (handle, task) = self
            .take_inner()?
            .restore_with_progress()
            .map_err(to_napi_error)?;
        Ok(JsPullProgressCreate {
            stream: JsPullProgressStream::from_creation(handle),
            abort: task.abort_handle(),
            task: std::sync::Arc::new(tokio::sync::Mutex::new(Some(task))),
        })
    }
}

impl JsRestoreBuilder {
    fn take_inner(&mut self) -> Result<RestoreBuilder> {
        self.inner
            .take()
            .ok_or_else(|| napi::Error::from_reason("RestoreBuilder already consumed"))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Retain explicit zero, but never truncate a positive limit into immediate expiry.
fn duration_seconds(seconds: f64) -> std::result::Result<u64, &'static str> {
    // Keep validation independent of Node's error lifecycle so standalone Rust tests
    // do not need N-API symbols. Only the public binding creates JavaScript errors.
    if !seconds.is_finite() || seconds < 0.0 || seconds >= u64::MAX as f64 {
        return Err("restore duration must be finite, non-negative, and fit in seconds");
    }
    Ok(seconds.ceil() as u64)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::duration_seconds;

    #[test]
    fn restore_duration_preserves_zero_and_rounds_positive_limits_up() {
        assert_eq!(duration_seconds(0.0).unwrap(), 0);
        assert_eq!(duration_seconds(-0.0).unwrap(), 0);
        assert_eq!(duration_seconds(0.5).unwrap(), 1);
        assert_eq!(duration_seconds(1.5).unwrap(), 2);
        assert_eq!(duration_seconds(f64::MIN_POSITIVE).unwrap(), 1);
        for value in [
            -1.0,
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            u64::MAX as f64,
        ] {
            assert_eq!(
                duration_seconds(value).unwrap_err(),
                "restore duration must be finite, non-negative, and fit in seconds",
            );
        }
    }
}
