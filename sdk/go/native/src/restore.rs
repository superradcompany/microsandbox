//! Dedicated restore entry point; unknown creation options are rejected at the FFI boundary.

use std::collections::HashMap;
use std::os::raw::{c_char, c_uchar};

use microsandbox::Sandbox;
use microsandbox::sandbox::{ExternalMountRestorePolicy, RestoreBuilder};

use super::{
    CustomNetworkPolicy, FfiError, MountSpec, PortBindingOpts, VsockRouteOpts, cstr,
    parse_custom_network_policy, parse_log_level, parse_security_profile, register, run_c,
    volume_mount,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreOptions {
    snapshot: String,
    snapshot_reference_kind: Option<String>,
    cpus: Option<u8>,
    memory_mib: Option<u32>,
    #[serde(default, deserialize_with = "deserialize_network_policy")]
    network_policy: Option<CustomNetworkPolicy>,
    #[serde(alias = "max_connections")]
    max_tcp_connections: Option<usize>,
    max_udp_connections: Option<usize>,
    #[serde(default)]
    disable_network: bool,
    security_profile: Option<String>,
    max_duration_secs: Option<u64>,
    idle_timeout_secs: Option<u64>,
    creation_progress: Option<u64>,
    #[serde(default)]
    forked: bool,
    #[serde(default)]
    disk_only: bool,
    snapshot_base: Option<String>,
    user: Option<String>,
    log_level: Option<String>,
    external_mount_policy: Option<ExternalMountRestorePolicy>,
    #[serde(default)]
    dangerously_inherit_resources: bool,
    #[serde(default)]
    allow_missing_resources: bool,
    #[serde(default)]
    volumes: HashMap<String, MountSpec>,
    #[serde(default)]
    captured_volumes: Vec<String>,
    #[serde(default)]
    ports: Vec<PortBindingOpts>,
    #[serde(default)]
    vsock: Vec<VsockRouteOpts>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Keep the shared rule parser, but reject broad network fields at the restore boundary.
fn deserialize_network_policy<'de, D>(
    deserializer: D,
) -> Result<Option<CustomNetworkPolicy>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::{Deserialize, de::Error};

    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    value
        .map(|value| {
            let fields = value
                .as_object()
                .ok_or_else(|| D::Error::custom("restore network policy must be an object"))?;
            if fields
                .keys()
                .any(|key| !matches!(key.as_str(), "default_egress" | "default_ingress" | "rules"))
            {
                return Err(D::Error::custom(
                    "restore network policy accepts only default actions and rules",
                ));
            }
            serde_json::from_value(value).map_err(D::Error::custom)
        })
        .transpose()
}

fn builder(name: String, opts: &RestoreOptions) -> Result<RestoreBuilder, FfiError> {
    let reference = super::parse_snapshot_reference(
        opts.snapshot.clone(),
        opts.snapshot_reference_kind.as_deref().unwrap_or(""),
    )?;
    let mut builder = Sandbox::restore_ref(reference).name(name);
    if let Some(cpus) = opts.cpus {
        builder = builder.cpus(cpus);
    }
    if let Some(memory) = opts.memory_mib {
        builder = builder.memory(memory);
    }
    if let Some(policy) = &opts.network_policy {
        builder = builder.network_policy(parse_custom_network_policy(policy, Vec::new())?);
    }
    if let Some(count) = opts.max_tcp_connections {
        builder = builder.max_tcp_connections(count);
    }
    if let Some(count) = opts.max_udp_connections {
        builder = builder.max_udp_connections(count);
    }
    if opts.disable_network {
        builder = builder.disable_network();
    }
    if let Some(profile) = &opts.security_profile {
        builder = builder.security(parse_security_profile(profile)?);
    }
    if let Some(seconds) = opts.max_duration_secs {
        builder = builder.max_duration(seconds);
    }
    if let Some(seconds) = opts.idle_timeout_secs {
        builder = builder.idle_timeout(seconds);
    }
    if opts.forked {
        builder = builder.forked();
    }
    if opts.disk_only {
        builder = builder.disk_only();
    }
    if let Some(base) = &opts.snapshot_base {
        builder = builder.snapshot_base(base);
    }
    if let Some(user) = &opts.user {
        builder = builder.user(user);
    }
    if let Some(level) = &opts.log_level {
        builder = builder.log_level(parse_log_level(level)?);
    }
    if let Some(policy) = opts.external_mount_policy {
        builder = builder.external_mount_policy(policy);
    }
    if opts.dangerously_inherit_resources {
        builder = builder.dangerously_inherit_resources();
    }
    if opts.allow_missing_resources {
        builder = builder.allow_missing_resources();
    }
    for (guest, spec) in &opts.volumes {
        let mount = volume_mount(guest, spec)?;
        builder = builder.volume(guest, |_| mount);
    }
    for guest in &opts.captured_volumes {
        builder = builder.volume(guest, |m| m.captured());
    }
    for port in &opts.ports {
        let bind = port
            .bind
            .parse()
            .map_err(|_| FfiError::invalid_argument("invalid restore bind address"))?;
        builder = match port.protocol.as_str() {
            "tcp" => builder.port_bind(bind, port.host_port, port.guest_port),
            "udp" => builder.port_udp_bind(bind, port.host_port, port.guest_port),
            _ => return Err(FfiError::invalid_argument("invalid restore port protocol")),
        };
    }
    for route in &opts.vsock {
        builder = match route.socket_type.as_str() {
            "stream" => builder.vsock(&route.host_socket, route.port),
            "dgram" => builder.vsock_dgram(&route.host_socket, route.port),
            _ => {
                return Err(FfiError::invalid_argument(
                    "invalid restore vsock socket type",
                ));
            }
        };
    }
    Ok(builder)
}

/// Restore a detached sandbox through a dedicated C entry point.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_sandbox_restore(
    cancel_id: u64,
    name: *const c_char,
    opts_json: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let name = unsafe { cstr(name) }?;
        let options: RestoreOptions = serde_json::from_str(&unsafe { cstr(opts_json) }?)
            .map_err(|e| FfiError::invalid_argument(format!("invalid restore options: {e}")))?;
        let builder = builder(name, &options)?;
        Ok(Box::pin(async move {
            let sandbox = if let Some(progress) = options.creation_progress {
                super::creation_progress::restore(builder, progress).await?
            } else {
                builder.restore().await?
            };
            let backend_kind = sandbox.backend_kind().as_str();
            let id = sandbox.id().to_string();
            let handle = register(sandbox)?;
            Ok(
                serde_json::json!({"handle":handle,"backend_kind":backend_kind,"id":id})
                    .to_string(),
            )
        }))
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restore_rejects_fresh_boot_options() {
        for field in [
            "image",
            "network",
            "cmd",
            "replace",
            "detached",
            "entrypoint",
        ] {
            let mut value = serde_json::json!({"snapshot":"saved"});
            value[field] = serde_json::Value::Null;
            assert!(
                serde_json::from_value::<RestoreOptions>(value).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn restore_parses_explicit_destination_controls() {
        let options: RestoreOptions = serde_json::from_value(serde_json::json!({
            "snapshot": "baseline", "cpus": 2, "memory_mib": 512,
            "network_policy": {"default_egress": "deny", "default_ingress": "deny", "rules": []},
            "max_connections": 0, "disable_network": true, "security_profile": "default",
            "max_duration_secs": 0, "idle_timeout_secs": 0
        }))
        .unwrap();
        assert_eq!(options.cpus, Some(2));
        assert_eq!(options.memory_mib, Some(512));
        assert_eq!(options.max_tcp_connections, Some(0));
        assert_eq!(options.max_duration_secs, Some(0));
        assert_eq!(options.idle_timeout_secs, Some(0));
        assert!(builder("destination".into(), &options).is_ok());
    }

    #[test]
    fn restore_connection_limits_preserve_omission_and_aliases() {
        let omitted: RestoreOptions =
            serde_json::from_value(serde_json::json!({"snapshot": "saved"})).unwrap();
        assert_eq!(omitted.max_tcp_connections, None);
        assert_eq!(omitted.max_udp_connections, None);

        for name in ["max_connections", "max_tcp_connections"] {
            for udp in [0, 7] {
                let options: RestoreOptions = serde_json::from_value(serde_json::json!({
                    "snapshot": "saved", name: 0, "max_udp_connections": udp
                }))
                .unwrap();
                assert_eq!(options.max_tcp_connections, Some(0));
                assert_eq!(options.max_udp_connections, Some(udp));
                assert!(builder("destination".into(), &options).is_ok());
            }
        }

        // Duplicate names must fail even when their values match, as they do
        // at the create boundary; neither spelling silently wins.
        for canonical in [0, 64] {
            let value = serde_json::json!({
                "snapshot": "saved", "max_connections": 0, "max_tcp_connections": canonical
            });
            assert!(serde_json::from_value::<RestoreOptions>(value).is_err());
        }
    }

    #[test]
    fn restore_rejects_nested_boot_network_options() {
        for field in [
            "tls",
            "dns",
            "ports",
            "ipv4_pool",
            "secrets",
            "max_connections",
            "max_tcp_connections",
            "max_udp_connections",
        ] {
            let mut policy = serde_json::json!({"default_egress":"deny", "rules":[]});
            policy[field] = serde_json::json!({});
            let value = serde_json::json!({"snapshot":"baseline", "network_policy":policy});
            assert!(
                serde_json::from_value::<RestoreOptions>(value).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn create_rejects_discarded_restore_fields() {
        for field in ["snapshot", "snapshot_base", "snapshot_disk_only", "forked"] {
            let mut value = serde_json::json!({"image":"alpine"});
            value[field] = serde_json::Value::Null;
            assert!(
                serde_json::from_value::<super::super::SandboxCreateOpts>(value).is_err(),
                "{field}"
            );
        }
    }
}
