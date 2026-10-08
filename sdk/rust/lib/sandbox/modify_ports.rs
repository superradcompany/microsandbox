//! Published-port modification planning and host-side preflight.

use std::net::{IpAddr, SocketAddr, UdpSocket};

use microsandbox_types::{PortProtocol, PublishedPortSpec};
use tokio::net::TcpSocket;

use super::{
    ChangeKind, ModificationConflict, ModificationPolicy, PlannedChange, SandboxConfig,
    SandboxModificationPatch, SandboxStatus, running_status, spec_change,
};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn requested(patch: &SandboxModificationPatch) -> bool {
    !patch.ports.is_empty() || !patch.ports_remove.is_empty()
}

pub(super) fn desired(
    config: &SandboxConfig,
    patch: &SandboxModificationPatch,
) -> Vec<PublishedPortSpec> {
    let mut result = config.spec.network.ports.clone();
    for port in &patch.ports {
        if let Some(current) = result.iter_mut().find(|entry| same_endpoint(entry, port)) {
            *current = port.clone();
        } else {
            result.push(port.clone());
        }
    }
    result.retain(|port| !removed(port, patch));
    result
}

#[allow(clippy::too_many_arguments)]
pub(super) fn plan(
    status: SandboxStatus,
    config: &SandboxConfig,
    active: Option<&SandboxConfig>,
    patch: &SandboxModificationPatch,
    policy: ModificationPolicy,
    changes: &mut Vec<PlannedChange>,
    conflicts: &mut Vec<ModificationConflict>,
) {
    if !requested(patch) {
        return;
    }
    let mut conflict = |message: String| {
        conflicts.push(ModificationConflict {
            field: "port".into(),
            message,
        })
    };
    if !cfg!(feature = "net") || !config.spec.network.enabled {
        conflict("published port changes require networking to be enabled".into());
    }
    for port in &patch.ports {
        if endpoint(&port.host_bind, port.host_port).is_none()
            || port.host_port == 0
            || port.guest_port == 0
        {
            conflict(
                "published ports require an IP address and nonzero host and guest ports".into(),
            );
        }
        if removed(port, patch) {
            conflict(format!(
                "port {} is both set and removed",
                format_port(port)
            ));
        }
    }
    for key in &patch.ports_remove {
        if endpoint(&key.host_bind, key.host_port).is_none() || key.host_port == 0 {
            conflict("port removal requires an IP address and nonzero host port".into());
        } else if !config
            .spec
            .network
            .ports
            .iter()
            .chain(
                active
                    .filter(|_| policy != ModificationPolicy::NextStart && running_status(status))
                    .into_iter()
                    .flat_map(|config| &config.spec.network.ports),
            )
            .any(|port| {
                endpoint(&port.host_bind, port.host_port) == endpoint(&key.host_bind, key.host_port)
                    && port.protocol == key.protocol
            })
        {
            conflict(format!(
                "no published port at {}:{} ({:?})",
                key.host_bind, key.host_port, key.protocol
            ));
        }
    }
    let target = desired(config, patch);
    for (index, port) in target.iter().enumerate() {
        if target[..index].iter().any(|other| overlaps(port, other)) {
            conflict(format!(
                "published port {} overlaps another mapping",
                format_port(port)
            ));
        }
    }

    // Restart must activate a previously saved port patch too. Next-start compares
    // only desired state so repeated saves remain no-ops.
    let active_differs = active.is_some_and(|active| {
        active.spec.network.ports.len() != target.len()
            || target.iter().any(|port| {
                !active.spec.network.ports.iter().any(|current| {
                    same_endpoint(current, port) && current.guest_port == port.guest_port
                })
            })
    });
    let before =
        if policy != ModificationPolicy::NextStart && running_status(status) && active_differs {
            active.unwrap_or(config)
        } else {
            config
        };
    for port in &target {
        let existing = before
            .spec
            .network
            .ports
            .iter()
            .find(|other| same_endpoint(other, port));
        if existing.is_some_and(|other| other.guest_port == port.guest_port) {
            continue;
        }
        changes.push(spec_change(
            "port",
            if existing.is_some() {
                ChangeKind::Updated
            } else {
                ChangeKind::Added
            },
            existing.map(format_port),
            Some(format_port(port)),
            status,
            policy,
            "published ports apply on restart; processes and connections will be interrupted",
        ));
    }
    for port in &before.spec.network.ports {
        if !target.iter().any(|other| same_endpoint(other, port)) {
            changes.push(spec_change(
                "port",
                ChangeKind::Removed,
                Some(format_port(port)),
                None,
                status,
                policy,
                "removing a published port requires restart; existing connections will close",
            ));
        }
    }
}

pub(super) fn preflight(
    config: &SandboxConfig,
    active: Option<&SandboxConfig>,
    patch: &SandboxModificationPatch,
    status: SandboxStatus,
) -> MicrosandboxResult<()> {
    let target = desired(config, patch);
    // Keep successful probes alive together to detect kernel-specific overlap.
    let mut tcp = Vec::new();
    let mut udp = Vec::new();
    for port in &target {
        if !super::stopped_status(status)
            && active
                .unwrap_or(config)
                .spec
                .network
                .ports
                .iter()
                .any(|current| overlaps(port, current))
        {
            // The current runtime must release these sockets before they can be
            // checked. Startup is still responsible for the definitive bind.
            continue;
        }
        let address = endpoint(&port.host_bind, port.host_port).ok_or_else(|| {
            MicrosandboxError::InvalidConfig("invalid published port address".into())
        })?;
        let result = match port.protocol {
            PortProtocol::Tcp => bind_tcp(address).map(|socket| tcp.push(socket)),
            PortProtocol::Udp => UdpSocket::bind(address).map(|socket| udp.push(socket)),
        };
        result.map_err(|error| {
            MicrosandboxError::InvalidConfig(format!(
                "cannot bind published port {}: {error}; no changes were applied",
                format_port(port)
            ))
        })?;
    }
    Ok(())
}

fn endpoint(bind: &str, port: u16) -> Option<SocketAddr> {
    bind.parse::<IpAddr>()
        .ok()
        .map(|ip| SocketAddr::new(ip, port))
}

fn same_endpoint(a: &PublishedPortSpec, b: &PublishedPortSpec) -> bool {
    endpoint(&a.host_bind, a.host_port) == endpoint(&b.host_bind, b.host_port)
        && a.protocol == b.protocol
}

fn removed(port: &PublishedPortSpec, patch: &SandboxModificationPatch) -> bool {
    patch.ports_remove.iter().any(|key| {
        endpoint(&key.host_bind, key.host_port) == endpoint(&port.host_bind, port.host_port)
            && key.protocol == port.protocol
    })
}

fn bind_tcp(address: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    let socket = if address.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    // Match the publisher's Unix reuse policy, including recently closed ports.
    #[cfg(not(windows))]
    socket.set_reuseaddr(true)?;
    socket.bind(address)?;
    socket.listen(1)
}

fn overlaps(a: &PublishedPortSpec, b: &PublishedPortSpec) -> bool {
    if a.host_port != b.host_port || a.protocol != b.protocol {
        return false;
    }
    let (Some(a), Some(b)) = (
        endpoint(&a.host_bind, a.host_port),
        endpoint(&b.host_bind, b.host_port),
    ) else {
        return false;
    };
    a == b || (a.is_ipv4() == b.is_ipv4() && (a.ip().is_unspecified() || b.ip().is_unspecified()))
        // IPv6 wildcard listeners may also cover IPv4 depending on the OS.
        || (a.is_ipv6() && a.ip().is_unspecified())
        || (b.is_ipv6() && b.ip().is_unspecified())
}

fn format_port(port: &PublishedPortSpec) -> String {
    let address = endpoint(&port.host_bind, port.host_port)
        .map(|address| address.to_string())
        .unwrap_or_else(|| port.host_bind.clone());
    let protocol = match port.protocol {
        PortProtocol::Tcp => "tcp",
        PortProtocol::Udp => "udp",
    };
    format!("{address}:{}/{protocol}", port.guest_port)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, feature = "net"))]
mod tests {
    use std::{net::TcpListener, sync::Arc};

    use sea_orm::{ActiveModelTrait, Set};

    use super::super::{LiveControl, SandboxModificationBuilder, build_plan};
    use super::*;
    use crate::LocalBackend;
    use crate::backend::Backend;
    use crate::db::entity::sandbox;
    use crate::sandbox::{ModificationDisposition, PublishedPortKey};

    fn port(host: u16, guest: u16, protocol: PortProtocol) -> PublishedPortSpec {
        PublishedPortSpec {
            host_port: host,
            guest_port: guest,
            protocol,
            ..Default::default()
        }
    }

    #[test]
    fn port_patch_preserves_other_endpoints_and_uses_restart_policies() {
        let mut config = SandboxConfig::default();
        config.spec.network.enabled = true;
        config.spec.network.ports = vec![
            port(8080, 80, PortProtocol::Tcp),
            port(8080, 53, PortProtocol::Udp),
        ];
        let patch = SandboxModificationPatch {
            ports: vec![port(8080, 3000, PortProtocol::Tcp)],
            ..Default::default()
        };
        let target = desired(&config, &patch);
        assert_eq!(target.len(), 2);
        assert_eq!(target[0].guest_port, 3000);
        assert_eq!(target[1].guest_port, 53);

        for (status, policy, expected) in [
            (
                SandboxStatus::Running,
                ModificationPolicy::NoRestart,
                ModificationDisposition::RequiresRestart,
            ),
            (
                SandboxStatus::Running,
                ModificationPolicy::Restart,
                ModificationDisposition::RequiresRestart,
            ),
            (
                SandboxStatus::Running,
                ModificationPolicy::NextStart,
                ModificationDisposition::NextStart,
            ),
            (
                SandboxStatus::Stopped,
                ModificationPolicy::NoRestart,
                ModificationDisposition::NextStart,
            ),
        ] {
            let plan = build_plan(
                "ports".into(),
                status,
                &config,
                Some(&config),
                LiveControl::default(),
                patch.clone(),
                policy,
            );
            assert!(plan.conflicts.is_empty());
            assert_eq!(plan.changes.len(), 1);
            let PlannedChange::Config(change) = &plan.changes[0] else {
                panic!("expected port change")
            };
            assert_eq!(change.disposition, expected);
            assert_eq!(change.before.as_deref(), Some("127.0.0.1:8080:80/tcp"));
            assert_eq!(change.after.as_deref(), Some("127.0.0.1:8080:3000/tcp"));
        }
        let mut saved = config.clone();
        saved.spec.network.ports = target;
        let pending = build_plan(
            "ports".into(),
            SandboxStatus::Running,
            &saved,
            Some(&config),
            LiveControl::default(),
            patch,
            ModificationPolicy::Restart,
        );
        assert!(super::super::plan_requires_restart(&pending));
    }

    #[test]
    fn port_plan_rejects_invalid_and_overlapping_requests() {
        let mut config = SandboxConfig::default();
        config.spec.network.enabled = true;
        config.spec.network.ports = vec![port(8080, 80, PortProtocol::Tcp)];
        let missing = PublishedPortKey {
            host_bind: "127.0.0.1".into(),
            host_port: 9999,
            protocol: PortProtocol::Tcp,
        };
        for patch in [
            SandboxModificationPatch {
                ports: vec![port(0, 80, PortProtocol::Tcp)],
                ..Default::default()
            },
            SandboxModificationPatch {
                ports: vec![PublishedPortSpec {
                    host_bind: "0.0.0.0".into(),
                    ..port(8080, 3000, PortProtocol::Tcp)
                }],
                ..Default::default()
            },
            SandboxModificationPatch {
                ports_remove: vec![missing],
                ..Default::default()
            },
            SandboxModificationPatch {
                ports: vec![port(8080, 3000, PortProtocol::Tcp)],
                ports_remove: vec![PublishedPortKey {
                    host_bind: "127.0.0.1".into(),
                    host_port: 8080,
                    protocol: PortProtocol::Tcp,
                }],
                ..Default::default()
            },
        ] {
            let plan = build_plan(
                "ports".into(),
                SandboxStatus::Running,
                &config,
                Some(&config),
                LiveControl::default(),
                patch,
                ModificationPolicy::Restart,
            );
            assert!(!plan.conflicts.is_empty());
            assert!(super::super::validate_apply_supported(&plan).is_err());
        }
    }

    #[tokio::test]
    async fn port_apply_persists_updates_and_conflicts_leave_config_unchanged() {
        let temp = tempfile::tempdir().unwrap();
        let backend: Arc<dyn Backend> = Arc::new(
            LocalBackend::builder()
                .config_path(temp.path().join("config.json"))
                .managed_config_path(temp.path().join("managed.json"))
                .home(temp.path())
                .build()
                .await
                .unwrap(),
        );
        let mut config = SandboxConfig::default();
        config.spec.name = "ports".into();
        config.spec.network.enabled = true;
        let pools = backend.as_local().unwrap().db().await.unwrap();
        sandbox::ActiveModel {
            name: Set("ports".into()),
            config: Set(serde_json::to_string(&config).unwrap()),
            status: Set(SandboxStatus::Stopped),
            ephemeral: Set(false),
            ..Default::default()
        }
        .insert(pools.write())
        .await
        .unwrap();

        // A real occupied endpoint must prevent persistence, including unrelated fields.
        let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
        let host = occupied.local_addr().unwrap().port();
        let request = SandboxModificationBuilder::new(backend.clone(), "ports")
            .port_mapping(port(host, 80, PortProtocol::Tcp))
            .label("should", "not persist");
        assert!(
            !request
                .clone()
                .dry_run()
                .await
                .unwrap()
                .conflicts
                .is_empty()
        );
        assert!(request.clone().apply().await.is_err());
        let handle = backend
            .sandboxes()
            .get(backend.clone(), "ports")
            .await
            .unwrap();
        assert!(handle.config().unwrap().spec.network.ports.is_empty());
        assert!(handle.config().unwrap().spec.labels.is_empty());
        drop(occupied);

        request.apply().await.unwrap();
        let handle = backend
            .sandboxes()
            .get(backend.clone(), "ports")
            .await
            .unwrap();
        assert_eq!(
            handle.config().unwrap().spec.network.ports[0].guest_port,
            80
        );
        SandboxModificationBuilder::new(backend.clone(), "ports")
            .port_mapping(port(host, 3000, PortProtocol::Tcp))
            .apply()
            .await
            .unwrap();
        let handle = backend
            .sandboxes()
            .get(backend.clone(), "ports")
            .await
            .unwrap();
        assert_eq!(
            handle.config().unwrap().spec.network.ports[0].guest_port,
            3000
        );
        SandboxModificationBuilder::new(backend.clone(), "ports")
            .remove_port(PublishedPortKey {
                host_bind: "127.0.0.1".into(),
                host_port: host,
                protocol: PortProtocol::Tcp,
            })
            .apply()
            .await
            .unwrap();
        let handle = backend
            .sandboxes()
            .get(backend.clone(), "ports")
            .await
            .unwrap();
        assert!(handle.config().unwrap().spec.network.ports.is_empty());
    }

    #[tokio::test]
    async fn preflight_accepts_own_listener_but_rejects_new_occupied_udp_endpoint() {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut config = SandboxConfig::default();
        config.spec.network.ports = vec![port(
            tcp.local_addr().unwrap().port(),
            80,
            PortProtocol::Tcp,
        )];
        let mut patch = SandboxModificationPatch {
            ports: vec![port(
                tcp.local_addr().unwrap().port(),
                3000,
                PortProtocol::Tcp,
            )],
            ..Default::default()
        };
        for status in [SandboxStatus::Running, SandboxStatus::Paused] {
            preflight(&config, Some(&config), &patch, status).unwrap();
        }
        patch.ports.push(port(
            udp.local_addr().unwrap().port(),
            53,
            PortProtocol::Udp,
        ));
        assert!(preflight(&config, Some(&config), &patch, SandboxStatus::Running).is_err());
    }
}
