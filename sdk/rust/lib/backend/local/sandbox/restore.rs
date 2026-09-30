//! Restored runtime resource targets projected back into sandbox configuration.

use microsandbox_control_client::{GetCpuState, GetMemoryState};

use super::modify::control_session;
use crate::sandbox::SandboxConfig;
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Project restored live targets into configuration after construction used original geometry.
pub(super) async fn restore_requested_resources(
    local: &crate::backend::LocalBackend,
    config: &mut SandboxConfig,
) -> MicrosandboxResult<()> {
    let resources = &config.spec.resources;
    let session =
        if resources.max_cpus > resources.cpus || resources.max_memory_mib > resources.memory_mib {
            local.control_session(&config.spec.name).await?
        } else {
            None
        };
    let mut cpus = resources.cpus;
    let mut memory_mib = resources.memory_mib;
    // libkrun creates the CPU controller only when capacity exceeds boot CPUs.
    // A fixed multi-CPU VM has no controller; its captured boot count is already final.
    if resources.max_cpus > resources.cpus {
        let state = control_session(&session)?
            .request(&GetCpuState)
            .await
            .map_err(MicrosandboxError::ControlClient)?;
        if state.possible != u32::from(resources.max_cpus)
            || state.requested_online == 0
            || state.requested_online > state.possible
        {
            return Err(crate::MicrosandboxError::Runtime(
                "restored CPU target is outside captured capacity".into(),
            ));
        }
        cpus = state.requested_online as u8;
    }
    if resources.max_memory_mib > resources.memory_mib {
        let state = control_session(&session)?
            .request(&GetMemoryState)
            .await
            .map_err(MicrosandboxError::ControlClient)?;
        if state.boot_mib != u64::from(resources.memory_mib)
            || state.max_mib != u64::from(resources.max_memory_mib)
            || state.target_mib < state.boot_mib
            || state.target_mib > state.max_mib
        {
            return Err(crate::MicrosandboxError::Runtime(
                "restored memory target is outside captured capacity".into(),
            ));
        }
        memory_mib = state.target_mib as u32;
    }
    // Persist requested targets, not the boot values or possibly still-converging actual values,
    // so subsequent modify calls neither silently skip changes nor claim false convergence.
    config.spec.resources.cpus = cpus;
    config.spec.resources.memory_mib = memory_mib;
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn config(cpus: u8, memory_mib: u32) -> SandboxConfig {
        let mut config = SandboxConfig::default();
        config.spec.name = "api".to_string();
        config.spec.resources.cpus = cpus;
        config.spec.resources.memory_mib = memory_mib;
        config.spec.resources.max_cpus = cpus;
        config.spec.resources.max_memory_mib = memory_mib;
        config
    }

    #[tokio::test]
    async fn restored_fixed_cpu_counts_do_not_require_a_hotplug_controller() {
        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        // No runtime/control endpoint exists: fixed geometry needs no query.
        for cpus in [1, 2, 4] {
            let mut config = config(cpus, 256);
            config.spec.resources.max_cpus = cpus;
            config.spec.resources.max_memory_mib = 256;
            restore_requested_resources(&local, &mut config)
                .await
                .unwrap();
            assert_eq!(config.spec.resources.cpus, cpus);
            assert_eq!(config.spec.resources.memory_mib, 256);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn restored_hotplug_cpu_state_still_rejects_invalid_targets() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let home = tempfile::tempdir_in("/tmp").unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        crate::test_support::seed_control_run(&local, "api").await;
        let agent =
            crate::runtime::sandbox_agent_socket_path_candidates_for(&local, "api").remove(0);
        let path = microsandbox_runtime::control::control_socket_path_for(&agent);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let listener = tokio::net::UnixListener::bind(path).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&line).unwrap()["op"],
                "capabilities"
            );
            stream
                .get_mut()
                .write_all(b"{\"ok\":true,\"capabilities\":{\"cpu_resize\":true,\"memory_resize\":true,\"secrets_update\":false}}\n")
                .await
                .unwrap();
            for (possible, requested) in [(3, 2), (4, 0), (4, 5)] {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(&line).unwrap()["op"],
                    "cpu_state"
                );
                let response = serde_json::json!({"ok":true,"cpu":{
                    "possible":possible,"requested_online":requested,"actual_online":1,"enforced":1
                }});
                stream
                    .get_mut()
                    .write_all(format!("{response}\n").as_bytes())
                    .await
                    .unwrap();
            }
        });
        for _ in 0..3 {
            let mut config = config(1, 256);
            config.spec.resources.max_cpus = 4;
            let error = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                restore_requested_resources(&local, &mut config),
            )
            .await
            .unwrap()
            .unwrap_err();
            assert!(error.to_string().contains("outside captured capacity"));
            assert_eq!(config.spec.resources.cpus, 1);
        }
        server.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn restored_targets_use_complete_frames_and_requested_not_actual_sizes() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let home = tempfile::tempdir_in("/tmp").unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        crate::test_support::seed_control_run(&local, "api").await;
        let agent =
            crate::runtime::sandbox_agent_socket_path_candidates_for(&local, "api").remove(0);
        let path = microsandbox_runtime::control::control_socket_path_for(&agent);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let listener = tokio::net::UnixListener::bind(path).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&line).unwrap()["op"],
                "capabilities"
            );
            stream
                .get_mut()
                .write_all(b"{\"ok\":true,\"capabilities\":{\"cpu_resize\":true,\"memory_resize\":true,\"secrets_update\":false}}\n")
                .await
                .unwrap();
            for (op, response) in [
                (
                    "cpu_state",
                    serde_json::json!({"ok":true,"cpu":{"possible":4,"requested_online":2,"actual_online":3,"enforced":2}}),
                ),
                (
                    "memory_state",
                    serde_json::json!({"ok":true,"memory":{"boot_mib":256,"max_mib":1024,"target_mib":768,"current_mib":512}}),
                ),
            ] {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                assert!(line.ends_with('\n'));
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(&line).unwrap()["op"],
                    op
                );
                stream
                    .get_mut()
                    .write_all(format!("{response}\n").as_bytes())
                    .await
                    .unwrap();
            }
        });
        let mut config = config(1, 256);
        config.spec.resources.max_cpus = 4;
        config.spec.resources.max_memory_mib = 1024;
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            restore_requested_resources(&local, &mut config),
        )
        .await
        .unwrap()
        .unwrap();
        server.await.unwrap();
        assert_eq!(config.spec.resources.cpus, 2);
        assert_eq!(config.spec.resources.memory_mib, 768);
    }
}
