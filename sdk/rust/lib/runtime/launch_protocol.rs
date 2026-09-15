//! Negotiate the private launch wire before spawning a VM or allocating runtime resources.

use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use microsandbox_runtime::launch_protocol::{LaunchCapabilities, LaunchProtocol, upgrade_required};
use tokio::{io::AsyncReadExt, process::Command};

use crate::{MicrosandboxError, MicrosandboxResult, sandbox::SandboxConfig};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) async fn negotiate(path: &Path) -> MicrosandboxResult<LaunchProtocol> {
    let (status, bytes) = probe(path, &["__launch-protocol"]).await?;
    if status.success() {
        let capabilities: LaunchCapabilities = serde_json::from_slice(&bytes)
            .map_err(|_| failure(path, "invalid launch capability response"))?;
        return if capabilities.protocols.contains(&2) {
            Ok(LaunchProtocol::Current)
        } else if capabilities.protocols.contains(&1) {
            Ok(LaunchProtocol::Legacy {
                file_mounts: true,
                resolved_network: true,
            })
        } else {
            Err(failure(
                path,
                "no mutually supported launch protocol; upgrade the SDK or msb",
            ))
        };
    }
    // Clap's unrecognized-command exit is the only allowed fallback. Crashes,
    // permissions, malformed successful output, and timeouts are real errors.
    if status.code() != Some(2) {
        return Err(failure(path, "launch capability probe failed"));
    }
    let (help_status, help) = probe(path, &["sandbox", "--help"]).await?;
    let help = String::from_utf8_lossy(&help);
    if !help_status.success()
        || !["--sandbox-id", "--vcpus", "--memory-mib"]
            .iter()
            .all(|flag| help.contains(flag))
    {
        return Err(failure(
            path,
            "runtime does not advertise a supported launcher",
        ));
    }
    let (version_status, version) = probe(path, &["--version"]).await?;
    if !version_status.success() {
        return Err(failure(path, "cannot identify legacy launch format"));
    }
    legacy_protocol(&String::from_utf8_lossy(&version))
        .ok_or_else(|| failure(path, "unsupported legacy launch format; upgrade msb"))
}

pub(super) fn validate_request(
    protocol: LaunchProtocol,
    config: &SandboxConfig,
) -> MicrosandboxResult<()> {
    if matches!(protocol, LaunchProtocol::Legacy { .. }) {
        if config.checkpoint_restore.is_some() {
            return Err(MicrosandboxError::Runtime(upgrade_required(
                "checkpoint restore or branch",
            )));
        }
        if !config.snapshot_upper_layers.is_empty()
            || !config.snapshot_root_layer_sources.is_empty()
        {
            return Err(MicrosandboxError::Runtime(upgrade_required(
                "checkpoint disk chains",
            )));
        }
    }
    Ok(())
}

fn legacy_protocol(version: &str) -> Option<LaunchProtocol> {
    // Package versions are used only to identify historical codecs in binaries
    // which shipped before capability discovery. This is not version equality.
    let version = version.trim().strip_prefix("msb ")?;
    let patch: u32 = version.strip_prefix("0.6.")?.parse().ok()?;
    (patch >= 10).then_some(LaunchProtocol::Legacy {
        file_mounts: patch >= 16,
        resolved_network: patch >= 17,
    })
}

async fn probe(path: &Path, args: &[&str]) -> MicrosandboxResult<(ExitStatus, Vec<u8>)> {
    let operation = async {
        let mut child = Command::new(path)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let mut bytes = Vec::new();
        // Bound memory as well as time, including a child that never closes stdout.
        child
            .stdout
            .take()
            .expect("piped stdout")
            .take(16 * 1024 + 1)
            .read_to_end(&mut bytes)
            .await?;
        if bytes.len() > 16 * 1024 {
            return Err(std::io::Error::other(
                "launch probe response exceeds 16 KiB",
            ));
        }
        Ok::<_, std::io::Error>((child.wait().await?, bytes))
    };
    tokio::time::timeout(Duration::from_secs(10), operation)
        .await
        .map_err(|_| failure(path, "launch capability probe timed out"))?
        .map_err(|error| failure(path, &format!("launch capability probe: {error}")))
}

fn failure(path: &Path, message: &str) -> MicrosandboxError {
    MicrosandboxError::Runtime(format!("{}: {message}", path.display()))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_boundaries_select_wire_features_without_version_equality() {
        assert_eq!(
            legacy_protocol("msb 0.6.10\n"),
            Some(LaunchProtocol::Legacy {
                file_mounts: false,
                resolved_network: false
            })
        );
        assert_eq!(
            legacy_protocol("msb 0.6.16"),
            Some(LaunchProtocol::Legacy {
                file_mounts: true,
                resolved_network: false
            })
        );
        assert_eq!(
            legacy_protocol("msb 0.6.18"),
            Some(LaunchProtocol::Legacy {
                file_mounts: true,
                resolved_network: true
            })
        );
        for value in [
            "msb 0.6.9",
            "msb 0.7.0",
            "other 0.6.18",
            "msb 0.6.18 garbage",
        ] {
            assert_eq!(legacy_protocol(value), None);
        }
    }

    #[cfg(unix)]
    async fn fake_runtime(script: &str) -> MicrosandboxResult<LaunchProtocol> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("msb");
        std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        negotiate(&path).await
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn capability_probe_selects_modern_and_rejects_bad_responses() {
        assert_eq!(
            fake_runtime("echo '{\"protocols\":[2,1]}'").await.unwrap(),
            LaunchProtocol::Current
        );
        assert_eq!(
            fake_runtime("echo '{\"protocols\":[1]}'").await.unwrap(),
            LaunchProtocol::Legacy {
                file_mounts: true,
                resolved_network: true
            }
        );
        for script in ["echo invalid", "echo '{\"protocols\":[99]}'", "exit 1"] {
            assert!(fake_runtime(script).await.is_err());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn legacy_probe_never_attempts_an_actual_launch() {
        let script = r#"case "$*" in
__launch-protocol) exit 2;;
'sandbox --help') echo '--sandbox-id --vcpus --memory-mib';;
--version) echo 'msb 0.6.18';;
*) exit 99;;
esac"#;
        assert_eq!(fake_runtime(script).await.unwrap().command(), "sandbox");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn probe_bounds_output_and_hung_processes() {
        assert!(
            fake_runtime("head -c 17000 /dev/zero")
                .await
                .unwrap_err()
                .to_string()
                .contains("exceeds")
        );
        assert!(
            fake_runtime("exec sleep 30")
                .await
                .unwrap_err()
                .to_string()
                .contains("timed out")
        );
    }

    #[test]
    fn restore_is_rejected_before_launch_resources_are_allocated() {
        let mut config = SandboxConfig::default();
        config.checkpoint_restore = Some(Default::default());
        let old = LaunchProtocol::Legacy {
            file_mounts: true,
            resolved_network: true,
        };
        assert!(
            validate_request(old, &config)
                .unwrap_err()
                .to_string()
                .contains("upgrade msb")
        );
        assert!(validate_request(LaunchProtocol::Current, &config).is_ok());
    }
}
