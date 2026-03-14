//! OCI image configuration parsing.

use std::collections::HashMap;

use crate::error::ImageError;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Runtime configuration parsed from an OCI image config blob.
///
/// These are defaults — [`SandboxBuilder`] fields override them.
/// Fields are `Option` where the OCI spec allows omission.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ImageConfig {
    /// Environment variables (`KEY=VALUE` format).
    pub env: Vec<String>,

    /// Default command.
    pub cmd: Option<Vec<String>>,

    /// Entrypoint.
    pub entrypoint: Option<Vec<String>>,

    /// Working directory for the default process.
    pub working_dir: Option<String>,

    /// Default user (`uid`, `uid:gid`, `username`, or `username:group`).
    pub user: Option<String>,

    /// Ports the image declares as exposed (informational only).
    pub exposed_ports: Vec<String>,

    /// Volume mount points declared by the image (informational).
    pub volumes: Vec<String>,

    /// Image labels (key-value metadata).
    pub labels: HashMap<String, String>,

    /// Signal to send for graceful shutdown (e.g., `SIGTERM`).
    pub stop_signal: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ImageConfig {
    /// Parse from raw OCI config JSON bytes, returning the config and diff_ids.
    pub fn parse(bytes: &[u8]) -> Result<(Self, Vec<String>), ImageError> {
        let oci_config: oci_spec::image::ImageConfiguration = serde_json::from_slice(bytes)
            .map_err(|e| ImageError::ConfigParse(format!("failed to parse image config: {e}")))?;

        let config = oci_config.config();

        let image_config = Self {
            env: config
                .as_ref()
                .and_then(|c| c.env().clone())
                .unwrap_or_default(),
            cmd: config.as_ref().and_then(|c| c.cmd().clone()),
            entrypoint: config.as_ref().and_then(|c| c.entrypoint().clone()),
            working_dir: config.as_ref().and_then(|c| c.working_dir().clone()),
            user: config.as_ref().and_then(|c| c.user().clone()),
            exposed_ports: config
                .as_ref()
                .and_then(|c| c.exposed_ports().clone())
                .unwrap_or_default(),
            volumes: config
                .as_ref()
                .and_then(|c| c.volumes().clone())
                .unwrap_or_default(),
            labels: config
                .as_ref()
                .and_then(|c| c.labels().as_ref())
                .cloned()
                .unwrap_or_default(),
            stop_signal: config.as_ref().and_then(|c| c.stop_signal().clone()),
        };

        let diff_ids = oci_config.rootfs().diff_ids().to_vec();

        Ok((image_config, diff_ids))
    }
}
