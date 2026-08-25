//! Agentd payload selection for guest bootstrap.

use std::{
    path::PathBuf,
    sync::{Arc, OnceLock},
};

use sha2::{Digest as _, Sha256};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_AGENTD_BYTES: usize = 128 * 1024 * 1024;

static AGENTD_PAYLOAD: OnceLock<AgentdPayload> = OnceLock::new();

#[cfg(feature = "embed-binaries")]
const EMBEDDED_AGENTD_BYTES: Option<&[u8]> =
    Some(include_bytes!(concat!(env!("OUT_DIR"), "/agentd")));
#[cfg(not(feature = "embed-binaries"))]
const EMBEDDED_AGENTD_BYTES: Option<&[u8]> = None;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Immutable agentd executable bytes injected into a guest filesystem.
#[derive(Clone, Debug)]
pub enum AgentdPayload {
    /// Agentd bytes compiled into the host binary.
    Embedded(&'static [u8]),

    /// Agentd bytes eagerly loaded from `MSB_AGENTD_PATH`.
    External(Arc<[u8]>),
}

/// Failure to select or validate the guest Agentd payload.
#[derive(Debug, thiserror::Error)]
pub enum AgentdPayloadError {
    /// `MSB_AGENTD_PATH` could not be read.
    #[error("failed to read MSB_AGENTD_PATH `{path}`: {source}")]
    Read {
        /// Configured path.
        path: PathBuf,
        /// Underlying filesystem error.
        source: std::io::Error,
    },

    /// Agentd bytes were not available.
    #[error(
        "agentd is unavailable; set MSB_AGENTD_PATH or build msb with the embed-binaries feature"
    )]
    Missing,

    /// Agentd bytes were not a compatible Linux ELF executable.
    #[error("invalid agentd payload: {0}")]
    Invalid(String),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AgentdPayload {
    /// Return the selected immutable executable bytes.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Embedded(bytes) => bytes,
            Self::External(bytes) => bytes,
        }
    }

    /// Load the runtime override, or fall back to the compiled payload.
    pub fn resolve() -> Result<Self, AgentdPayloadError> {
        Self::resolve_from(std::env::var_os("MSB_AGENTD_PATH").map(PathBuf::from))
    }

    /// Load an explicit runtime override, or fall back to the compiled payload.
    fn resolve_from(path: Option<PathBuf>) -> Result<Self, AgentdPayloadError> {
        if let Some(path) = path {
            let bytes = std::fs::read(&path).map_err(|source| AgentdPayloadError::Read {
                path: path.clone(),
                source,
            })?;
            validate_agentd(&bytes)?;
            let digest = hex::encode(Sha256::digest(&bytes));
            tracing::info!(
                path = %path.display(),
                sha256 = %digest,
                "using agentd runtime override"
            );
            return Ok(Self::External(Arc::from(bytes)));
        }

        let bytes = EMBEDDED_AGENTD_BYTES.ok_or(AgentdPayloadError::Missing)?;
        validate_agentd(bytes)?;
        Ok(Self::Embedded(bytes))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Resolve the Agentd payload for one sandbox runtime process.
pub fn resolve_agentd_payload() -> Result<AgentdPayload, AgentdPayloadError> {
    AgentdPayload::resolve()
}

/// Select and cache the Agentd payload before a sandbox VM is constructed.
pub fn initialize_agentd_payload() -> Result<&'static AgentdPayload, AgentdPayloadError> {
    if let Some(payload) = AGENTD_PAYLOAD.get() {
        return Ok(payload);
    }

    let payload = AgentdPayload::resolve()?;
    let _ = AGENTD_PAYLOAD.set(payload);
    Ok(AGENTD_PAYLOAD
        .get()
        .expect("agentd payload was initialized by this process"))
}

/// Return the process-selected Agentd bytes.
///
/// The CLI initializes this fallibly before VM construction. Direct filesystem
/// users get the same selection lazily, with a clear panic if they omitted both
/// an override and an embedded fallback.
pub fn agentd_bytes() -> &'static [u8] {
    initialize_agentd_payload()
        .expect("agentd payload must be available before filesystem construction")
        .as_bytes()
}

/// Return the embedded Agentd payload, when this build contains one.
pub fn embedded_agentd_payload() -> Option<AgentdPayload> {
    EMBEDDED_AGENTD_BYTES.map(AgentdPayload::Embedded)
}

fn validate_agentd(bytes: &[u8]) -> Result<(), AgentdPayloadError> {
    if bytes.len() < 64 {
        return Err(AgentdPayloadError::Invalid(
            "file is too small to be an ELF executable".into(),
        ));
    }
    if bytes.len() > MAX_AGENTD_BYTES {
        return Err(AgentdPayloadError::Invalid(format!(
            "file exceeds the {MAX_AGENTD_BYTES}-byte safety limit"
        )));
    }
    if &bytes[..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
        return Err(AgentdPayloadError::Invalid(
            "expected a 64-bit little-endian ELF executable".into(),
        ));
    }

    let file_type = u16::from_le_bytes([bytes[16], bytes[17]]);
    if !matches!(file_type, 2 | 3) {
        return Err(AgentdPayloadError::Invalid(format!(
            "ELF type {file_type} is not executable or position-independent"
        )));
    }

    let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
    let expected = match std::env::consts::ARCH {
        "x86_64" => 62,
        "aarch64" => 183,
        architecture => {
            return Err(AgentdPayloadError::Invalid(format!(
                "unsupported host architecture {architecture}"
            )));
        }
    };
    if machine != expected {
        return Err(AgentdPayloadError::Invalid(format!(
            "ELF machine {machine} does not match host architecture {}",
            std::env::consts::ARCH
        )));
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn executable_elf(machine: u16) -> [u8; 64] {
        let mut bytes = [0_u8; 64];
        bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
        bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes
    }

    #[test]
    fn rejects_non_elf_payload() {
        let error = validate_agentd(&[0; 64]).unwrap_err();
        assert!(error.to_string().contains("expected a 64-bit"));
    }

    #[test]
    fn accepts_the_guest_architecture_for_this_host_build() {
        let machine = match std::env::consts::ARCH {
            "x86_64" => 62,
            "aarch64" => 183,
            architecture => panic!("unsupported test architecture {architecture}"),
        };

        validate_agentd(&executable_elf(machine)).unwrap();
    }

    #[test]
    fn rejects_a_guest_architecture_mismatch() {
        let machine = if std::env::consts::ARCH == "x86_64" {
            183
        } else {
            62
        };

        let error = validate_agentd(&executable_elf(machine)).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not match host architecture")
        );
    }

    #[test]
    fn explicit_missing_payload_fails_without_embedded_fallback() {
        let error = AgentdPayload::resolve_from(Some(PathBuf::from(
            "/definitely/missing/microsandbox-agentd",
        )))
        .unwrap_err();

        assert!(matches!(error, AgentdPayloadError::Read { .. }));
    }

    #[test]
    fn explicit_invalid_payload_fails_without_embedded_fallback() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agentd");
        std::fs::write(&path, [0_u8; 64]).unwrap();

        let error = AgentdPayload::resolve_from(Some(path)).unwrap_err();
        assert!(matches!(error, AgentdPayloadError::Invalid(_)));
    }
}
