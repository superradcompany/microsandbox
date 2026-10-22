//! One destination registry for all consumers of a logical saved binding.

use std::fmt;

use microsandbox_types::SecretSource;
use microsandbox_types::snapshot::saved_config::{MAX_SAVED_CONFIG_BYTES, SavedBindingKind};

use super::{GatewayBindingInput, ListenerBindingInput, RuntimeBindingInput, StorageBindingInput};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Destination material, never persisted in a portable saved-config document. A shared ID
/// has one value, even when command defaults and host substitution both consume it.
pub enum ConfigurationBindingInput {
    /// Resolved text, with an exact mode when it also supplies registered script backing.
    Text(RuntimeBindingInput),
    /// Unresolved destination credential reference. It can prepare substitution policy, but
    /// cannot masquerade as ready argv/env/init/script text.
    TextSource(SecretSource),
    /// Gateway endpoint, trust or authentication input.
    Gateway(GatewayBindingInput),
    /// Filesystem or IPC input; existence and captured identity remain unproved.
    Storage(StorageBindingInput),
    /// Destination listener address, before socket allocation.
    Listener(ListenerBindingInput),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ConfigurationBindingInput {
    pub(super) fn kind(&self) -> SavedBindingKind {
        match self {
            Self::Text(_) | Self::TextSource(_) => SavedBindingKind::Text,
            Self::Gateway(value) => value.kind(),
            Self::Storage(value) => value.kind(),
            Self::Listener(_) => SavedBindingKind::Listener,
        }
    }

    /// Bound the entire registry before any family copies shared material. Per-family
    /// preparation still validates shape and expanded consumer budgets afterward. Captured-
    /// only inputs are retained for identity admission and receive this bound too.
    pub(super) fn account_bytes(&self, total: &mut usize) -> MicrosandboxResult<()> {
        let mut add = |bytes: usize| {
            *total = total.checked_add(bytes).ok_or_else(limit_error)?;
            if *total > MAX_SAVED_CONFIG_BYTES {
                return Err(limit_error());
            }
            Ok(())
        };
        match self {
            Self::Text(input) => add(input.text.len()),
            Self::TextSource(source) => add(source_bytes(source)),
            Self::Listener(_) => Ok(()),
            Self::Storage(input) => match input {
                StorageBindingInput::FilesystemFile(path)
                | StorageBindingInput::FilesystemDirectory(path)
                | StorageBindingInput::DiskImage(path)
                | StorageBindingInput::StreamSocket(path)
                | StorageBindingInput::DatagramSocket(path) => {
                    add(path.as_os_str().as_encoded_bytes().len())
                }
                StorageBindingInput::NamedDirectory(name)
                | StorageBindingInput::NamedDisk(name) => add(name.len()),
            },
            Self::Gateway(input) => match input {
                GatewayBindingInput::DnsResolver(value)
                | GatewayBindingInput::ProxyEndpoint(value)
                | GatewayBindingInput::Socks4User(value) => add(value.len()),
                GatewayBindingInput::Certificate(path) => {
                    add(path.as_os_str().as_encoded_bytes().len())
                }
                GatewayBindingInput::TlsIdentity(identity) => {
                    for path in [&identity.cert_path, &identity.key_path]
                        .into_iter()
                        .flatten()
                    {
                        add(path.as_os_str().as_encoded_bytes().len())?;
                    }
                    Ok(())
                }
                GatewayBindingInput::Socks5Credentials(credentials) => {
                    add(credentials.username.len())?;
                    add(source_bytes(&credentials.password))
                }
            },
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for ConfigurationBindingInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigurationBindingInput")
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn source_bytes(source: &SecretSource) -> usize {
    match source {
        SecretSource::Env { var } => var.len(),
        SecretSource::Store { reference } => reference.len(),
    }
}

fn limit_error() -> MicrosandboxError {
    MicrosandboxError::InvalidConfig("SCFG_LIMIT: destination binding registry is too large".into())
}
