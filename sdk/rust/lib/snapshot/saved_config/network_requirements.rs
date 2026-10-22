//! Source-bound logical requirements. Never derive identifiers from private values or paths.

use microsandbox_types::OutboundProxy;
use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_ENTRIES, SavedBindingReference, SavedTlsCaptureBindings,
};

use super::{NetworkCaptureBindings, ProxyCaptureBindings, RuntimeCaptureSource};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Active and next-start requirements must not accidentally share an identity when
/// their source values differ. Only fixed field names and ordinals enter generated IDs.
#[derive(Clone, Copy)]
pub(crate) enum NetworkCaptureSection {
    Active,
    Pending,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RuntimeCaptureSource<'_> {
    /// Derive requirements from this exact retained record, not current catalog intent.
    /// Partial historical sections stay unknown. Guest trust remains supplied by an
    /// independent inventory; neither a boolean nor a source path establishes its identity.
    /// These references do not grant destination access or prove full-resume fidelity.
    pub(crate) fn network_requirements(
        &self,
        section: NetworkCaptureSection,
        guest_trust: Vec<SavedBindingReference>,
    ) -> MicrosandboxResult<NetworkCaptureBindings> {
        let prefix = match section {
            NetworkCaptureSection::Active => "active.network",
            NetworkCaptureSection::Pending => "pending.network",
        };
        let reference = |field: &str| SavedBindingReference {
            id: format!("{prefix}.{field}"),
        };
        let references = |field: &str, length: usize| {
            if length > MAX_SAVED_CONFIG_ENTRIES {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "SCFG_LIMIT: network.{field}: too many binding requirements"
                )));
            }
            Ok((0..length)
                .map(|index| reference(&format!("{field}.{index}")))
                .collect::<Vec<_>>())
        };
        let network = &self.config.spec.network;
        let mut bindings = NetworkCaptureBindings {
            guest_trust,
            ..Default::default()
        };
        if self.complete_network_field("dns")
            && let Some(dns) = &network.dns
        {
            bindings.resolvers = references("dns.resolvers", dns.nameservers.len())?;
        }
        if self.complete_network_field("tls")
            && let Some(tls) = &network.tls
        {
            bindings.tls = Some(SavedTlsCaptureBindings {
                upstream_cas: references("tls.upstream_cas", tls.upstream_ca_cert.len())?,
                scoped_upstream_cas: references(
                    "tls.scoped_upstream_cas",
                    tls.scoped_upstream_ca_cert.len(),
                )?,
                // Enabled interception also needs a destination identity when the source
                // generated its CA automatically. Never copy the generated private key.
                intercept_ca: (tls.enabled
                    || tls.intercept_ca.cert_path.is_some()
                    || tls.intercept_ca.key_path.is_some())
                .then(|| reference("tls.intercept_ca")),
            });
        }
        if self.complete_network_field("ports") {
            bindings.listeners = references("listeners", network.ports.len())?;
        }
        if self.complete_network_field("secrets")
            && let Some(secrets) = &network.secrets
        {
            let requirements = references("secrets", secrets.secrets.len())?;
            for (secret, binding) in secrets.secrets.iter().zip(requirements) {
                // This key names the guest placeholder variable, not its host secret
                // source. Preserve guest policy, but use ordinals for binding IDs and
                // never inspect host source names, resolved values or their digests.
                if bindings
                    .secrets
                    .insert(secret.env_var.clone(), binding)
                    .is_some()
                {
                    return Err(MicrosandboxError::InvalidConfig(
                        "SCFG_BINDING: network.secrets: duplicate source secret key".into(),
                    ));
                }
            }
        }
        if self.complete_network_field("outbound_proxy")
            && let Some(proxy) = &network.outbound_proxy
        {
            let authenticated = match proxy {
                OutboundProxy::HttpConnect { .. } => false,
                OutboundProxy::Socks4 { user_id, .. } => user_id.is_some(),
                OutboundProxy::Socks5 { credentials, .. } => credentials.is_some(),
                _ => {
                    return Err(MicrosandboxError::InvalidConfig(
                        "SCFG_UNSUPPORTED: network.outbound_proxy: unsupported proxy protocol"
                            .into(),
                    ));
                }
            };
            bindings.proxy = Some(ProxyCaptureBindings {
                endpoint: reference("proxy.endpoint"),
                credentials: authenticated.then(|| reference("proxy.credentials")),
            });
        }
        Ok(bindings)
    }
}
