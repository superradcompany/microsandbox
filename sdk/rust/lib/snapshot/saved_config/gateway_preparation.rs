//! Prepare destination gateway references without resolving credentials or opening host files.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_BYTES, MAX_SAVED_CONFIG_ENTRIES, MAX_SAVED_TEXT_BYTES, SavedBindingKind,
    SavedNetworkConfig, SavedProxyProtocol, SavedValue,
};
use microsandbox_types::{
    DnsConfigPatch, InterceptCaConfig, NetworkSpec, NetworkSpecPatch, OutboundProxy,
    ScopedUpstreamCaCert, SecretSource, Socks5Credentials, TlsConfigPatch,
};

use super::{GatewayInputPlan, select_gateway_inputs};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Destination-owned gateway material. Paths retain the caller's existing resolution policy;
/// none is opened here. Credential sources are resolved by the normal launch preparation.
#[derive(Clone)]
pub enum GatewayBindingInput {
    /// One resolver, in the native IP/hostname and optional-port syntax.
    DnsResolver(String),
    /// Public certificate file, possibly shared by scoped, global and guest trust consumers.
    Certificate(PathBuf),
    /// Both destination certificate and private-key paths; not an auto-generated identity.
    TlsIdentity(InterceptCaConfig),
    /// Native proxy address without a scheme or embedded authentication.
    ProxyEndpoint(String),
    /// SOCKS4 user ID; kept separate from the endpoint.
    Socks4User(String),
    /// SOCKS5 username and unresolved password source.
    Socks5Credentials(Socks5Credentials),
}

/// Native resource inputs plus immutable source requirements. This is not authorization to
/// activate: file validation, credential resolution, policy and captured identity still apply.
pub struct GatewayConfigurationPlan {
    patch: NetworkSpecPatch,
    guest_trust: Vec<PathBuf>,
    selection: GatewayInputPlan,
}

#[derive(Default)]
struct InputBudget(usize);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl GatewayBindingInput {
    pub(super) fn kind(&self) -> SavedBindingKind {
        match self {
            Self::DnsResolver(_) => SavedBindingKind::DnsResolver,
            Self::Certificate(_) => SavedBindingKind::Certificate,
            Self::TlsIdentity(_) => SavedBindingKind::TlsIdentity,
            Self::ProxyEndpoint(_) => SavedBindingKind::ProxyEndpoint,
            Self::Socks4User(_) | Self::Socks5Credentials(_) => SavedBindingKind::ProxyCredentials,
        }
    }
}

impl GatewayConfigurationPlan {
    /// Retain logical requirements and full-resume obligations even after inputs are supplied.
    /// The selection describes pre-binding requirements, not a remaining missing-input set.
    pub fn selection(&self) -> &GatewayInputPlan {
        &self.selection
    }

    /// Apply resource fields without changing sibling network policy, listeners or secrets.
    /// Unknown observations refuse before any destination mutation.
    pub fn apply_inputs_to(&self, destination: &mut NetworkSpec) -> MicrosandboxResult<()> {
        self.require_known()?;
        self.patch.clone().apply_to(destination);
        Ok(())
    }

    /// Certificates still need safe destination loading and guest installation before boot.
    /// A host-trust boolean never substitutes for a selected certificate binding.
    pub fn guest_trust_certificates(&self) -> MicrosandboxResult<&[PathBuf]> {
        self.require_known()?;
        Ok(&self.guest_trust)
    }

    fn require_known(&self) -> MicrosandboxResult<()> {
        if self.selection.unknown_fields.is_empty() {
            Ok(())
        } else {
            Err(error(
                "SCFG_UNKNOWN",
                "gateway observations need explicit resolution",
            ))
        }
    }
}

impl InputBudget {
    fn bytes(&mut self, value: &[u8]) -> MicrosandboxResult<()> {
        if value.is_empty() || value.len() > MAX_SAVED_TEXT_BYTES || value.contains(&0) {
            return Err(error("SCFG_VALUE", "invalid destination gateway input"));
        }
        self.0 = self
            .0
            .checked_add(value.len())
            .ok_or_else(|| error("SCFG_LIMIT", "expanded gateway inputs are too large"))?;
        if self.0 > MAX_SAVED_CONFIG_BYTES {
            return Err(error("SCFG_LIMIT", "expanded gateway inputs are too large"));
        }
        Ok(())
    }

    fn path(&mut self, value: &Path) -> MicrosandboxResult<()> {
        // Do not canonicalize, collapse symlink/.. segments, require UTF-8 or touch the file.
        self.bytes(value.as_os_str().as_encoded_bytes())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for GatewayBindingInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayBindingInput")
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for GatewayConfigurationPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayConfigurationPlan")
            .field("selection", &self.selection)
            .field("guest_trust_count", &self.guest_trust.len())
            .finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Prepare already mode/clear-selected gateway fields and apply explicit inputs last. The
/// caller supplies only surviving gateway bindings, after global binding-demand validation.
/// All selected gateway uses are immediate: missing material never becomes direct egress,
/// auto-generated trust, an empty resolver, or an unauthenticated proxy by fallback.
///
/// Native credential references and file paths remain destination-only. No lookup, file
/// creation, certificate decoding, DNS resolution or serialization to portable metadata occurs.
pub fn prepare_gateway_configuration(
    saved: &SavedNetworkConfig,
    explicit: &NetworkSpecPatch,
    inputs: &BTreeMap<String, GatewayBindingInput>,
    full_resume: bool,
) -> MicrosandboxResult<GatewayConfigurationPlan> {
    let selection = select_gateway_inputs(saved, explicit, full_resume)?;
    if inputs.len() > MAX_SAVED_CONFIG_ENTRIES {
        return Err(error("SCFG_LIMIT", "too many gateway binding inputs"));
    }
    for (id, input) in inputs {
        if selection.remaining_bindings.get(id).map(|use_| use_.kind) != Some(input.kind()) {
            return Err(error(
                "SCFG_BINDING",
                "gateway input has no matching selected consumer",
            ));
        }
    }
    if selection
        .remaining_bindings
        .keys()
        .any(|id| !inputs.contains_key(id))
    {
        return Err(error(
            "SCFG_BINDING",
            "required gateway binding inputs are missing",
        ));
    }

    let mut budget = InputBudget::default();
    let mut patch = NetworkSpecPatch::new();
    let requirements = &selection.requirements;
    if let Some(dns) = requirements.dns.as_ref().and_then(SavedValue::value) {
        let mut nameservers = Vec::new();
        for reference in &dns.resolvers {
            let GatewayBindingInput::DnsResolver(value) = &inputs[&reference.id] else {
                return Err(error("SCFG_BINDING", "resolver input has the wrong kind"));
            };
            budget.bytes(value.as_bytes())?;
            nameservers.push(value.clone());
        }
        patch.dns = Some(DnsConfigPatch::new().nameservers(nameservers));
    }
    if let Some(tls) = requirements.tls.as_ref().and_then(SavedValue::value) {
        let mut prepared = TlsConfigPatch::new();
        prepared.upstream_ca_cert = Some(
            tls.upstream_cas
                .iter()
                .map(|reference| certificate(&inputs[&reference.id], &mut budget))
                .collect::<MicrosandboxResult<_>>()?,
        );
        prepared.scoped_upstream_ca_cert = Some(
            tls.scoped_upstream_cas
                .iter()
                .map(|scope| {
                    budget.bytes(scope.pattern.as_bytes())?;
                    Ok(ScopedUpstreamCaCert {
                        pattern: scope.pattern.clone(),
                        path: certificate(&inputs[&scope.binding.id], &mut budget)?,
                    })
                })
                .collect::<MicrosandboxResult<_>>()?,
        );
        let identity = match &tls.intercept_ca {
            Some(reference) => {
                let GatewayBindingInput::TlsIdentity(value) = &inputs[&reference.id] else {
                    return Err(error(
                        "SCFG_BINDING",
                        "TLS identity input has the wrong kind",
                    ));
                };
                let (Some(cert), Some(key)) = (&value.cert_path, &value.key_path) else {
                    return Err(error(
                        "SCFG_BINDING",
                        "TLS identity binding requires certificate and key paths",
                    ));
                };
                budget.path(cert)?;
                budget.path(key)?;
                value.clone()
            }
            None => InterceptCaConfig::default(),
        };
        prepared.intercept_ca = Some(identity);
        patch.tls = Some(prepared);
    }
    let mut guest_trust = Vec::new();
    if let Some(trust) = requirements
        .guest_trust
        .as_ref()
        .and_then(SavedValue::value)
    {
        for reference in trust {
            guest_trust.push(certificate(&inputs[&reference.id], &mut budget)?);
        }
    }
    if let Some(proxy) = requirements
        .outbound_proxy
        .as_ref()
        .and_then(SavedValue::value)
    {
        let GatewayBindingInput::ProxyEndpoint(address) = &inputs[&proxy.endpoint.id] else {
            return Err(error("SCFG_BINDING", "proxy endpoint has the wrong kind"));
        };
        budget.bytes(address.as_bytes())?;
        let credentials = proxy
            .credentials
            .as_ref()
            .map(|reference| &inputs[&reference.id]);
        patch.outbound_proxy = Some(Some(match (proxy.protocol, credentials) {
            (SavedProxyProtocol::HttpConnect, None) => OutboundProxy::HttpConnect {
                address: address.clone(),
            },
            (SavedProxyProtocol::Socks4, None) => OutboundProxy::Socks4 {
                address: address.clone(),
                user_id: None,
            },
            (SavedProxyProtocol::Socks4, Some(GatewayBindingInput::Socks4User(user))) => {
                // SOCKS4 permits an explicitly empty user ID; do not collapse it to omission.
                if !user.is_empty() {
                    budget.bytes(user.as_bytes())?;
                }
                OutboundProxy::Socks4 {
                    address: address.clone(),
                    user_id: Some(user.clone()),
                }
            }
            (SavedProxyProtocol::Socks5, None) => OutboundProxy::Socks5 {
                address: address.clone(),
                credentials: None,
            },
            (SavedProxyProtocol::Socks5, Some(GatewayBindingInput::Socks5Credentials(auth))) => {
                budget.bytes(auth.username.as_bytes())?;
                let (SecretSource::Env { var: source } | SecretSource::Store { reference: source }) =
                    &auth.password;
                budget.bytes(source.as_bytes())?;
                OutboundProxy::Socks5 {
                    address: address.clone(),
                    credentials: Some(auth.clone()),
                }
            }
            _ => {
                return Err(error(
                    "SCFG_BINDING",
                    "proxy credentials do not match the selected protocol",
                ));
            }
        }));
    }
    for field in &selection.defaulted_fields {
        match *field {
            "network.dns.nameservers" => {
                patch.dns = Some(DnsConfigPatch::new().nameservers(vec![]))
            }
            "network.tls.upstream_ca_cert" => {
                patch
                    .tls
                    .get_or_insert_with(TlsConfigPatch::new)
                    .upstream_ca_cert = Some(vec![])
            }
            "network.tls.scoped_upstream_ca_cert" => {
                patch
                    .tls
                    .get_or_insert_with(TlsConfigPatch::new)
                    .scoped_upstream_ca_cert = Some(vec![])
            }
            "network.tls.intercept_ca" => {
                patch
                    .tls
                    .get_or_insert_with(TlsConfigPatch::new)
                    .intercept_ca = Some(InterceptCaConfig::default())
            }
            "network.outbound_proxy" => patch.outbound_proxy = Some(None),
            "network.guest_trust" => {} // No destination-supplied certificate requirements.
            _ => return Err(error("SCFG_VALUE", "unknown gateway default field")),
        }
    }
    // Compose through native patch merging: an explicit empty list/clear must replace the
    // prepared requirement, while a resource override must never erase sibling policy.
    patch = patch.overlay(selection.destination.clone());
    Ok(GatewayConfigurationPlan {
        patch,
        guest_trust,
        selection,
    })
}

fn certificate(
    input: &GatewayBindingInput,
    budget: &mut InputBudget,
) -> MicrosandboxResult<PathBuf> {
    let GatewayBindingInput::Certificate(path) = input else {
        return Err(error(
            "SCFG_BINDING",
            "certificate input has the wrong kind",
        ));
    };
    budget.path(path)?;
    Ok(path.clone())
}

fn error(code: &str, reason: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(format!("{code}: network: {reason}"))
}
