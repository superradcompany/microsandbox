use napi::bindgen_prelude::*;
use napi_derive::napi;

use microsandbox_network::builder::NetworkBuilder as RustNetworkBuilder;
use microsandbox_network::policy::NetworkPolicy as RustNetworkPolicy;
use microsandbox_network::secrets::config::ViolationAction as RustViolationAction;

use crate::dns_builder::JsDnsBuilder;
use crate::secret_builder::JsSecretBuilder;
use crate::tls_builder::JsTlsBuilder;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fluent builder for sandbox network configuration.
#[napi(js_name = "NetworkBuilder")]
pub struct JsNetworkBuilder {
    inner: Option<RustNetworkBuilder>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsNetworkBuilder {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Some(RustNetworkBuilder::new()),
        }
    }

    /// Enable or disable networking.
    #[napi]
    pub fn enabled(&mut self, enabled: bool) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.enabled(enabled));
        self
    }

    /// Publish a TCP port.
    #[napi]
    pub fn port(&mut self, host_port: u32, guest_port: u32) -> Result<&Self> {
        let h = u16::try_from(host_port)
            .map_err(|_| napi::Error::from_reason("host port out of range"))?;
        let g = u16::try_from(guest_port)
            .map_err(|_| napi::Error::from_reason("guest port out of range"))?;
        let prev = self.take_inner();
        self.inner = Some(prev.port(h, g));
        Ok(self)
    }

    /// Publish a UDP port.
    #[napi(js_name = "portUdp")]
    pub fn port_udp(&mut self, host_port: u32, guest_port: u32) -> Result<&Self> {
        let h = u16::try_from(host_port)
            .map_err(|_| napi::Error::from_reason("host port out of range"))?;
        let g = u16::try_from(guest_port)
            .map_err(|_| napi::Error::from_reason("guest port out of range"))?;
        let prev = self.take_inner();
        self.inner = Some(prev.port_udp(h, g));
        Ok(self)
    }

    /// Set a policy. Construct via the JS-side `NetworkPolicy.publicOnly()`
    /// / `.allowAll()` / `.none()` / `.nonLocal()` factories or build a
    /// custom one and pass it through `JSON.stringify`-friendly JSON. Here
    /// we accept the canonical serialized form (a JSON string) to avoid
    /// re-modeling the rule schema across the FFI; Phase 7 reconciles.
    #[napi(js_name = "policyJson")]
    pub fn policy_json(&mut self, json: String) -> Result<&Self> {
        let policy: RustNetworkPolicy = serde_json::from_str(&json)
            .map_err(|e| napi::Error::from_reason(format!("invalid policy JSON: {e}")))?;
        let prev = self.take_inner();
        self.inner = Some(prev.policy(policy));
        Ok(self)
    }

    /// Configure DNS interception via a callback. The callback receives
    /// a fresh `DnsBuilder`; chain setters on it and return.
    #[napi]
    pub fn dns(
        &mut self,
        env: &Env,
        configure: Function<ClassInstance<JsDnsBuilder>, ClassInstance<JsDnsBuilder>>,
    ) -> Result<&Self> {
        let initial = JsDnsBuilder::new().into_instance(env)?;
        let mut returned = configure.call(initial)?;
        let dns_builder = returned.take_inner_builder()?;
        let prev = self.take_inner();
        self.inner = Some(prev.dns(|_default| dns_builder));
        Ok(self)
    }

    /// Configure TLS interception via a callback.
    #[napi]
    pub fn tls(
        &mut self,
        env: &Env,
        configure: Function<ClassInstance<JsTlsBuilder>, ClassInstance<JsTlsBuilder>>,
    ) -> Result<&Self> {
        let initial = JsTlsBuilder::new().into_instance(env)?;
        let mut returned = configure.call(initial)?;
        let tls_builder = returned.take_inner_builder()?;
        let prev = self.take_inner();
        self.inner = Some(prev.tls(|_default| tls_builder));
        Ok(self)
    }

    /// Add a secret via a callback.
    #[napi]
    pub fn secret(
        &mut self,
        env: &Env,
        configure: Function<ClassInstance<JsSecretBuilder>, ClassInstance<JsSecretBuilder>>,
    ) -> Result<&Self> {
        let initial = JsSecretBuilder::new().into_instance(env)?;
        let mut returned = configure.call(initial)?;
        let secret_builder = returned.take_inner_builder()?;
        let prev = self.take_inner();
        self.inner = Some(prev.secret(|_default| secret_builder));
        Ok(self)
    }

    /// 4-arg shorthand: add a secret with explicit placeholder.
    #[napi(js_name = "secretEnv")]
    pub fn secret_env(
        &mut self,
        env_var: String,
        value: String,
        placeholder: String,
        allowed_host: String,
    ) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.secret_env(env_var, value, placeholder, allowed_host));
        self
    }

    /// Set the violation action for secrets: `"block" | "block-and-log"
    /// | "block-and-terminate"`.
    #[napi(js_name = "onSecretViolation")]
    pub fn on_secret_violation(&mut self, action: String) -> Result<&Self> {
        let act = parse_violation_action(&action)?;
        let prev = self.take_inner();
        self.inner = Some(prev.on_secret_violation(act));
        Ok(self)
    }

    /// Set the maximum number of concurrent connections.
    #[napi(js_name = "maxConnections")]
    pub fn max_connections(&mut self, max: u32) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.max_connections(max as usize));
        self
    }

    /// Trust the host's root CAs inside the guest. Default: false.
    #[napi(js_name = "trustHostCAs")]
    pub fn trust_host_cas(&mut self, enabled: bool) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.trust_host_cas(enabled));
        self
    }
}

impl JsNetworkBuilder {
    fn take_inner(&mut self) -> RustNetworkBuilder {
        self.inner
            .take()
            .expect("NetworkBuilder used after consumption")
    }

    /// Internal: extract the underlying Rust builder. Used by
    /// `SandboxBuilder.network()` to route through the core SDK closure.
    #[allow(dead_code)]
    pub(crate) fn take_inner_builder(&mut self) -> Result<RustNetworkBuilder> {
        self.inner
            .take()
            .ok_or_else(|| napi::Error::from_reason("NetworkBuilder already consumed"))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn parse_violation_action(s: &str) -> Result<RustViolationAction> {
    match s {
        "block" => Ok(RustViolationAction::Block),
        "block-and-log" => Ok(RustViolationAction::BlockAndLog),
        "block-and-terminate" => Ok(RustViolationAction::BlockAndTerminate),
        other => Err(napi::Error::from_reason(format!(
            "unknown violation action `{other}` (expected block | block-and-log | block-and-terminate)"
        ))),
    }
}
