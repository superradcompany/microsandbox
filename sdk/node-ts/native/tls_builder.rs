use std::path::PathBuf;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use microsandbox_network::builder::TlsBuilder as RustTlsBuilder;
use microsandbox_network::tls::TlsConfig as RustTlsConfig;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// TLS interception configuration produced by `TlsBuilder.build()`.
#[derive(Clone)]
#[napi(object, js_name = "TlsConfig")]
pub struct JsTlsConfig {
    pub enabled: bool,
    pub bypass: Vec<String>,
    pub verify_upstream: bool,
    pub intercepted_ports: Vec<u32>,
    pub block_quic: bool,
    pub upstream_ca_cert_paths: Vec<String>,
    pub intercept_ca_cert_path: Option<String>,
    pub intercept_ca_key_path: Option<String>,
}

/// Fluent builder for TLS interception settings.
#[napi(js_name = "TlsBuilder")]
pub struct JsTlsBuilder {
    inner: Option<RustTlsBuilder>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsTlsBuilder {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Some(RustTlsBuilder::new()),
        }
    }

    /// Add a bypass pattern (no MITM). Supports `*.suffix` wildcards.
    #[napi]
    pub fn bypass(&mut self, pattern: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.bypass(pattern));
        self
    }

    /// Verify upstream server certificates (default: true).
    #[napi(js_name = "verifyUpstream")]
    pub fn verify_upstream(&mut self, verify: bool) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.verify_upstream(verify));
        self
    }

    /// Set the ports to intercept (default: 443).
    #[napi(js_name = "interceptedPorts")]
    pub fn intercepted_ports(&mut self, ports: Vec<u32>) -> Result<&Self> {
        let ports16: std::result::Result<Vec<u16>, _> =
            ports.iter().map(|p| u16::try_from(*p)).collect();
        let ports16 =
            ports16.map_err(|_| napi::Error::from_reason("intercepted port out of u16 range"))?;
        let prev = self.take_inner();
        self.inner = Some(prev.intercepted_ports(ports16));
        Ok(self)
    }

    /// Block QUIC on intercepted ports (default: true).
    #[napi(js_name = "blockQuic")]
    pub fn block_quic(&mut self, block: bool) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.block_quic(block));
        self
    }

    /// Add an upstream CA certificate PEM path. May be called repeatedly.
    #[napi(js_name = "upstreamCaCert")]
    pub fn upstream_ca_cert(&mut self, path: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.upstream_ca_cert(PathBuf::from(path)));
        self
    }

    /// Set a custom interception CA certificate PEM path.
    #[napi(js_name = "interceptCaCert")]
    pub fn intercept_ca_cert(&mut self, path: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.intercept_ca_cert(PathBuf::from(path)));
        self
    }

    /// Set a custom interception CA private key PEM path.
    #[napi(js_name = "interceptCaKey")]
    pub fn intercept_ca_key(&mut self, path: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.intercept_ca_key(PathBuf::from(path)));
        self
    }

    /// Materialize into a `TlsConfig`.
    #[napi]
    pub fn build(&mut self) -> Result<JsTlsConfig> {
        let cfg = self.take_built()?;
        Ok(to_js_tls_config(cfg))
    }
}

impl JsTlsBuilder {
    fn take_inner(&mut self) -> RustTlsBuilder {
        self.inner
            .take()
            .expect("TlsBuilder used after .build() consumed it")
    }

    /// Internal: extract the underlying Rust builder. Used by
    /// `NetworkBuilder.tls()` to route through the core SDK closure.
    #[allow(dead_code)]
    pub(crate) fn take_inner_builder(&mut self) -> Result<RustTlsBuilder> {
        self.inner
            .take()
            .ok_or_else(|| napi::Error::from_reason("TlsBuilder already consumed"))
    }

    /// Internal: extract the built `TlsConfig`. Used by `NetworkBuilder.tls()`.
    #[allow(dead_code)]
    pub(crate) fn take_built(&mut self) -> Result<RustTlsConfig> {
        let b = self
            .inner
            .take()
            .ok_or_else(|| napi::Error::from_reason("TlsBuilder.build() called more than once"))?;
        Ok(b.build())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn to_js_tls_config(cfg: RustTlsConfig) -> JsTlsConfig {
    JsTlsConfig {
        enabled: cfg.enabled,
        bypass: cfg.bypass,
        verify_upstream: cfg.verify_upstream,
        intercepted_ports: cfg.intercepted_ports.iter().map(|p| *p as u32).collect(),
        block_quic: cfg.block_quic_on_intercept,
        upstream_ca_cert_paths: cfg
            .upstream_ca_cert
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect(),
        intercept_ca_cert_path: cfg
            .intercept_ca
            .cert_path
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned()),
        intercept_ca_key_path: cfg
            .intercept_ca
            .key_path
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned()),
    }
}
