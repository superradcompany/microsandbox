use napi::bindgen_prelude::*;
use napi_derive::napi;

use microsandbox::RegistryAuth as RustRegistryAuth;
use microsandbox::sandbox::RegistryConfigBuilder as RustRegistryConfigBuilder;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Plain-object form of `RegistryAuth`. `kind: "anonymous" | "basic"`.
#[derive(Clone)]
#[napi(object, js_name = "RegistryAuthInput")]
pub struct JsRegistryAuthInput {
    pub kind: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Fluent builder for OCI registry connection settings.
#[napi(js_name = "RegistryConfigBuilder")]
pub struct JsRegistryConfigBuilder {
    inner: Option<RustRegistryConfigBuilder>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsRegistryConfigBuilder {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Some(RustRegistryConfigBuilder::default()),
        }
    }

    /// Set authentication credentials.
    #[napi]
    pub fn auth(&mut self, auth: JsRegistryAuthInput) -> Result<&Self> {
        let rust_auth = parse_registry_auth(auth)?;
        let prev = self.take_inner();
        self.inner = Some(prev.auth(rust_auth));
        Ok(self)
    }

    /// Use plain HTTP (no TLS).
    #[napi]
    pub fn insecure(&mut self) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.insecure());
        self
    }

    /// Add a PEM-encoded CA root certificate to trust. May be called repeatedly.
    #[napi(js_name = "caCerts")]
    pub fn ca_certs(&mut self, pem_data: Buffer) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.ca_certs(pem_data.to_vec()));
        self
    }

    // Build is intentionally not exposed here — the sandbox builder
    // consumes `RegistryConfigBuilder` via the `registry(...)` callback,
    // which forwards the configuration directly to the core SDK.
}

impl JsRegistryConfigBuilder {
    fn take_inner(&mut self) -> RustRegistryConfigBuilder {
        self.inner
            .take()
            .expect("RegistryConfigBuilder used after consumption")
    }

    /// Internal: extract the underlying Rust builder. Used by
    /// `SandboxBuilder.registry()` to route through the core SDK closure.
    #[allow(dead_code)]
    pub(crate) fn take_inner_builder(&mut self) -> Result<RustRegistryConfigBuilder> {
        self.inner
            .take()
            .ok_or_else(|| napi::Error::from_reason("RegistryConfigBuilder already consumed"))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn parse_registry_auth(auth: JsRegistryAuthInput) -> Result<RustRegistryAuth> {
    match auth.kind.as_str() {
        "anonymous" => Ok(RustRegistryAuth::Anonymous),
        "basic" => {
            let username = auth.username.ok_or_else(|| {
                napi::Error::from_reason("registry auth `basic` requires `username`")
            })?;
            let password = auth.password.ok_or_else(|| {
                napi::Error::from_reason("registry auth `basic` requires `password`")
            })?;
            Ok(RustRegistryAuth::Basic { username, password })
        }
        other => Err(napi::Error::from_reason(format!(
            "unknown registry auth kind `{other}` (expected anonymous | basic)"
        ))),
    }
}
