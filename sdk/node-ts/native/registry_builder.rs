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

/// Built registry configuration produced by `RegistryConfigBuilder.build()`.
#[derive(Clone)]
#[napi(object, js_name = "RegistryConfig")]
pub struct JsRegistryConfig {
    pub auth: Option<JsRegistryAuthInput>,
    pub insecure: bool,
    /// Number of PEM CA certs accumulated via `caCerts(buffer)`. Bytes
    /// themselves are not echoed back.
    pub ca_certs_count: u32,
    /// Filesystem path passed to `caCertsPath(path)`, if any.
    pub ca_certs_path: Option<String>,
}

/// Fluent builder for OCI registry connection settings.
#[napi(js_name = "RegistryConfigBuilder")]
pub struct JsRegistryConfigBuilder {
    inner: Option<RustRegistryConfigBuilder>,
    auth: Option<JsRegistryAuthInput>,
    insecure: bool,
    ca_certs_count: u32,
    ca_certs_path: Option<String>,
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
            auth: None,
            insecure: false,
            ca_certs_count: 0,
            ca_certs_path: None,
        }
    }

    /// Set authentication credentials.
    #[napi]
    pub fn auth(&mut self, auth: JsRegistryAuthInput) -> Result<&Self> {
        let rust_auth = parse_registry_auth(auth.clone())?;
        let prev = self.take_inner();
        self.inner = Some(prev.auth(rust_auth));
        self.auth = Some(auth);
        Ok(self)
    }

    /// Use plain HTTP (no TLS).
    #[napi]
    pub fn insecure(&mut self) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.insecure());
        self.insecure = true;
        self
    }

    /// Add a PEM-encoded CA root certificate (raw bytes). May be called
    /// repeatedly to add several CAs.
    #[napi(js_name = "caCerts")]
    pub fn ca_certs(&mut self, pem_data: Buffer) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.ca_certs(pem_data.to_vec()));
        self.ca_certs_count += 1;
        self
    }

    /// Read a PEM CA root certificate from `path` and add it. Convenience
    /// shorthand over `caCerts(buffer)`. Panics on read failure deferred
    /// to the next async call site if the path doesn't exist (we surface
    /// it as a typed error there).
    #[napi(js_name = "caCertsPath")]
    pub fn ca_certs_path(&mut self, path: String) -> Result<&Self> {
        let pem = std::fs::read(&path).map_err(|e| {
            napi::Error::from_reason(format!("failed to read CA certs from `{path}`: {e}"))
        })?;
        let prev = self.take_inner();
        self.inner = Some(prev.ca_certs(pem));
        self.ca_certs_count += 1;
        self.ca_certs_path = Some(path);
        Ok(self)
    }

    /// Snapshot the accumulated configuration.
    #[napi]
    pub fn build(&self) -> JsRegistryConfig {
        JsRegistryConfig {
            auth: self.auth.clone(),
            insecure: self.insecure,
            ca_certs_count: self.ca_certs_count,
            ca_certs_path: self.ca_certs_path.clone(),
        }
    }
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
