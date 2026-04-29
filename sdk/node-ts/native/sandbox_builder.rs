use std::path::PathBuf;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use microsandbox::sandbox::LogLevel as RustLogLevel;
use microsandbox::sandbox::{
    PullPolicy as RustPullPolicy, Sandbox as RustSandbox, SandboxBuilder as RustSandboxBuilder,
};
use microsandbox::size::Mebibytes;

use crate::dns_builder::JsDnsBuilder;
use crate::error::to_napi_error;
use crate::exec_options_builder::parse_rlimit_resource;
use crate::image_builder::JsImageBuilder;
use crate::mount_builder::JsMountBuilder;
use crate::network_builder::JsNetworkBuilder;
use crate::patch_builder::JsPatchBuilder;
use crate::registry_builder::JsRegistryConfigBuilder;
use crate::sandbox::Sandbox as JsSandbox;
use crate::secret_builder::JsSecretBuilder;
use crate::tls_builder::JsTlsBuilder;

// Hint to the napi codegen so `dns/tls/secret` callbacks below also
// re-emit references to these classes (otherwise they'd appear as
// the Rust struct names in `index.d.ts`).
#[allow(dead_code)]
type _NapiHints = (JsDnsBuilder, JsTlsBuilder, JsSecretBuilder);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fluent builder for a sandbox. Mirrors `microsandbox::sandbox::SandboxBuilder`
/// 1:1; setters mutate in place and return `this`. Closure-style
/// sub-builders (volume / patch / network / secret / registry / imageWith)
/// receive a fresh napi-wrapped builder, let JS chain on it, and route
/// the result back through the core SDK's closure callback.
#[napi(js_name = "SandboxBuilder")]
pub struct JsSandboxBuilder {
    inner: Option<RustSandboxBuilder>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsSandboxBuilder {
    #[napi(constructor)]
    pub fn new(name: String) -> Self {
        Self {
            inner: Some(RustSandboxBuilder::new(name)),
        }
    }

    /// Set the rootfs image source. Accepts an OCI reference or a host
    /// path (paths starting with `/`, `./`, `../` resolve as local; disk
    /// image extensions `.qcow2`/`.raw`/`.vmdk` resolve to virtio-blk).
    #[napi]
    pub fn image(&mut self, image: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.image(image));
        self
    }

    /// Configure a disk-image rootfs explicitly via a callback.
    #[napi(js_name = "imageWith")]
    pub fn image_with(
        &mut self,
        env: &Env,
        configure: Function<ClassInstance<JsImageBuilder>, ClassInstance<JsImageBuilder>>,
    ) -> Result<&Self> {
        let initial = JsImageBuilder::new().into_instance(env)?;
        let mut returned = configure.call(initial)?;
        let img_builder = returned.take_inner_builder()?;
        let prev = self.take_inner();
        self.inner = Some(prev.image_with(|_default| img_builder));
        Ok(self)
    }

    /// Number of virtual CPUs.
    #[napi]
    pub fn cpus(&mut self, count: u32) -> Result<&Self> {
        let n =
            u8::try_from(count).map_err(|_| napi::Error::from_reason("cpus out of u8 range"))?;
        let prev = self.take_inner();
        self.inner = Some(prev.cpus(n));
        Ok(self)
    }

    /// Guest memory in MiB.
    #[napi]
    pub fn memory(&mut self, mib: u32) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.memory(Mebibytes::from(mib)));
        self
    }

    /// Override log verbosity: `"trace" | "debug" | "info" | "warn" | "error"`.
    #[napi(js_name = "logLevel")]
    pub fn log_level(&mut self, level: String) -> Result<&Self> {
        let l = match level.as_str() {
            "trace" => RustLogLevel::Trace,
            "debug" => RustLogLevel::Debug,
            "info" => RustLogLevel::Info,
            "warn" => RustLogLevel::Warn,
            "error" => RustLogLevel::Error,
            other => {
                return Err(napi::Error::from_reason(format!(
                    "invalid log level `{other}`"
                )));
            }
        };
        let prev = self.take_inner();
        self.inner = Some(prev.log_level(l));
        Ok(self)
    }

    /// Suppress sandbox logs.
    #[napi(js_name = "quietLogs")]
    pub fn quiet_logs(&mut self) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.quiet_logs());
        self
    }

    /// Default working directory for commands.
    #[napi]
    pub fn workdir(&mut self, path: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.workdir(path));
        self
    }

    /// Shell binary used by `Sandbox.shell(...)`.
    #[napi]
    pub fn shell(&mut self, shell: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.shell(shell));
        self
    }

    /// Configure registry connection settings via a callback.
    #[napi]
    pub fn registry(
        &mut self,
        env: &Env,
        configure: Function<
            ClassInstance<JsRegistryConfigBuilder>,
            ClassInstance<JsRegistryConfigBuilder>,
        >,
    ) -> Result<&Self> {
        let initial = JsRegistryConfigBuilder::new().into_instance(env)?;
        let mut returned = configure.call(initial)?;
        let reg_builder = returned.take_inner_builder()?;
        let prev = self.take_inner();
        self.inner = Some(prev.registry(|_default| reg_builder));
        Ok(self)
    }

    /// Replace any existing sandbox with the same name.
    #[napi]
    pub fn replace(&mut self) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.replace());
        self
    }

    /// Override the image entrypoint.
    #[napi]
    pub fn entrypoint(&mut self, cmd: Vec<String>) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.entrypoint(cmd));
        self
    }

    /// Override the guest hostname.
    #[napi]
    pub fn hostname(&mut self, name: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.hostname(name));
        self
    }

    /// Override the libkrunfw shared library path for this sandbox.
    #[napi(js_name = "libkrunfwPath")]
    pub fn libkrunfw_path(&mut self, path: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.libkrunfw_path(PathBuf::from(path)));
        self
    }

    /// Default running user.
    #[napi]
    pub fn user(&mut self, user: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.user(user));
        self
    }

    /// Image pull policy: `"always" | "if-missing" | "never"`.
    #[napi(js_name = "pullPolicy")]
    pub fn pull_policy(&mut self, policy: String) -> Result<&Self> {
        let p = match policy.as_str() {
            "always" => RustPullPolicy::Always,
            "if-missing" => RustPullPolicy::IfMissing,
            "never" => RustPullPolicy::Never,
            other => {
                return Err(napi::Error::from_reason(format!(
                    "invalid pull policy `{other}`"
                )));
            }
        };
        let prev = self.take_inner();
        self.inner = Some(prev.pull_policy(p));
        Ok(self)
    }

    /// Disable networking entirely.
    #[napi(js_name = "disableNetwork")]
    pub fn disable_network(&mut self) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.disable_network());
        self
    }

    /// Configure networking via a callback.
    #[napi]
    pub fn network(
        &mut self,
        env: &Env,
        configure: Function<ClassInstance<JsNetworkBuilder>, ClassInstance<JsNetworkBuilder>>,
    ) -> Result<&Self> {
        let initial = JsNetworkBuilder::new().into_instance(env)?;
        let mut returned = configure.call(initial)?;
        let net_builder = returned.take_inner_builder()?;
        let prev = self.take_inner();
        self.inner = Some(prev.network(|_default| net_builder));
        Ok(self)
    }

    /// Publish a TCP port from host -> guest.
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

    /// Publish a UDP port from host -> guest.
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

    /// Shorthand: add a secret. Auto-generates the placeholder as
    /// `$MSB_<env_var>` and allows substitution only on `allowed_host`.
    #[napi(js_name = "secretEnv")]
    pub fn secret_env(&mut self, env_var: String, value: String, allowed_host: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.secret_env(env_var, value, allowed_host));
        self
    }

    /// Set a single environment variable.
    #[napi]
    pub fn env(&mut self, key: String, value: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.env(key, value));
        self
    }

    /// Set environment variables from an object.
    #[napi]
    pub fn envs(&mut self, vars: std::collections::HashMap<String, String>) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.envs(vars));
        self
    }

    /// Set a hard rlimit (soft = hard).
    #[napi]
    pub fn rlimit(&mut self, resource: String, limit: u32) -> Result<&Self> {
        let res = parse_rlimit_resource(&resource)?;
        let prev = self.take_inner();
        self.inner = Some(prev.rlimit(res, limit as u64));
        Ok(self)
    }

    /// Set a separate soft and hard rlimit.
    #[napi(js_name = "rlimitRange")]
    pub fn rlimit_range(&mut self, resource: String, soft: u32, hard: u32) -> Result<&Self> {
        let res = parse_rlimit_resource(&resource)?;
        let prev = self.take_inner();
        self.inner = Some(prev.rlimit_range(res, soft as u64, hard as u64));
        Ok(self)
    }

    /// Mount a script under `/.msb/scripts/<name>` inside the guest.
    #[napi]
    pub fn script(&mut self, name: String, content: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.script(name, content));
        self
    }

    /// Mount many scripts at once.
    #[napi]
    pub fn scripts(&mut self, scripts: std::collections::HashMap<String, String>) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.scripts(scripts));
        self
    }

    /// Auto-stop after `secs` seconds.
    #[napi(js_name = "maxDuration")]
    pub fn max_duration(&mut self, secs: u32) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.max_duration(secs as u64));
        self
    }

    /// Auto-stop after `secs` seconds of inactivity.
    #[napi(js_name = "idleTimeout")]
    pub fn idle_timeout(&mut self, secs: u32) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.idle_timeout(secs as u64));
        self
    }

    /// Configure a volume mount via a callback. The callback receives a
    /// `MountBuilder` already pre-bound to `guestPath`.
    #[napi]
    pub fn volume(
        &mut self,
        env: &Env,
        guest_path: String,
        configure: Function<ClassInstance<JsMountBuilder>, ClassInstance<JsMountBuilder>>,
    ) -> Result<&Self> {
        let initial = JsMountBuilder::new(guest_path.clone()).into_instance(env)?;
        let mut returned = configure.call(initial)?;
        let mount_builder = returned.take_inner_builder()?;
        let prev = self.take_inner();
        // The core's volume() signature is volume(guest_path, FnOnce(MountBuilder) -> MountBuilder).
        // The MountBuilder we hand back already encodes the guest path
        // (we constructed it that way above); the default supplied by
        // the core is discarded.
        self.inner = Some(prev.volume(guest_path, |_default| mount_builder));
        Ok(self)
    }

    /// Add a single rootfs patch built externally.
    #[napi(js_name = "addPatch")]
    pub fn add_patch(&mut self, patch: crate::patch_builder::JsBuiltPatch) -> Result<&Self> {
        let p = crate::patch_builder::js_patch_to_rust(patch)?;
        let prev = self.take_inner();
        self.inner = Some(prev.add_patch(p));
        Ok(self)
    }

    /// Apply rootfs patches via a callback.
    #[napi]
    pub fn patch(
        &mut self,
        env: &Env,
        configure: Function<ClassInstance<JsPatchBuilder>, ClassInstance<JsPatchBuilder>>,
    ) -> Result<&Self> {
        let initial = JsPatchBuilder::new().into_instance(env)?;
        let mut returned = configure.call(initial)?;
        let patches = returned.take_built()?;
        let prev = self.take_inner();
        let mut next = prev;
        for p in patches {
            next = next.add_patch(p);
        }
        self.inner = Some(next);
        Ok(self)
    }

    /// Materialize the built configuration without creating a sandbox.
    /// Returns the JSON-serialized `SandboxConfig` for inspection.
    #[napi]
    pub fn build(&mut self) -> Result<String> {
        let b = self
            .inner
            .take()
            .ok_or_else(|| napi::Error::from_reason("SandboxBuilder already consumed"))?;
        let cfg = b.build().map_err(to_napi_error)?;
        serde_json::to_string(&cfg)
            .map_err(|e| napi::Error::from_reason(format!("failed to serialize config: {e}")))
    }

    /// Create and start the sandbox in attached mode.
    ///
    /// # Safety
    /// `&mut self` async is required because we drain `inner`
    /// synchronously before awaiting; napi-rs requires the `unsafe` tag
    /// regardless. JS callers see `create(): Promise<Sandbox>`.
    #[napi]
    pub async unsafe fn create(&mut self) -> Result<JsSandbox> {
        let b = self
            .inner
            .take()
            .ok_or_else(|| napi::Error::from_reason("SandboxBuilder already consumed"))?;
        let inner: RustSandbox = b.create().await.map_err(to_napi_error)?;
        Ok(JsSandbox::from_rust(inner))
    }

    /// Create and start the sandbox in detached mode (survives the
    /// parent process).
    ///
    /// # Safety
    /// Same justification as `create`.
    #[napi(js_name = "createDetached")]
    pub async unsafe fn create_detached(&mut self) -> Result<JsSandbox> {
        let b = self
            .inner
            .take()
            .ok_or_else(|| napi::Error::from_reason("SandboxBuilder already consumed"))?;
        let inner: RustSandbox = b.create_detached().await.map_err(to_napi_error)?;
        Ok(JsSandbox::from_rust(inner))
    }
}

impl JsSandboxBuilder {
    fn take_inner(&mut self) -> RustSandboxBuilder {
        self.inner
            .take()
            .expect("SandboxBuilder used after consumption")
    }
}
