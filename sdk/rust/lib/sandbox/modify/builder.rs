//! The modification builders and their dispatch: a local sandbox to the
//! engine in `local`, a Cloud sandbox to the server.

use std::sync::Arc;

use microsandbox_types::{EnvVar, SecretSubstitution, SecretViolationAction};

#[cfg(feature = "local")]
use super::local;
use super::{
    ModificationPolicy, PublishedPortKey, SandboxModificationPatch, SandboxModificationPlan,
    SecretModificationPatch, SecretSource,
};
use crate::MicrosandboxResult;
use crate::backend::{Backend, SandboxIdentity};
#[cfg(not(feature = "local"))]
use crate::error::{Operation, UnsupportedReason};
use crate::size::Mebibytes;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fluent builder returned by [`Sandbox::modify`](crate::sandbox::Sandbox::modify).
///
/// [`dry_run`](Self::dry_run) plans the patch; [`apply`](Self::apply) applies it.
#[derive(Clone)]
pub struct SandboxModificationBuilder {
    pub(super) backend: Arc<dyn Backend>,
    pub(super) name: String,
    pub(super) patch: SandboxModificationPatch,
    pub(super) policy: ModificationPolicy,
    /// The Cloud sandbox this builder was taken from; requests address it by id.
    #[cfg(feature = "cloud")]
    cloud_id: Option<String>,
}

/// Fluent builder for one declarative secret spec inside a modification
/// patch, obtained through [`SandboxModificationBuilder::secret`].
///
/// It shares the create-time [`SecretBuilder`](crate::sandbox::SecretBuilder)
/// vocabulary: [`env`](Self::env) names the secret, [`source`](Self::source)
/// or [`value`](Self::value) provides material (mutually exclusive),
/// [`placeholder`](Self::placeholder) and [`allow`](Self::allow)
/// state the guest-visible reference and the host allow-list.
#[derive(Default)]
pub struct SecretPatchBuilder {
    spec: SecretModificationPatch,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SandboxModificationBuilder {
    pub(crate) fn new(backend: Arc<dyn Backend>, name: impl Into<String>) -> Self {
        Self {
            backend,
            name: name.into(),
            patch: SandboxModificationPatch::default(),
            policy: ModificationPolicy::NoRestart,
            #[cfg(feature = "cloud")]
            cloud_id: None,
        }
    }

    /// Bind the builder to the sandbox it was taken from, so a Cloud request
    /// addresses that sandbox by id and never a replacement that reused its name.
    pub(crate) fn bound_to(self, identity: SandboxIdentity) -> Self {
        #[cfg(feature = "cloud")]
        if let SandboxIdentity::Cloud(id) = identity {
            return Self {
                cloud_id: Some(id),
                ..self
            };
        }
        #[cfg(not(feature = "cloud"))]
        let _ = identity;
        self
    }

    /// Set the desired effective vCPU count.
    pub fn cpus(mut self, cpus: u8) -> Self {
        self.patch.cpus = Some(cpus);
        self
    }

    /// Set the desired boot-time maximum possible vCPU count.
    pub fn max_cpus(mut self, max_cpus: u8) -> Self {
        self.patch.max_cpus = Some(max_cpus);
        self
    }

    /// Set the desired effective guest memory. Accepts a bare `u32` in MiB or a typed size.
    pub fn memory(mut self, size: impl Into<Mebibytes>) -> Self {
        self.patch.memory_mib = Some(size.into().as_u32());
        self
    }

    /// Set the boot-time maximum hotpluggable memory. Accepts a bare `u32` in MiB or a typed size.
    pub fn max_memory(mut self, size: impl Into<Mebibytes>) -> Self {
        self.patch.max_memory_mib = Some(size.into().as_u32());
        self
    }

    /// Set the desired total root disk size, accepting a bare `u32` in MiB or a typed size.
    /// Managed and flat roots are grow-only. Tmpfs changes take effect on the next boot;
    /// user-owned disk images cannot be resized through this API.
    pub fn root_disk_size(mut self, size: impl Into<Mebibytes>) -> Self {
        self.patch.root_disk_size_mib = Some(size.into().as_u32());
        self
    }

    /// Set an environment variable for future execs.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.patch.env.push(EnvVar::new(key, value));
        self
    }

    /// Remove an environment variable.
    pub fn remove_env(mut self, key: impl Into<String>) -> Self {
        self.patch.env_remove.push(key.into());
        self
    }

    /// Set a sandbox label.
    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.patch.labels.push((key.into(), value.into()));
        self
    }

    /// Remove a sandbox label.
    pub fn remove_label(mut self, key: impl Into<String>) -> Self {
        self.patch.labels_remove.push(key.into());
        self
    }

    /// Set the working directory for future execs.
    pub fn workdir(mut self, path: impl Into<String>) -> Self {
        self.patch.workdir = Some(path.into());
        self
    }

    /// Add or update a published mapping without changing other host endpoints.
    /// This requires restart or next-start policy on a running sandbox.
    pub fn port(self, host_port: u16, guest_port: u16) -> Self {
        self.port_mapping(microsandbox_types::PublishedPortSpec {
            host_port,
            guest_port,
            ..Default::default()
        })
    }

    /// Add or update a mapping with an explicit host address and protocol.
    pub fn port_mapping(mut self, port: microsandbox_types::PublishedPortSpec) -> Self {
        self.patch.ports.push(port);
        self
    }

    /// Remove one published host endpoint. Missing endpoints are rejected.
    pub fn remove_port(mut self, port: PublishedPortKey) -> Self {
        self.patch.ports_remove.push(port);
        self
    }

    /// Persist the requested changes for the next start.
    pub fn next_start(mut self) -> Self {
        self.policy = ModificationPolicy::NextStart;
        self
    }

    /// Plan the requested changes under restart-backed apply semantics.
    pub fn restart(mut self) -> Self {
        self.policy = ModificationPolicy::Restart;
        self
    }

    /// Declare the desired state of one secret via a closure.
    ///
    /// The spec mirrors the create-time secret vocabulary: name the secret
    /// with `.env(..)`, provide material with `.source(..)` or `.value(..)`,
    /// and optionally set `.placeholder(..)` and `.allow(..)`. The
    /// planner diffs the spec against the existing config to infer the
    /// change: a secret that does not exist yet is added, material on an
    /// existing secret rotates it, and host or placeholder differences
    /// update those aspects.
    ///
    /// ```ignore
    /// sandbox.modify()
    ///     .secret(|s| s
    ///         .env("API_KEY")
    ///         .source(SecretSource::Env { var: "API_KEY".into() })
    ///         .allow("api.example.com"))
    ///     .apply()
    ///     .await?;
    /// ```
    ///
    /// Declaring the same secret again replaces the earlier spec. Removal is
    /// always explicit through [`remove_secret`](Self::remove_secret).
    pub fn secret(mut self, f: impl FnOnce(SecretPatchBuilder) -> SecretPatchBuilder) -> Self {
        let spec = f(SecretPatchBuilder::new()).build();
        self.patch
            .secrets
            .retain(|existing| existing.name != spec.name);
        self.patch.secrets.push(spec);
        self
    }

    /// Remove a secret. Removal is always explicit; omitting a secret from
    /// the patch never removes it.
    pub fn remove_secret(mut self, name: impl Into<String>) -> Self {
        self.patch.secrets_remove.push(name.into());
        self
    }

    /// Replace the accumulated patch wholesale. Language bindings deserialize the canonical [`SandboxModificationPatch`] and inject it here instead of replaying the fluent setters.
    pub fn with_patch(mut self, patch: SandboxModificationPatch) -> Self {
        self.patch = patch;
        self
    }

    /// Compute a modification plan without applying anything.
    ///
    /// On a Cloud sandbox the server plans the change from a request that carries no secret value.
    pub async fn dry_run(self) -> MicrosandboxResult<SandboxModificationPlan> {
        #[cfg(feature = "cloud")]
        if let Some(cloud) = self.backend.as_cloud() {
            return cloud
                .plan_modification(self.cloud_sandbox_id()?, &self.patch, self.policy)
                .await;
        }
        #[cfg(feature = "local")]
        return local::dry_run(self).await;
        #[cfg(not(feature = "local"))]
        Err(local_engine_missing())
    }

    /// Apply supported changes, preserving any earlier live effects on failure.
    ///
    /// Live-capable changes apply to the running VM first (CPU count through
    /// guest CPU hotplug when the target fits inside the active `max_cpus`);
    /// the desired config is persisted only after the live step succeeds. For
    /// stopped sandboxes or `next_start` requests, changes persist for the next
    /// start. When the policy is `restart`, the existing stop/start lifecycle
    /// path makes restart-required changes active. Live secret rotation,
    /// removal, and allowed-host updates go through the runtime control
    /// socket; the durable config records host-side source references for
    /// source-based specs and persists the value for value-based specs (the
    /// same at-rest property as create's `secret_env`).
    ///
    /// Configuring a secret that requires TLS identity on a sandbox with
    /// interception off also turns interception on. That is planned as a
    /// `tls` change and, like every other restart-backed change, needs
    /// `restart` or `next_start` on a running sandbox. Existing secrets that
    /// opt out of TLS identity continue to support live plain-HTTP updates.
    /// Changes to an existing secret's substitution, violation action, TLS
    /// identity requirement, or placeholder passthrough hosts require restart
    /// or next-start policy, even when combined with otherwise live edits.
    ///
    /// # Cloud sandboxes
    ///
    /// On a Cloud sandbox, `modify` changes secrets only; a patch that sets any other field is
    /// refused with [`MicrosandboxError::Unsupported`](crate::MicrosandboxError::Unsupported)
    /// before anything is sent. The server applies the whole request, in order, and answers
    /// once.
    ///
    /// - On a running sandbox, a new value, a change of allowed hosts and a removal are
    ///   delivered to the running sandbox, as on a local one. A new value and new hosts for the
    ///   same secret are saved together. Each change reads `live` once the running sandbox has
    ///   it; otherwise `apply` fails with
    ///   [`ModificationNotConfirmed`](crate::MicrosandboxError::ModificationNotConfirmed).
    ///   Every start uses the saved state, or the sandbox does not start.
    /// - A placeholder change, a secret policy change (substitution, passthrough hosts,
    ///   violation action or TLS identity), and an added secret need a restart. Cloud
    ///   never restarts a sandbox, so these are saved for the next start: use
    ///   [`next_start`](Self::next_start), or change a stopped sandbox. On a running sandbox
    ///   they are refused as `requires restart` under the other policies.
    /// - The next start is the next stop and start. If the sandbox's VM restarts in between,
    ///   it keeps what the running sandbox had. A change reads `next start` only when the
    ///   sandbox is already stopped when the server handles the request, or under
    ///   [`next_start`](Self::next_start). A running or failed sandbox answers each live
    ///   change with `live` or fails with `ModificationNotConfirmed`. A crashed Local sandbox
    ///   counts as stopped, so a change to it reads `next start`.
    /// - A value from an environment-variable source is read once, when `apply` runs.
    /// - On Local and Cloud, a connection that is already open keeps the value and settings
    ///   it started with until it closes: a live rotation, narrowing of allowed hosts or
    ///   removal reaches only new connections, and revokes nothing on an open one.
    /// - The last request the server receives wins: if another caller's newer change arrives
    ///   first, sending an older request again overwrites it.
    ///
    /// # Errors on Cloud
    ///
    /// [`MicrosandboxError::ModificationNotConfirmed`](crate::MicrosandboxError::ModificationNotConfirmed)
    /// means the change did not complete as asked: it may be saved without being in effect on
    /// the running sandbox, or its result is unknown; `cause` says which is known, and whether
    /// sending the same change again retries it. Until the server knows the result, usually
    /// within seconds, starting the sandbox is refused.
    /// Every other error means nothing was changed.
    pub async fn apply(self) -> MicrosandboxResult<SandboxModificationPlan> {
        #[cfg(feature = "cloud")]
        if let Some(cloud) = self.backend.as_cloud() {
            return cloud
                .apply_modification(self.cloud_sandbox_id()?, &self.patch, self.policy)
                .await;
        }
        #[cfg(feature = "local")]
        return local::apply(self).await;
        #[cfg(not(feature = "local"))]
        Err(local_engine_missing())
    }

    /// The id of the Cloud sandbox this builder was taken from.
    #[cfg(feature = "cloud")]
    fn cloud_sandbox_id(&self) -> MicrosandboxResult<&str> {
        self.cloud_id.as_deref().ok_or_else(|| {
            crate::MicrosandboxError::Runtime(format!(
                "sandbox {:?} has no cloud id to modify; take the builder from its Sandbox or SandboxHandle",
                self.name
            ))
        })
    }
}

impl SecretPatchBuilder {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Name the secret (required). This is the environment variable that
    /// exposes the placeholder inside the guest.
    pub fn env(mut self, name: impl Into<String>) -> Self {
        self.spec.name = name.into();
        self
    }

    /// Provide the secret material as a raw value (mutually exclusive with
    /// [`source`](Self::source)), for embedders that hold only a value.
    ///
    /// The value rides in the in-process patch only: it is zeroized on drop,
    /// redacted from `Debug` output, and never enters the plan. Applying a
    /// value persists it into the durable config — the same at-rest property
    /// as create's `secret_env` — until a later source-based rotate migrates
    /// the entry to a reference.
    pub fn value(mut self, value: impl Into<String>) -> Self {
        self.spec.value = zeroize::Zeroizing::new(value.into());
        self
    }

    /// Provide the secret material as a host-side source reference (mutually
    /// exclusive with [`value`](Self::value)). The durable config records
    /// only the reference; the value is resolved host-side when needed.
    pub fn source(mut self, source: SecretSource) -> Self {
        self.spec.source = Some(source);
        self
    }

    /// Set the guest-visible placeholder. New secrets default to
    /// `$MSB_<env_var>`, matching create-time secret configuration.
    /// Placeholder changes cannot reach already-running processes, so they
    /// classify as restart-required on a running sandbox.
    pub fn placeholder(mut self, placeholder: impl Into<String>) -> Self {
        self.spec.placeholder = Some(placeholder.into());
        self
    }

    /// Add an allowed host pattern (`api.example.com`, `*.example.org`, or
    /// `*`). A non-empty list replaces the secret's current allow-list; an
    /// empty list leaves it unchanged.
    pub fn allow(mut self, host: impl Into<String>) -> Self {
        self.spec.allowed_hosts.push(host.into());
        self
    }

    /// Replace the request locations where substitution is enabled.
    pub fn substitution(mut self, value: SecretSubstitution) -> Self {
        self.spec.substitution = Some(value);
        self
    }

    /// Add a host allowed to receive the unchanged placeholder where substitution does not apply.
    pub fn allow_placeholder_for(mut self, host: impl Into<String>) -> Self {
        self.spec.passthrough_hosts.push(host.into());
        self
    }

    /// Deprecated alias for [`allow_placeholder_for`](Self::allow_placeholder_for).
    #[deprecated(note = "use allow_placeholder_for instead")]
    pub fn allow_passthrough_for(self, host: impl Into<String>) -> Self {
        self.allow_placeholder_for(host)
    }

    /// Set the per-secret blocking action.
    pub fn violation_action(mut self, value: SecretViolationAction) -> Self {
        self.spec.violation_action = Some(value);
        self
    }

    /// Set whether substitution requires verified TLS identity.
    pub fn require_tls_identity(mut self, value: bool) -> Self {
        self.spec.require_tls_identity = Some(value);
        self
    }

    pub(super) fn build(self) -> SecretModificationPatch {
        self.spec
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// The error a build without the local engine returns for a non-Cloud sandbox.
#[cfg(not(feature = "local"))]
fn local_engine_missing() -> crate::MicrosandboxError {
    crate::MicrosandboxError::unsupported(
        Operation::SandboxModify,
        UnsupportedReason::RequiresCrateFeature("local"),
    )
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, feature = "cloud"))]
mod tests {
    use std::sync::Mutex;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::MicrosandboxError;
    use crate::error::{Operation, UnsupportedReason};

    const SANDBOX_ID: &str = "6f1c1f7e-3b8a-4c2e-9d55-0a1b2c3d4e5f";

    /// A Cloud server that records each request line and answers with `body`.
    async fn cloud_server(body: &'static str) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let lines = Arc::new(Mutex::new(Vec::new()));
        let log = lines.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut request = vec![0; 64 * 1024];
                let read = stream.read(&mut request).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&request[..read]);
                log.lock()
                    .unwrap()
                    .push(request.lines().next().unwrap_or_default().to_owned());
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        (url, lines)
    }

    fn cloud_sandbox(url: &str) -> crate::sandbox::Sandbox {
        crate::sandbox::Sandbox::from_cloud_state(
            Arc::new(crate::test_support::cloud_backend(url, "test-key").unwrap()),
            crate::backend::SandboxCloudState {
                id: SANDBOX_ID.to_owned(),
                org_id: "test-org".to_owned(),
                created_at: chrono::Utc::now(),
            },
            "agent-1".to_owned(),
            crate::sandbox::SandboxConfig::default(),
        )
    }

    #[tokio::test]
    async fn cloud_non_secret_field_is_unsupported() {
        let (url, lines) = cloud_server("{}").await;
        let sandbox = cloud_sandbox(&url);
        let modify = || {
            sandbox
                .modify()
                .port(8080, 80)
                .secret(|secret| secret.env("API_KEY").value("dummy-value"))
        };

        for error in [
            modify().dry_run().await.unwrap_err(),
            modify().apply().await.unwrap_err(),
        ] {
            assert!(
                matches!(
                    &error,
                    MicrosandboxError::Unsupported {
                        op: Operation::SandboxModify,
                        reason: UnsupportedReason::NotAvailable(message),
                    } if message.starts_with("ports:")
                ),
                "{error:?}"
            );
        }
        assert!(lines.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_cloud_builder_addresses_its_sandbox_by_id() {
        const PLAN: &str = r#"{"sandbox":"agent-1","status":"running","applied":false,"policy":"no_restart","changes":[],"conflicts":[],"warnings":[]}"#;
        let (url, lines) = cloud_server(PLAN).await;

        let plan = cloud_sandbox(&url)
            .modify()
            .remove_secret("OLD_KEY")
            .dry_run()
            .await
            .unwrap();

        assert_eq!(plan.sandbox, "agent-1");
        assert_eq!(
            *lines.lock().unwrap(),
            [format!(
                "POST /v1/sandboxes/{SANDBOX_ID}/modifications/plan HTTP/1.1"
            )]
        );

        let unbound = SandboxModificationBuilder::new(
            Arc::new(crate::test_support::cloud_backend(&url, "test-key").unwrap()),
            "agent-1",
        );
        assert!(matches!(
            unbound.dry_run().await,
            Err(MicrosandboxError::Runtime(_))
        ));
        assert_eq!(lines.lock().unwrap().len(), 1);
    }
}
