//! Sandbox modification planning.

use std::sync::Arc;

use microsandbox_types::{EnvVar, SecretSubstitution, SecretViolationAction};

use crate::MicrosandboxResult;
use crate::backend::{Backend, SandboxIdentity};
use crate::size::Mebibytes;

pub use microsandbox_types::modify::{
    ChangeKind, ConfigPlannedChange, ModificationConflict, ModificationDisposition,
    ModificationPolicy, ModificationWarning, PlannedChange, ResourceConvergenceState, ResourceKind,
    ResourceResizeStatus, SandboxModificationPatch, SandboxModificationPlan, SecretChangeKind,
    SecretModificationPatch, SecretPlannedChange, SecretSource,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fluent builder returned by [`Sandbox::modify`](super::Sandbox::modify).
///
/// The builder is intentionally plan-first. Phase 3 exposes the canonical SDK
/// patch and dry-run contract; later phases can wire the same patch type into
/// persistence, live runtime mutation, and restart-backed apply.
#[derive(Clone)]
pub struct SandboxModificationBuilder {
    backend: Arc<dyn Backend>,
    name: String,
    identity: SandboxIdentity,
    patch: SandboxModificationPatch,
    policy: ModificationPolicy,
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
    pub(crate) fn new(
        backend: Arc<dyn Backend>,
        name: impl Into<String>,
        identity: SandboxIdentity,
    ) -> Self {
        Self {
            backend,
            name: name.into(),
            identity,
            patch: SandboxModificationPatch::default(),
            policy: ModificationPolicy::NoRestart,
        }
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
    pub async fn dry_run(self) -> MicrosandboxResult<SandboxModificationPlan> {
        self.backend
            .sandboxes()
            .plan_modification_identified(
                self.backend.clone(),
                &self.name,
                self.identity,
                self.patch,
                self.policy,
            )
            .await
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
    /// On the cloud backend, a request that gets no response is retried with
    /// the same idempotency key. If every retry fails the error carries no
    /// operation id, and applying the same change again is safe.
    pub async fn apply(self) -> MicrosandboxResult<SandboxModificationPlan> {
        self.backend
            .sandboxes()
            .apply_modification_identified(
                self.backend.clone(),
                &self.name,
                self.identity,
                self.patch,
                self.policy,
            )
            .await
    }
}

impl SecretPatchBuilder {
    fn new() -> Self {
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

    fn build(self) -> SecretModificationPatch {
        self.spec
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, feature = "local"))]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::size::SizeExt;

    #[tokio::test]
    async fn size_setters_accept_bare_mib_and_typed_sizes() {
        let temp = tempdir().unwrap();
        let backend: Arc<dyn Backend> = Arc::new(
            crate::test_support::local_backend_builder(temp.path())
                .build()
                .await
                .unwrap(),
        );
        let plain =
            SandboxModificationBuilder::new(backend.clone(), "size-api", SandboxIdentity::Local(1))
                .memory(1024)
                .max_memory(8192)
                .root_disk_size(4096);
        let typed = SandboxModificationBuilder::new(backend, "size-api", SandboxIdentity::Local(1))
            .memory(1.gib())
            .max_memory(8.gib())
            .root_disk_size(4.gib());
        for patch in [&plain.patch, &typed.patch] {
            assert_eq!(patch.memory_mib, Some(1024));
            assert_eq!(patch.max_memory_mib, Some(8192));
            assert_eq!(patch.root_disk_size_mib, Some(4096));
        }
    }

    #[cfg(feature = "net")]
    #[test]
    #[allow(deprecated)] // Both spellings must produce the existing modification contract.
    fn secret_patch_builder_builds_declarative_specs() {
        let spec = SecretPatchBuilder::new()
            .env("API_KEY")
            .source(SecretSource::Env {
                var: "HOST_API_KEY".to_string(),
            })
            .placeholder("$REF")
            .allow("api.example.com")
            .allow("*.example.org")
            .allow_placeholder_for("api.anthropic.com")
            .allow_passthrough_for("*.anthropic.com")
            .build();

        assert_eq!(spec.name, "API_KEY");
        assert_eq!(
            spec.source,
            Some(SecretSource::Env {
                var: "HOST_API_KEY".to_string()
            })
        );
        assert!(spec.value.is_empty());
        assert_eq!(spec.placeholder.as_deref(), Some("$REF"));
        assert_eq!(spec.allowed_hosts, vec!["api.example.com", "*.example.org"]);
        assert_eq!(
            spec.passthrough_hosts,
            vec!["api.anthropic.com", "*.anthropic.com"]
        );
        let wire = serde_json::to_value(&spec).unwrap();
        assert_eq!(
            wire["passthrough_hosts"],
            serde_json::json!(["api.anthropic.com", "*.anthropic.com"])
        );
        assert!(wire.get("allow_placeholder_for").is_none());

        let spec = SecretPatchBuilder::new()
            .env("API_KEY")
            .value("caller-held")
            .build();
        assert_eq!(spec.value.as_str(), "caller-held");
        assert_eq!(spec.source, None);
    }
}
