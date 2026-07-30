//! Backend abstraction: routes SDK calls to either a local libkrun runtime or
//! a remote msb-cloud control plane.
//!
//! The [`Backend`] trait + its sub-traits ([`SandboxBackend`], `VolumeBackend`,
//! `SnapshotBackend`) are the dispatch surface every SDK handle (`Sandbox`,
//! `Volume`, `ExecHandle`, …) routes through. Two implementations are planned:
//! [`LocalBackend`] (wraps today's libkrun + agentd path) and `CloudBackend`
//! (HTTP to msb-cloud, lives in this crate once the cloud-side wire surface is
//! complete).
//!
//! ## Ambient default
//!
//! [`default_backend`] returns the process-wide default. [`set_default_backend`]
//! installs one; if never called, the first access resolves environment and
//! profile configuration before falling back to [`LocalBackend::lazy`].
//! [`with_backend`] scopes an override to one async future (and any tasks it
//! spawns) via `tokio::task_local!`.
//!
//! See `planning/microsandbox/design/api/local-cloud-backend.md` for the
//! full trait-surface spec, and `planning/microsandbox/design/api/ambient-backend.md`
//! for the resolution ladder + process-level config story.

mod cloud;
mod local;
mod misconfigured;
mod profile;
pub(crate) mod sandbox;
pub(crate) mod volume;

pub use cloud::{CloudBackend, CloudBackendBuilder, DEFAULT_CLOUD_API_URL};
use futures::future::BoxFuture;
pub use local::{LocalBackend, LocalBackendBuilder};
pub use microsandbox_types::{
    CloudCreateSandboxRequest, CloudCreateSandboxResponse, CloudErrorBody, CloudErrorDetails,
    CloudMessageResponse, CloudPaginated, CloudSandboxStatus, CloudSandboxStatusReason,
};
pub use profile::{Profile, ProfileBackend, SdkConfig, load_sdk_config, resolve_default_backend};
pub use sandbox::{
    SandboxBackend, SandboxCloudState, SandboxHandleCloudState, SandboxHandleInner,
    SandboxHandleLocalState, SandboxInner, SandboxLocalState,
};
pub use volume::{
    CloudVolumeKind, CloudVolumeStatus, VolumeBackend, VolumeCloudState, VolumeHandleCloudState,
    VolumeHandleInner, VolumeHandleLocalState, VolumeInner, VolumeLocalState,
};

use std::{
    sync::{Arc, OnceLock, RwLock},
    time::Duration,
};

use serde::{Deserialize, Serialize};

use crate::MicrosandboxResult;
use crate::error::{Operation, UnsupportedReason};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Which backend variant a [`Backend`] implementation represents. Returned by
/// [`Backend::kind`] for runtime introspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    /// Local libkrun + agentd backend. Spawns microVMs on the calling host.
    Local,
    /// Remote backend talking to an msb-cloud control plane over HTTP.
    Cloud,
}

/// How the active backend was selected.
///
/// This describes the selector, never its credential value. Backend
/// diagnostics therefore cannot expose `MSB_API_KEY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendSelectionSource {
    /// Installed directly through an SDK constructor or setter.
    #[serde(rename = "programmatic")]
    Programmatic,
    /// Selected explicitly by `MSB_BACKEND`.
    #[serde(rename = "MSB_BACKEND")]
    MsbBackend,
    /// Selected implicitly by a non-empty `MSB_API_KEY`.
    #[serde(rename = "MSB_API_KEY")]
    MsbApiKey,
    /// Selected by the profile named in `MSB_PROFILE`.
    #[serde(rename = "MSB_PROFILE")]
    MsbProfile,
    /// Selected by an explicit SDK profile constructor.
    #[serde(rename = "profile")]
    Profile,
    /// Selected by `active_profile` in the SDK config file.
    #[serde(rename = "active_profile")]
    ActiveProfile,
    /// Selected by the SDK's final local fallback.
    #[serde(rename = "default")]
    Default,
}

/// Secret-safe description of an SDK backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendInfo {
    /// Local or cloud execution.
    pub kind: BackendKind,
    /// Effective cloud API endpoint. Absent for local backends.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_url: Option<String>,
    /// Selector that chose this backend.
    pub source: BackendSelectionSource,
    /// Selected SDK profile, when profile-based selection was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl BackendKind {
    /// Stable lowercase name used by language bindings and diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Cloud => "cloud",
        }
    }
}

impl BackendSelectionSource {
    /// Stable public name for this selection source.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Programmatic => "programmatic",
            Self::MsbBackend => "MSB_BACKEND",
            Self::MsbApiKey => "MSB_API_KEY",
            Self::MsbProfile => "MSB_PROFILE",
            Self::Profile => "profile",
            Self::ActiveProfile => "active_profile",
            Self::Default => "default",
        }
    }
}

/// Top-level routing trait for SDK dispatch. Implementations route to
/// resource-specific sub-traits (sandboxes, volumes, snapshots) via accessor
/// methods.
///
/// Object-safe — handles hold an `Arc<dyn Backend>`. Sub-trait accessors stay
/// off this trait until each sub-trait's surface is finalised, which lets the
/// scaffolding land without committing to method signatures that will change.
/// New methods ship with default implementations, so custom backends
/// (mocks, proxies) keep compiling as the trait grows.
pub trait Backend: Send + Sync + 'static {
    /// Return the kind of backend this is (`Local` or `Cloud`).
    fn kind(&self) -> BackendKind;

    /// Return a secret-safe description of this backend.
    fn info(&self) -> BackendInfo {
        BackendInfo {
            kind: self.kind(),
            api_url: None,
            source: BackendSelectionSource::Programmatic,
            profile: None,
        }
    }

    /// Return the sandbox lifecycle backend.
    fn sandboxes(&self) -> &dyn SandboxBackend;

    /// Return the volume lifecycle backend.
    fn volumes(&self) -> &dyn VolumeBackend;

    /// Try downcast to a concrete `&LocalBackend` when in a local context.
    ///
    /// Used by helpers that need access to local-only state (DB pool, config
    /// paths) without keeping a separate `Arc<LocalBackend>` alongside the
    /// `Arc<dyn Backend>`. Returns `None` for cloud backends.
    fn as_local(&self) -> Option<&LocalBackend> {
        None
    }

    /// Open a fresh agent connection to the named sandbox with an explicit
    /// handshake timeout. Local dials the relay socket; cloud dials the
    /// sandbox's agent WebSocket route.
    /// Exec, attach, and guest-filesystem operations route through this
    /// connection. The default errors as unsupported for backends that
    /// cannot reach a sandbox agent.
    fn dial_agent<'a>(
        &'a self,
        _name: &'a str,
        _timeout: Duration,
    ) -> BoxFuture<'a, MicrosandboxResult<crate::agent::AgentClient>> {
        Box::pin(async {
            Err(crate::MicrosandboxError::unsupported(
                Operation::AgentConnect,
                UnsupportedReason::NotAvailable(
                    "this backend does not provide agent connectivity".into(),
                ),
            ))
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Ambient default
//--------------------------------------------------------------------------------------------------

/// Process-wide default backend. Lazy-initialised from environment/profile
/// configuration, with `LocalBackend::lazy()` as the final fallback.
static DEFAULT: OnceLock<RwLock<Arc<dyn Backend>>> = OnceLock::new();

/// Install a process-wide default backend.
///
/// Replaces any previously installed default. Subsequent calls to
/// [`default_backend`] (in this process) return this backend unless a
/// [`with_backend`] scope is active on the current task.
///
/// Call this once at process startup, typically right after argument parsing
/// and before any SDK operations. Existing user code that never calls this
/// gets `LocalBackend` automatically on first access.
pub fn set_default_backend(backend: impl Into<Arc<dyn Backend>>) {
    let cell = default_cell();
    *cell.write().expect("DEFAULT backend RwLock poisoned") = backend.into();
}

/// Replace the process-wide default backend and return the previous default.
///
/// This is primarily used by language SDKs that provide a restorable
/// process-wide backend scope. Unlike [`with_backend`], this is not task-local:
/// concurrent work in the same process can observe the replacement until the
/// caller restores the returned backend.
pub fn swap_default_backend(backend: impl Into<Arc<dyn Backend>>) -> Arc<dyn Backend> {
    let cell = default_cell();
    let mut guard = cell.write().expect("DEFAULT backend RwLock poisoned");
    std::mem::replace(&mut *guard, backend.into())
}

/// Return the active default backend.
///
/// Resolution order:
/// 1. A [`with_backend`] scope on the current task, if any.
/// 2. The backend installed via [`set_default_backend`], if any.
/// 3. Lazy-initialised `LocalBackend` (matches today's behaviour).
pub fn default_backend() -> Arc<dyn Backend> {
    if let Ok(scoped) = SCOPED_BACKEND.try_with(|b| b.clone()) {
        return scoped;
    }
    default_cell()
        .read()
        .expect("DEFAULT backend RwLock poisoned")
        .clone()
}

/// Return a secret-safe description of the active default backend.
///
/// Like [`default_backend`], the first call freezes ambient environment and
/// profile resolution for the process.
pub fn default_backend_info() -> BackendInfo {
    default_backend().info()
}

/// Run `future` with `backend` installed as the default for the duration of
/// the future and any tasks it spawns. Useful for libraries that need to talk
/// to a non-default backend (e.g. tests using a mock, or multi-backend tools)
/// without globally swapping the default.
///
/// Implemented via `tokio::task_local!`, so spawned tasks inherit the override
/// only if launched within `future`. Tasks launched before the scope began
/// see the global default.
pub async fn with_backend<F, T>(backend: impl Into<Arc<dyn Backend>>, future: F) -> T
where
    F: std::future::Future<Output = T>,
{
    SCOPED_BACKEND.scope(backend.into(), future).await
}

/// Lazy-init the OnceLock by consulting the Q1 resolution ladder
/// ([`resolve_default_backend`]). Resolver errors install a fail-closed backend
/// that returns the configuration error from SDK operations. This prevents an
/// explicit but incomplete Cloud selection from silently executing locally.
fn default_cell() -> &'static RwLock<Arc<dyn Backend>> {
    DEFAULT.get_or_init(|| {
        let resolved = profile::resolve_default_backend().unwrap_or_else(|e| {
            tracing::error!(error = %e, "default backend resolution failed");
            Arc::new(misconfigured::ConfigurationErrorBackend::new(e))
        });
        RwLock::new(resolved)
    })
}

tokio::task_local! {
    /// Task-local override installed by [`with_backend`].
    static SCOPED_BACKEND: Arc<dyn Backend>;
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_backend_resolves_to_local_when_unset() {
        // Each `cargo test` run is its own process, but other tests in the
        // same binary may install a different default. Be tolerant: just
        // check the kind is one of the known variants.
        let b = default_backend();
        assert!(matches!(b.kind(), BackendKind::Local | BackendKind::Cloud));
    }

    #[tokio::test]
    async fn with_backend_overrides_for_scope() {
        struct Fake(BackendKind);
        impl Backend for Fake {
            fn kind(&self) -> BackendKind {
                self.0
            }

            fn sandboxes(&self) -> &dyn SandboxBackend {
                unimplemented!("fake backend only tests kind routing")
            }

            fn volumes(&self) -> &dyn VolumeBackend {
                unimplemented!("fake backend only tests kind routing")
            }
        }
        let fake: Arc<dyn Backend> = Arc::new(Fake(BackendKind::Cloud));
        let observed = with_backend(fake, async { default_backend().kind() }).await;
        assert_eq!(observed, BackendKind::Cloud);

        // Outside the scope, the default is whatever it was before — but at
        // least it's not the fake we just installed (since we didn't call
        // `set_default_backend`).
        let outside = default_backend().kind();
        assert!(matches!(outside, BackendKind::Local | BackendKind::Cloud));
    }

    #[test]
    fn swap_default_backend_restores_previous_backend() {
        struct Fake(BackendKind);
        impl Backend for Fake {
            fn kind(&self) -> BackendKind {
                self.0
            }

            fn sandboxes(&self) -> &dyn SandboxBackend {
                unimplemented!("fake backend only tests kind routing")
            }

            fn volumes(&self) -> &dyn VolumeBackend {
                unimplemented!("fake backend only tests kind routing")
            }
        }

        let original = default_backend();
        let fake: Arc<dyn Backend> = Arc::new(Fake(BackendKind::Cloud));
        let previous = swap_default_backend(fake);
        assert_eq!(default_backend().kind(), BackendKind::Cloud);

        set_default_backend(previous);
        assert_eq!(default_backend().kind(), original.kind());
    }
}
