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
//! installs one; if never called, the first access lazy-initialises to
//! [`LocalBackend::lazy`]. [`with_backend`] scopes an override to one async
//! future (and any tasks it spawns) via `tokio::task_local!`.
//!
//! See `planning/microsandbox/design/api/local-cloud-backend.md` for the
//! full trait-surface spec, and `planning/microsandbox/design/api/ambient-backend.md`
//! for the resolution ladder + process-level config story.

mod cloud;
mod local;
mod profile;
pub(crate) mod sandbox;
pub(crate) mod volume;

pub use cloud::{CloudBackend, CloudBackendBuilder};
pub use local::{LocalBackend, LocalBackendBuilder};
pub use microsandbox_types::{
    CloudCreateSandboxRequest, CloudCreateSandboxResponse, CloudErrorBody, CloudErrorDetails,
    CloudMessageResponse, CloudPaginated, CloudSandboxStatus,
};
pub use profile::{Profile, ProfileBackend, SdkConfig, load_sdk_config, resolve_default_backend};
pub use sandbox::{
    SandboxBackend, SandboxCloudState, SandboxHandleCloudState, SandboxHandleInner,
    SandboxHandleLocalState, SandboxInner, SandboxList, SandboxLocalState,
};
pub use volume::{
    VolumeBackend, VolumeCloudState, VolumeHandleCloudState, VolumeHandleInner,
    VolumeHandleLocalState, VolumeInner, VolumeLocalState,
};

use std::sync::{Arc, OnceLock, RwLock};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Which backend variant a [`Backend`] implementation represents. Returned by
/// [`Backend::kind`] for runtime introspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    /// Local libkrun + agentd backend. Spawns microVMs on the calling host.
    Local,
    /// Remote backend talking to an msb-cloud control plane over HTTP.
    Cloud,
}

/// Top-level routing trait for SDK dispatch. Implementations route to
/// resource-specific sub-traits (sandboxes, volumes, snapshots) via accessor
/// methods.
///
/// Object-safe — handles hold an `Arc<dyn Backend>`. Sub-trait accessors stay
/// off this trait until each sub-trait's surface is finalised, which lets the
/// scaffolding land without committing to method signatures that will change.
pub trait Backend: Send + Sync + 'static {
    /// Return the kind of backend this is (`Local` or `Cloud`).
    fn kind(&self) -> BackendKind;

    /// Return the sandbox lifecycle backend.
    fn sandboxes(&self) -> &dyn SandboxBackend;

    /// Return the volume lifecycle backend.
    fn volumes(&self) -> &dyn VolumeBackend;

    /// Downcast to a concrete `&LocalBackend` when this backend is local.
    ///
    /// Used by helpers that need access to local-only state (DB pool, config
    /// paths) without keeping a separate `Arc<LocalBackend>` alongside the
    /// `Arc<dyn Backend>`. Returns `None` for cloud backends.
    fn as_local(&self) -> Option<&LocalBackend> {
        None
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Ambient default
//--------------------------------------------------------------------------------------------------

/// Process-wide default backend. Lazy-initialised to `LocalBackend::lazy()`
/// on first access if `set_default_backend` has not been called.
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
/// ([`resolve_default_backend`]). Falls back to `LocalBackend::lazy` if the
/// resolver itself errors (e.g. malformed config file) — error gets logged
/// rather than panicking, so `default_backend()` never fails.
fn default_cell() -> &'static RwLock<Arc<dyn Backend>> {
    DEFAULT.get_or_init(|| {
        let resolved = profile::resolve_default_backend().unwrap_or_else(|e| {
            tracing::warn!(
                error = %e,
                "default backend resolution failed; falling back to LocalBackend"
            );
            Arc::new(LocalBackend::lazy())
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
