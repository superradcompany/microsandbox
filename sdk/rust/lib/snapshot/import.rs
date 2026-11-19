//! Call-time import admission for language bindings that schedule Rust work later.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::context::{Context, configured_context};
use crate::{MicrosandboxError, MicrosandboxResult};

use super::{Checkpoint, LoadOpts, SnapshotImportResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Internal binding transport: own the selected backend and local path meanings before
/// releasing the language thread. This is neither persisted data nor a public import result.
#[doc(hidden)]
pub struct PreparedSnapshotImport {
    backend: Arc<dyn Context>,
    files: Vec<PathBuf>,
    options: LoadOpts,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PreparedSnapshotImport {
    /// Capture the current default backend and the local meaning of input paths.
    ///
    /// Local archive, destination and base paths are anchored now, before deferred
    /// binding work can observe a different working directory. File contents are
    /// read and validated when an import method runs, not by this constructor.
    pub fn new(files: Vec<PathBuf>, options: LoadOpts) -> MicrosandboxResult<Self> {
        Self::with_backend(configured_context(), files, options)
    }

    pub(crate) fn with_backend(
        backend: Arc<dyn Context>,
        files: Vec<PathBuf>,
        options: LoadOpts,
    ) -> MicrosandboxResult<Self> {
        Self::with_caller_directory(backend, files, options, None)
    }

    /// Native transports that dispatch on another thread can supply the directory
    /// observed by the caller. Remote selectors remain provider-owned.
    #[doc(hidden)]
    pub fn with_caller_directory(
        backend: Arc<dyn Context>,
        files: Vec<PathBuf>,
        options: LoadOpts,
        directory: Option<&Path>,
    ) -> MicrosandboxResult<Self> {
        let request = Self {
            backend,
            files,
            options,
        };
        #[cfg(feature = "local")]
        let request = request.anchor_local(directory)?;
        #[cfg(not(feature = "local"))]
        let _ = directory;
        Ok(request)
    }

    #[cfg(feature = "local")]
    fn anchor_local(mut self, directory: Option<&Path>) -> MicrosandboxResult<Self> {
        if self.backend.kind() == crate::context::ContextKind::Local {
            if directory.is_some_and(|path| !path.is_absolute()) {
                return Err(MicrosandboxError::InvalidConfig(
                    "import working directory must be absolute".into(),
                ));
            }
            let anchor = |path: PathBuf| {
                if let Some(directory) = directory
                    && !path.as_os_str().is_empty()
                {
                    std::path::absolute(directory.join(path))
                } else {
                    std::path::absolute(path)
                }
            };
            self.files = self
                .files
                .into_iter()
                .map(anchor)
                .collect::<std::io::Result<_>>()?;
            self.options.dest = self.options.dest.map(anchor).transpose()?;
            self.options.base = self
                .options
                .base
                .map(|value| {
                    crate::context::local::snapshot::anchor_archive_selector_in(value, directory)
                })
                .transpose()?;
        }
        Ok(self)
    }

    /// Import the prepared inputs into the named group on the retained backend.
    /// Returns the imported checkpoints and the resulting group/head outcome.
    pub async fn group(self, name: String) -> MicrosandboxResult<SnapshotImportResult> {
        #[cfg(feature = "local")]
        if let Some(local) = self.backend.as_local() {
            return crate::context::local::snapshot::load_group_admitted(
                local,
                self.backend.clone(),
                &name,
                &self.files,
                self.options,
            )
            .await;
        }
        self.backend
            .snapshot_ops()
            .load_group(self.backend.clone(), &name, &self.files, self.options)
            .await
    }

    /// Import the prepared inputs and return their retained checkpoint handles.
    /// Uses the backend and path meanings fixed when this request was constructed.
    pub async fn checkpoints(self) -> MicrosandboxResult<Vec<Checkpoint>> {
        #[cfg(feature = "local")]
        if let Some(local) = self.backend.as_local() {
            return crate::context::local::snapshot::load_many_admitted(
                local,
                self.backend.clone(),
                &self.files,
                self.options,
            )
            .await;
        }
        self.backend
            .snapshot_ops()
            .load_many(self.backend.clone(), &self.files, self.options)
            .await
    }

    /// Import the prepared inputs and return the first resulting checkpoint.
    /// Returns an error if the backend reports no checkpoints; this is not an
    /// exact-member selector and does not restrict a batch to one imported member.
    pub async fn checkpoint(self) -> MicrosandboxResult<Checkpoint> {
        self.checkpoints().await?.into_iter().next().ok_or_else(|| {
            MicrosandboxError::Runtime("snapshot import returned no checkpoint".into())
        })
    }

    /// Preserve the old single-archive dispatch for backends that implement `load`
    /// without implementing the optional batch interface. An explicit base uses batch.
    pub async fn legacy_checkpoint(self) -> MicrosandboxResult<Checkpoint> {
        if self.options.base.is_some() {
            return self.checkpoint().await;
        }
        let path = self.files.first().ok_or_else(|| {
            MicrosandboxError::InvalidConfig("snapshot import requires an archive".into())
        })?;
        self.backend
            .snapshot_ops()
            .load(self.backend.clone(), path, self.options.dest.as_deref())
            .await
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, feature = "local"))]
#[path = "import_tests.rs"]
mod tests;
