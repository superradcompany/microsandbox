//! CLI completion functions
use clap_complete::CompletionCandidate;
use clap_complete::engine::ValueCompleter;
use microsandbox::sandbox::{SandboxHandle, SandboxStatus};
use microsandbox::{Image, ImageHandle};

use std::ffi::OsStr;
use std::future::Future;
use std::sync::OnceLock;

use crate::commands::common;

static CONTEXT: OnceLock<AppContext> = OnceLock::new();

fn context() -> &'static AppContext {
    CONTEXT.get_or_init(AppContext::new)
}
struct AppContext {}

impl AppContext {
    fn new() -> Self {
        Self {}
    }

    async fn sandboxes(
        &self,
        status_filters: &'static [SandboxStatus],
    ) -> anyhow::Result<Vec<SandboxHandle>> {
        let sandboxes = common::list_sandboxes(&[]).await?;

        let filtered: Vec<_> = sandboxes
            .into_iter()
            .filter(|s| {
                // is_empty check here acts as an 'any' status
                status_filters.is_empty() || status_filters.contains(&s.status_snapshot())
            })
            .collect();
        Ok(filtered)
    }

    async fn images(&self) -> anyhow::Result<Vec<ImageHandle>> {
        let backend = crate::commands::common::resolve_local_backend()?;
        let local = crate::commands::common::local_backend_ref(&backend)?;
        let images = Image::list_local(local).await?;
        Ok(images)
    }
}

fn block_on_context_completion<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build completion runtime")
        .block_on(future)
}

/// ValueCompleter to list available images
pub struct ImageCompleter;

impl ValueCompleter for ImageCompleter {
    fn complete(&self, current: &OsStr) -> Vec<CompletionCandidate> {
        let current = current.to_string_lossy();
        let images = block_on_context_completion(context().images());

        match images {
            Ok(images) => images
                .iter()
                .filter(|i| i.reference().starts_with(current.as_ref()))
                .map(|i| CompletionCandidate::new(i.reference()))
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

/// ValueCompleter to list stopped and running sandboxes
pub struct SandboxCompleter {
    /// filter which sandbox statuses should be returned
    pub status_filters: &'static [SandboxStatus],
}

impl ValueCompleter for SandboxCompleter {
    fn complete(&self, current: &OsStr) -> Vec<CompletionCandidate> {
        let current = current.to_string_lossy();
        let sandboxes = block_on_context_completion(context().sandboxes(self.status_filters));

        match sandboxes {
            Ok(sandboxes) => sandboxes
                .iter()
                .filter(|i| i.name().starts_with(current.as_ref()))
                .map(|i| CompletionCandidate::new(i.name()))
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}
