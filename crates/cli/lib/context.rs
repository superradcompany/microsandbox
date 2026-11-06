//! CLI completion functions
use clap_complete::CompletionCandidate;
use clap_complete::engine::ValueCompleter;
use microsandbox::sandbox::SandboxHandle;
use microsandbox::{Image, ImageHandle};

use std::ffi::OsStr;
use std::future::Future;
use std::sync::OnceLock;

static CONTEXT: OnceLock<AppContext> = OnceLock::new();

fn context() -> &'static AppContext {
    CONTEXT.get_or_init(AppContext::new)
}
struct AppContext {}

impl AppContext {
    fn new() -> Self {
        Self {}
    }

    async fn _containers(&self) -> anyhow::Result<Vec<SandboxHandle>> {
        Ok(Vec::new())
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
