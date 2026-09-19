//! Operation timing for startup stages and cloud agent connections.
//! Enable with `RUST_LOG=info,microsandbox::profiling=trace`.

#[cfg(feature = "local")]
use std::future::Future;
use std::time::Instant;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Log target for opt-in profiling events.
pub(crate) const TARGET: &str = "microsandbox::profiling";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "local")]
struct StageTiming<'a> {
    sandbox_name: &'a str,
    stage: &'static str,
    started: Instant,
    outcome: &'static str,
}

/// Emits one terminal event when a polled connection attempt finishes or is dropped.
#[cfg(feature = "cloud")]
pub(crate) struct ConnectionTiming<'a> {
    name: &'a str,
    id: Option<String>,
    started: Instant,
    stage: &'static str,
    outcome: &'static str,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "cloud")]
impl<'a> ConnectionTiming<'a> {
    pub(crate) fn new(name: &'a str) -> Self {
        Self {
            name,
            id: None,
            started: Instant::now(),
            stage: "identity",
            outcome: "cancelled",
        }
    }

    pub(crate) fn identity(&mut self, id: &str) {
        self.id = Some(id.to_owned());
    }

    pub(crate) fn stage(&mut self, stage: &'static str) {
        self.stage = stage;
    }

    pub(crate) fn finish(&mut self, outcome: &'static str) {
        self.outcome = outcome;
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "local")]
impl Drop for StageTiming<'_> {
    fn drop(&mut self) {
        tracing::trace!(target: TARGET,
            sandbox_name = self.sandbox_name,
            stage = self.stage,
            elapsed_seconds = self.started.elapsed().as_secs_f64(),
            outcome = self.outcome,
            "sandbox startup stage finished"
        );
    }
}

#[cfg(feature = "cloud")]
impl Drop for ConnectionTiming<'_> {
    fn drop(&mut self) {
        tracing::trace!(target: TARGET,
            sandbox_name = self.name,
            sandbox_id = self.id.as_deref().unwrap_or(""),
            elapsed_seconds = self.started.elapsed().as_secs_f64(),
            stage = self.stage,
            outcome = self.outcome,
            "cloud agent connection finished"
        );
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Measure a fallible startup stage, including errors and future cancellation.
#[cfg(feature = "local")]
pub(crate) async fn measure<T, E>(
    sandbox_name: &str,
    stage: &'static str,
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    let mut timing = StageTiming {
        sandbox_name,
        stage,
        started: Instant::now(),
        outcome: "cancelled",
    };
    let result = future.await;
    timing.outcome = if result.is_ok() { "success" } else { "error" };
    result
}
