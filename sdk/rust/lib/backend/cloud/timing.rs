//! Connection timing that survives early errors, timeout and future cancellation.

use std::time::Instant;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Emits one terminal event when a polled connection attempt finishes or is dropped.
pub(super) struct ConnectionTiming<'a> {
    name: &'a str,
    id: Option<String>,
    started: Instant,
    stage: &'static str,
    outcome: &'static str,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<'a> ConnectionTiming<'a> {
    pub(super) fn new(name: &'a str) -> Self {
        Self {
            name,
            id: None,
            started: Instant::now(),
            stage: "identity",
            outcome: "cancelled",
        }
    }

    pub(super) fn identity(&mut self, id: &str) {
        self.id = Some(id.to_owned());
    }

    pub(super) fn stage(&mut self, stage: &'static str) {
        self.stage = stage;
    }

    pub(super) fn finish(&mut self, outcome: &'static str) {
        self.outcome = outcome;
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for ConnectionTiming<'_> {
    fn drop(&mut self) {
        tracing::debug!(
            sandbox_name = self.name,
            sandbox_id = self.id.as_deref().unwrap_or(""),
            elapsed_seconds = self.started.elapsed().as_secs_f64(),
            stage = self.stage,
            outcome = self.outcome,
            "cloud agent connection finished"
        );
    }
}
