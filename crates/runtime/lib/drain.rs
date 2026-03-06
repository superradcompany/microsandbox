//! Drain state machine for supervisor shutdown orchestration.
//!
//! A drain is a deliberate shutdown sequence triggered by idle timeout,
//! max duration, external signal, or explicit drain request. Once triggered,
//! it cannot be cancelled. The drain progresses through phases based on the
//! supervisor's `ShutdownMode`.

use crate::policy::ShutdownMode;
use crate::termination::TerminationReason;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Current phase of the drain sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrainPhase {
    /// Waiting for children to exit voluntarily (Graceful mode only).
    WaitingVoluntary,

    /// SIGTERM has been sent, waiting for children to exit.
    SentSigterm,

    /// SIGKILL has been sent, waiting for children to exit.
    SentSigkill,

    /// All children have exited.
    Complete,
}

/// Tracks the state of a drain operation.
pub struct DrainState {
    /// The reason drain was triggered.
    reason: TerminationReason,

    /// Current phase of the drain.
    phase: DrainPhase,

    /// Signals sent during this drain (e.g., "SIGTERM", "SIGKILL").
    signals_sent: Vec<&'static str>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DrainState {
    /// Create a new drain state with the given reason.
    pub fn new(reason: TerminationReason) -> Self {
        Self {
            reason,
            phase: DrainPhase::WaitingVoluntary,
            signals_sent: Vec::new(),
        }
    }

    /// Returns the reason drain was triggered.
    pub fn reason(&self) -> &TerminationReason {
        &self.reason
    }

    /// Returns the list of signals sent during this drain.
    pub fn signals_sent(&self) -> &[&str] {
        &self.signals_sent
    }

    /// Advance to the next phase.
    pub fn advance(&mut self, phase: DrainPhase) {
        self.phase = phase;
    }

    /// Record that a signal was sent.
    pub fn record_signal(&mut self, signal: &'static str) {
        self.signals_sent.push(signal);
    }

    /// Determine the initial drain phase based on the shutdown mode.
    pub fn initial_phase(mode: &ShutdownMode) -> DrainPhase {
        match mode {
            ShutdownMode::Graceful => DrainPhase::WaitingVoluntary,
            ShutdownMode::Terminate => DrainPhase::SentSigterm,
            ShutdownMode::Kill => DrainPhase::SentSigkill,
        }
    }
}
