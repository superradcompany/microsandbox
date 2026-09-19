//! Inert configuration, separate from connection and request execution.

use std::time::Duration;

use microsandbox_protocol::codec::MAX_FRAME_SIZE;
use tokio::time::Instant;

use crate::{ClientError, ClientResult, ErrorKind};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Hard resource bounds for one framed connection.
#[derive(Debug, Clone)]
pub struct ClientLimits {
    /// Maximum length after the four-byte prefix, including ID and flags.
    pub max_frame_size: u32,
    /// Active and draining IDs both consume this capacity.
    pub max_in_flight: usize,
    /// Writer item capacity, in addition to the shared byte budget.
    pub queued_writes: usize,
    /// Per-subscription response capacity, in addition to the byte budget.
    pub queued_responses: usize,
    /// Combined queued/in-progress read and write bytes.
    pub buffered_bytes: u32,
    /// Completion deadline once the first frame byte arrives; idle is separate.
    pub incomplete_frame_timeout: Option<Duration>,
    /// Default local request wait; no remote cancellation is implied.
    pub request_timeout: Option<Duration>,
}

/// Connection configuration. Builders have no I/O or background side effects.
#[derive(Debug, Clone)]
pub struct ConnectOptions {
    /// Total time allowed for dial and protocol establishment.
    pub setup_timeout: Duration,
    /// Requested local resource limits; a protocol may reduce these.
    pub limits: ClientLimits,
}

/// Options for one request or stream-opening attempt.
#[derive(Debug, Clone, Default)]
pub struct RequestOptions {
    /// Overrides the connection's default local wait when set.
    pub request_timeout: Option<Duration>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ConnectOptions {
    /// Set the deadline for the complete setup attempt.
    pub fn setup_timeout(mut self, timeout: Duration) -> Self {
        self.setup_timeout = timeout;
        self
    }

    /// Configure resource bounds before connecting.
    pub fn limits(mut self, configure: impl FnOnce(ClientLimits) -> ClientLimits) -> Self {
        self.limits = configure(self.limits);
        self
    }
}

impl RequestOptions {
    /// Stop waiting after this duration; the peer may still execute the work.
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = Some(timeout);
        self
    }
}

impl ClientLimits {
    /// Reject limits that cannot buffer even one maximum-sized frame.
    pub fn validate(&self) -> ClientResult<()> {
        for timeout in [self.incomplete_frame_timeout, self.request_timeout]
            .into_iter()
            .flatten()
        {
            checked_deadline(timeout)?;
        }
        if self.max_frame_size < 5
            || self.max_frame_size > MAX_FRAME_SIZE
            || self.max_in_flight == 0
            || self.queued_writes == 0
            || self.queued_responses == 0
            || self.queued_writes > tokio::sync::Semaphore::MAX_PERMITS
            || self.queued_responses > tokio::sync::Semaphore::MAX_PERMITS
            || u64::from(self.buffered_bytes) > tokio::sync::Semaphore::MAX_PERMITS as u64
            || self.buffered_bytes < self.max_frame_size + 4
        {
            return Err(ClientError::new(ErrorKind::InvalidOptions));
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            setup_timeout: Duration::from_secs(10),
            limits: ClientLimits::default(),
        }
    }
}

impl Default for ClientLimits {
    fn default() -> Self {
        Self {
            max_frame_size: MAX_FRAME_SIZE,
            max_in_flight: 1024,
            queued_writes: 256,
            queued_responses: 1024,
            buffered_bytes: 8 * 1024 * 1024,
            incomplete_frame_timeout: None,
            request_timeout: None,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn checked_deadline(timeout: Duration) -> ClientResult<Instant> {
    Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| ClientError::new(ErrorKind::InvalidOptions))
}
