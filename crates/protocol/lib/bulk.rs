//! Generation-7 raw bulk records, control payloads, and flow state.

use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Generation that introduced raw bulk records.
pub const BULK_PROTOCOL_VERSION: u8 = 7;

/// First and only bulk record format in generation 7.
pub const BULK_FORMAT_RAW_V1: u8 = 1;

/// Bytes in the raw record body before its payload.
pub const BULK_HEADER_SIZE: usize = 12;

/// Default raw-record payload selected by generation-7 peers.
pub const DEFAULT_BULK_RECORD_PAYLOAD: u32 = 256 * 1024;

/// Smallest record payload a peer may negotiate.
pub const MIN_BULK_RECORD_PAYLOAD: u32 = 16 * 1024;

/// Largest record payload generation 7 permits.
pub const MAX_BULK_RECORD_PAYLOAD: u32 = 1024 * 1024;

/// Default receive window granted to one bulk flow.
pub const DEFAULT_BULK_WINDOW: u64 = 8 * 1024 * 1024;

/// Largest receive window generation 7 permits.
pub const MAX_BULK_WINDOW: u64 = 32 * 1024 * 1024;

/// Flow-mask bit for host-to-guest data.
pub const BULK_FLOW_MASK_HOST_TO_GUEST: u8 = 0b01;

/// Flow-mask bit for guest-to-host data.
pub const BULK_FLOW_MASK_GUEST_TO_HOST: u8 = 0b10;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Operation family carried by a raw bulk record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BulkKind {
    /// Filesystem read or write bytes.
    Filesystem = 1,

    /// TCP stream bytes.
    Tcp = 2,
}

/// Physical direction of a raw bulk flow across the VM boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BulkFlow {
    /// Host or SDK to guest or agentd.
    HostToGuest = 1,

    /// Guest or agentd to host or SDK.
    GuestToHost = 2,
}

/// A generation-7 raw record after fixed-header validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkRecord {
    /// Correlation that owns this record.
    pub id: u32,

    /// Operation family.
    pub kind: BulkKind,

    /// Physical data direction.
    pub flow: BulkFlow,

    /// Zero-based stream offset of the first payload byte.
    pub offset: u64,

    /// Opaque payload bytes.
    pub payload: Bytes,
}

/// Optional raw-bulk offer on a generation-7 opening request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BulkOffer {
    /// Bulk record format. Generation 7 requires `1`.
    pub format: u8,

    /// Largest payload this host accepts in one raw record.
    pub max_record_payload: u32,

    /// Initial absolute guest-to-host exclusive send limit.
    pub guest_to_host_credit_limit: u64,
}

/// Guest acceptance of one offered bulk correlation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BulkAccepted {
    /// Accepted operation family.
    pub kind: BulkKind,

    /// Enabled-flow mask.
    pub flows: u8,

    /// Accepted record format.
    pub format: u8,

    /// Effective maximum record payload.
    pub max_record_payload: u32,

    /// Initial absolute host-to-guest exclusive send limit.
    pub host_to_guest_credit_limit: u64,

    /// Exact host grant accepted for guest-to-host data.
    pub guest_to_host_credit_limit: u64,
}

/// Absolute credit update from a flow receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BulkCredit {
    /// Operation family.
    pub kind: BulkKind,

    /// Flow whose sender receives credit.
    pub flow: BulkFlow,

    /// Bytes for which the receiver has accepted responsibility.
    pub consumed_offset: u64,

    /// Absolute exclusive byte offset the sender may reach.
    pub credit_limit: u64,
}

/// Exact end offset for one flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BulkFinish {
    /// Operation family.
    pub kind: BulkKind,

    /// Flow that reached EOF or half-close.
    pub flow: BulkFlow,

    /// Exact final byte offset.
    pub final_offset: u64,
}

/// Reason one peer cancelled an entire bulk correlation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BulkCancelReason {
    /// Local caller dropped or cancelled the operation.
    CallerCancelled = 1,

    /// Destination file or socket I/O failed.
    DestinationIo = 2,

    /// A configured resource limit was reached.
    ResourceLimit = 3,

    /// The underlying transport failed.
    TransportFailure = 4,

    /// The peer violated the correlation state machine.
    ProtocolState = 5,
}

/// Best-effort request to stop an entire bulk correlation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BulkCancel {
    /// Operation family.
    pub kind: BulkKind,

    /// Stable cancellation reason.
    pub reason: BulkCancelReason,

    /// Human-readable diagnostic without payload data.
    pub message: String,
}

/// Sender-side absolute-offset and credit state for one flow.
#[derive(Debug, Clone)]
pub struct BulkSendState {
    kind: BulkKind,
    flow: BulkFlow,
    max_record_payload: u32,
    next_offset: u64,
    consumed_offset: u64,
    credit_limit: u64,
    finished: bool,
}

/// Receiver-side exact-offset and replenishment state for one flow.
#[derive(Debug, Clone)]
pub struct BulkReceiveState {
    kind: BulkKind,
    flow: BulkFlow,
    max_record_payload: u32,
    window: u64,
    next_expected_offset: u64,
    consumed_offset: u64,
    credit_limit: u64,
    finished: bool,
}

/// Validation failure in generation-7 bulk state.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BulkStateError {
    /// Unsupported record format.
    #[error("unsupported bulk format {0}")]
    UnsupportedFormat(u8),

    /// Negotiated record limit is outside generation-7 bounds.
    #[error("invalid maximum bulk record payload {0}")]
    InvalidRecordLimit(u32),

    /// A raw record payload is empty or exceeds the negotiated limit.
    #[error("invalid bulk record payload length {length} (max {max})")]
    InvalidPayloadLength {
        /// Actual payload length.
        length: usize,
        /// Negotiated maximum.
        max: u32,
    },

    /// The record or control belongs to another operation family or flow.
    #[error("bulk kind or flow does not match the correlation")]
    FlowMismatch,

    /// Offset arithmetic overflowed `u64`.
    #[error("bulk offset overflow")]
    OffsetOverflow,

    /// A sender tried to exceed the absolute receive credit.
    #[error("bulk record end {end} exceeds credit limit {limit}")]
    CreditExceeded {
        /// Proposed exclusive record end.
        end: u64,
        /// Current exclusive credit limit.
        limit: u64,
    },

    /// Credit state regressed or violated the negotiated window.
    #[error("invalid bulk credit: {0}")]
    InvalidCredit(String),

    /// A record did not start at the exact expected stream offset.
    #[error("bulk record offset {actual} does not match expected {expected}")]
    OffsetMismatch {
        /// Required offset.
        expected: u64,
        /// Received offset.
        actual: u64,
    },

    /// A finish marker did not match the exact admitted offset.
    #[error("bulk finish offset {actual} does not match expected {expected}")]
    FinishMismatch {
        /// Required final offset.
        expected: u64,
        /// Received final offset.
        actual: u64,
    },

    /// Data or control arrived after this flow finished.
    #[error("bulk flow is already finished")]
    AlreadyFinished,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl BulkKind {
    /// Parse a generation-7 wire value.
    pub fn from_wire(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Filesystem),
            2 => Some(Self::Tcp),
            _ => None,
        }
    }
}

impl BulkFlow {
    /// Parse a generation-7 wire value.
    pub fn from_wire(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::HostToGuest),
            2 => Some(Self::GuestToHost),
            _ => None,
        }
    }

    /// Return this flow's bit in [`BulkAccepted::flows`].
    pub fn mask(self) -> u8 {
        match self {
            Self::HostToGuest => BULK_FLOW_MASK_HOST_TO_GUEST,
            Self::GuestToHost => BULK_FLOW_MASK_GUEST_TO_HOST,
        }
    }
}

impl BulkOffer {
    /// Build the default offer for a filesystem read.
    pub fn filesystem_read() -> Self {
        Self::new(DEFAULT_BULK_WINDOW)
    }

    /// Build the default offer for a filesystem write.
    pub fn filesystem_write() -> Self {
        Self::new(0)
    }

    /// Build the default bidirectional TCP offer.
    pub fn tcp() -> Self {
        Self::new(DEFAULT_BULK_WINDOW)
    }

    /// Validate generation-7 offer limits.
    pub fn validate(self) -> Result<Self, BulkStateError> {
        validate_record_limit(self.max_record_payload)?;
        if self.format != BULK_FORMAT_RAW_V1 {
            return Err(BulkStateError::UnsupportedFormat(self.format));
        }
        if self.guest_to_host_credit_limit > MAX_BULK_WINDOW {
            return Err(BulkStateError::InvalidCredit(format!(
                "initial guest-to-host limit {} exceeds {}",
                self.guest_to_host_credit_limit, MAX_BULK_WINDOW
            )));
        }
        Ok(self)
    }

    fn new(guest_to_host_credit_limit: u64) -> Self {
        Self {
            format: BULK_FORMAT_RAW_V1,
            max_record_payload: DEFAULT_BULK_RECORD_PAYLOAD,
            guest_to_host_credit_limit,
        }
    }
}

impl BulkAccepted {
    /// Validate an acceptance against the opening offer and required operation shape.
    pub fn validate_against(
        self,
        offer: BulkOffer,
        kind: BulkKind,
        flows: u8,
    ) -> Result<Self, BulkStateError> {
        let offer = offer.validate()?;
        validate_record_limit(self.max_record_payload)?;
        if self.kind != kind || self.flows != flows || self.flows & !0b11 != 0 {
            return Err(BulkStateError::FlowMismatch);
        }
        if self.format != BULK_FORMAT_RAW_V1 {
            return Err(BulkStateError::UnsupportedFormat(self.format));
        }
        if self.max_record_payload > offer.max_record_payload {
            return Err(BulkStateError::InvalidRecordLimit(self.max_record_payload));
        }
        if self.guest_to_host_credit_limit != offer.guest_to_host_credit_limit {
            return Err(BulkStateError::InvalidCredit(
                "guest-to-host grant was not echoed exactly".into(),
            ));
        }
        if self.host_to_guest_credit_limit > MAX_BULK_WINDOW {
            return Err(BulkStateError::InvalidCredit(
                "host-to-guest grant exceeds the generation-7 window".into(),
            ));
        }
        let host_to_guest = self.flows & BULK_FLOW_MASK_HOST_TO_GUEST != 0;
        let guest_to_host = self.flows & BULK_FLOW_MASK_GUEST_TO_HOST != 0;
        if host_to_guest != (self.host_to_guest_credit_limit != 0) {
            return Err(BulkStateError::InvalidCredit(
                "host-to-guest credit must be nonzero exactly when that flow is enabled".into(),
            ));
        }
        if guest_to_host != (self.guest_to_host_credit_limit != 0) {
            return Err(BulkStateError::InvalidCredit(
                "guest-to-host credit must be nonzero exactly when that flow is enabled".into(),
            ));
        }
        Ok(self)
    }
}

impl BulkSendState {
    /// Create one sender flow from negotiated limits.
    pub fn new(
        kind: BulkKind,
        flow: BulkFlow,
        max_record_payload: u32,
        credit_limit: u64,
    ) -> Result<Self, BulkStateError> {
        validate_record_limit(max_record_payload)?;
        if credit_limit > MAX_BULK_WINDOW {
            return Err(BulkStateError::InvalidCredit(
                "initial credit exceeds the generation-7 window".into(),
            ));
        }
        Ok(Self {
            kind,
            flow,
            max_record_payload,
            next_offset: 0,
            consumed_offset: 0,
            credit_limit,
            finished: false,
        })
    }

    /// Return the next byte offset this sender will assign.
    pub fn next_offset(&self) -> u64 {
        self.next_offset
    }

    /// Return the currently admitted exclusive limit.
    pub fn credit_limit(&self) -> u64 {
        self.credit_limit
    }

    /// Return the maximum payload negotiated for this flow.
    pub fn max_record_payload(&self) -> u32 {
        self.max_record_payload
    }

    /// Return bytes the sender may currently admit without another credit update.
    pub fn available_credit(&self) -> u64 {
        self.credit_limit.saturating_sub(self.next_offset)
    }

    /// Admit a payload and advance the ordered sender cursor.
    pub fn admit(&mut self, payload_len: usize) -> Result<u64, BulkStateError> {
        if self.finished {
            return Err(BulkStateError::AlreadyFinished);
        }
        validate_payload_len(payload_len, self.max_record_payload)?;
        let end = self
            .next_offset
            .checked_add(payload_len as u64)
            .ok_or(BulkStateError::OffsetOverflow)?;
        if end > self.credit_limit {
            return Err(BulkStateError::CreditExceeded {
                end,
                limit: self.credit_limit,
            });
        }
        let offset = self.next_offset;
        self.next_offset = end;
        Ok(offset)
    }

    /// Apply one idempotent absolute credit update.
    pub fn apply_credit(&mut self, credit: BulkCredit) -> Result<bool, BulkStateError> {
        if credit.kind != self.kind || credit.flow != self.flow {
            return Err(BulkStateError::FlowMismatch);
        }
        if credit.consumed_offset > self.next_offset {
            return Err(BulkStateError::InvalidCredit(
                "peer consumed bytes the sender has not admitted".into(),
            ));
        }
        if credit.credit_limit < credit.consumed_offset
            || credit.credit_limit - credit.consumed_offset > MAX_BULK_WINDOW
        {
            return Err(BulkStateError::InvalidCredit(
                "credit limit is outside the allowed absolute window".into(),
            ));
        }

        if credit.consumed_offset <= self.consumed_offset
            && credit.credit_limit <= self.credit_limit
        {
            return Ok(false);
        }
        if credit.consumed_offset < self.consumed_offset
            || credit.credit_limit < self.credit_limit
            || credit.credit_limit < self.next_offset
        {
            return Err(BulkStateError::InvalidCredit(
                "credit fields advanced inconsistently".into(),
            ));
        }

        self.consumed_offset = credit.consumed_offset;
        self.credit_limit = credit.credit_limit;
        Ok(true)
    }

    /// Finish this sender at its exact current offset.
    pub fn finish(&mut self) -> Result<BulkFinish, BulkStateError> {
        if self.finished {
            return Err(BulkStateError::AlreadyFinished);
        }
        self.finished = true;
        Ok(BulkFinish {
            kind: self.kind,
            flow: self.flow,
            final_offset: self.next_offset,
        })
    }
}

impl BulkReceiveState {
    /// Create one receiver flow and its initial absolute grant.
    pub fn new(
        kind: BulkKind,
        flow: BulkFlow,
        max_record_payload: u32,
        credit_limit: u64,
        window: u64,
    ) -> Result<Self, BulkStateError> {
        validate_record_limit(max_record_payload)?;
        if window == 0 || window > MAX_BULK_WINDOW || credit_limit > window {
            return Err(BulkStateError::InvalidCredit(
                "invalid initial receive window".into(),
            ));
        }
        Ok(Self {
            kind,
            flow,
            max_record_payload,
            window,
            next_expected_offset: 0,
            consumed_offset: 0,
            credit_limit,
            finished: false,
        })
    }

    /// Return the next exact record offset.
    pub fn next_expected_offset(&self) -> u64 {
        self.next_expected_offset
    }

    /// Return the current absolute receive credit limit.
    pub fn credit_limit(&self) -> u64 {
        self.credit_limit
    }

    /// Validate and admit a record before its destination consumes the payload.
    pub fn accept_record(&mut self, record: &BulkRecord) -> Result<u64, BulkStateError> {
        if self.finished {
            return Err(BulkStateError::AlreadyFinished);
        }
        if record.kind != self.kind || record.flow != self.flow {
            return Err(BulkStateError::FlowMismatch);
        }
        validate_payload_len(record.payload.len(), self.max_record_payload)?;
        if record.offset != self.next_expected_offset {
            return Err(BulkStateError::OffsetMismatch {
                expected: self.next_expected_offset,
                actual: record.offset,
            });
        }
        let end = record
            .offset
            .checked_add(record.payload.len() as u64)
            .ok_or(BulkStateError::OffsetOverflow)?;
        if end > self.credit_limit {
            return Err(BulkStateError::CreditExceeded {
                end,
                limit: self.credit_limit,
            });
        }
        self.next_expected_offset = end;
        Ok(end)
    }

    /// Mark admitted bytes consumed and return a replenishment when half the window remains.
    pub fn consume(&mut self, consumed_offset: u64) -> Result<Option<BulkCredit>, BulkStateError> {
        if consumed_offset < self.consumed_offset || consumed_offset > self.next_expected_offset {
            return Err(BulkStateError::InvalidCredit(
                "consumed offset is outside admitted bytes".into(),
            ));
        }
        self.consumed_offset = consumed_offset;
        if self.credit_limit - self.consumed_offset > self.window / 2 {
            return Ok(None);
        }
        let next_limit = self
            .consumed_offset
            .checked_add(self.window)
            .ok_or(BulkStateError::OffsetOverflow)?;
        if next_limit <= self.credit_limit {
            return Ok(None);
        }
        self.credit_limit = next_limit;
        Ok(Some(BulkCredit {
            kind: self.kind,
            flow: self.flow,
            consumed_offset: self.consumed_offset,
            credit_limit: self.credit_limit,
        }))
    }

    /// Accept an exact finish after all earlier records.
    pub fn accept_finish(&mut self, finish: BulkFinish) -> Result<(), BulkStateError> {
        if self.finished {
            return Err(BulkStateError::AlreadyFinished);
        }
        if finish.kind != self.kind || finish.flow != self.flow {
            return Err(BulkStateError::FlowMismatch);
        }
        if finish.final_offset != self.next_expected_offset {
            return Err(BulkStateError::FinishMismatch {
                expected: self.next_expected_offset,
                actual: finish.final_offset,
            });
        }
        self.finished = true;
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

macro_rules! impl_wire_enum {
    ($type:ty, $parse:path) => {
        impl Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_u8(*self as u8)
            }
        }

        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = u8::deserialize(deserializer)?;
                $parse(value).ok_or_else(|| serde::de::Error::custom("unknown bulk enum value"))
            }
        }
    };
}

impl_wire_enum!(BulkKind, BulkKind::from_wire);
impl_wire_enum!(BulkFlow, BulkFlow::from_wire);

impl Serialize for BulkCancelReason {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(*self as u8)
    }
}

impl<'de> Deserialize<'de> for BulkCancelReason {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        match value {
            1 => Ok(Self::CallerCancelled),
            2 => Ok(Self::DestinationIo),
            3 => Ok(Self::ResourceLimit),
            4 => Ok(Self::TransportFailure),
            5 => Ok(Self::ProtocolState),
            _ => Err(serde::de::Error::custom("unknown bulk cancel reason")),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn validate_record_limit(limit: u32) -> Result<(), BulkStateError> {
    if !(MIN_BULK_RECORD_PAYLOAD..=MAX_BULK_RECORD_PAYLOAD).contains(&limit) {
        return Err(BulkStateError::InvalidRecordLimit(limit));
    }
    Ok(())
}

fn validate_payload_len(length: usize, max: u32) -> Result<(), BulkStateError> {
    if length == 0 || length > max as usize {
        return Err(BulkStateError::InvalidPayloadLength { length, max });
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_stops_at_exact_credit_and_accepts_absolute_replenishment() {
        let mut sender = BulkSendState::new(
            BulkKind::Filesystem,
            BulkFlow::GuestToHost,
            MIN_BULK_RECORD_PAYLOAD,
            MIN_BULK_RECORD_PAYLOAD as u64,
        )
        .unwrap();
        assert_eq!(sender.admit(MIN_BULK_RECORD_PAYLOAD as usize).unwrap(), 0);
        assert!(matches!(
            sender.admit(1),
            Err(BulkStateError::CreditExceeded { .. })
        ));

        assert!(
            sender
                .apply_credit(BulkCredit {
                    kind: BulkKind::Filesystem,
                    flow: BulkFlow::GuestToHost,
                    consumed_offset: MIN_BULK_RECORD_PAYLOAD as u64,
                    credit_limit: 2 * MIN_BULK_RECORD_PAYLOAD as u64,
                })
                .unwrap()
        );
        assert_eq!(
            sender.admit(MIN_BULK_RECORD_PAYLOAD as usize).unwrap(),
            MIN_BULK_RECORD_PAYLOAD as u64
        );
    }

    #[test]
    fn receiver_rejects_gap_and_replenishes_at_half_window() {
        let window = 2 * MIN_BULK_RECORD_PAYLOAD as u64;
        let mut receiver = BulkReceiveState::new(
            BulkKind::Tcp,
            BulkFlow::HostToGuest,
            MIN_BULK_RECORD_PAYLOAD,
            window,
            window,
        )
        .unwrap();
        let gap = BulkRecord {
            id: 4,
            kind: BulkKind::Tcp,
            flow: BulkFlow::HostToGuest,
            offset: 1,
            payload: Bytes::from_static(b"x"),
        };
        assert!(matches!(
            receiver.accept_record(&gap),
            Err(BulkStateError::OffsetMismatch { .. })
        ));

        let record = BulkRecord {
            offset: 0,
            payload: Bytes::from(vec![0; MIN_BULK_RECORD_PAYLOAD as usize]),
            ..gap
        };
        let end = receiver.accept_record(&record).unwrap();
        let credit = receiver.consume(end).unwrap().unwrap();
        assert_eq!(credit.consumed_offset, MIN_BULK_RECORD_PAYLOAD as u64);
        assert_eq!(credit.credit_limit, 3 * MIN_BULK_RECORD_PAYLOAD as u64);
    }
}
