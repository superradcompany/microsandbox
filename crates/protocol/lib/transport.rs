//! Internal host/guest binding contract for optional agent transport lanes.

use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};

use crate::AGENT_BULK_PORT_NAME;
use crate::bulk::{BULK_HEADER_SIZE, BULK_PROTOCOL_VERSION, BulkRecord};
use crate::codec::{self, MAX_FRAME_SIZE};
use crate::error::{ProtocolError, ProtocolResult};
use crate::message::{FLAG_BULK, FRAME_HEADER_SIZE};
use crate::{AGENT_RELAY_ID_RANGE_STEP, AGENT_RELAY_MAX_CLIENTS};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Stable transport-profile name advertised after a successful binding.
pub const DUAL_PORT_V1_PROFILE: &str = "dual-port-v1";

/// Bytes in either the bulk-port hello or acknowledgement.
pub const BULK_BINDING_SIZE: usize = 24;

/// First binding format used on the dedicated bulk console port.
pub const BULK_BINDING_FORMAT_V1: u8 = 1;

/// Bytes prepended to every raw frame on the dedicated bulk lane.
pub const CLIENT_INCARNATION_SIZE: usize = 16;

/// Bytes in the fixed capability-gated range-lease control frame.
pub const RELAY_CLIENT_LEASE_SIZE: usize = 41;

/// First backwards-readable range-lease record format.
pub const RELAY_LEASE_FORMAT_V1: u8 = 1;

const BULK_HELLO_MAGIC: [u8; 4] = *b"MSBB";
const BULK_ACK_MAGIC: [u8; 4] = *b"MSBA";
const RELAY_CLIENT_MAGIC: [u8; 4] = *b"MSBL";
const RELAY_CLIENT_CONNECTED: u8 = 1;
const RELAY_CLIENT_DISCONNECTED_ACK: u8 = 2;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Optional `core.ready` capability proving that the dedicated bulk lane is bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BulkTransportReady {
    /// Selected internal transport profile.
    pub profile: String,

    /// Exact virtio-console port name carrying raw records.
    pub port: String,

    /// Per-boot binding identity echoed by both peers.
    pub connection_id: [u8; 16],
}

/// Stable identity for one ownership period of a relay correlation range.
pub type ClientIncarnation = [u8; CLIENT_INCARNATION_SIZE];

/// Agentd advertisement for the highest backwards-readable relay lease format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayLeaseReady {
    /// Highest fixed MSBL record format this agent can read.
    pub max_format: u8,
}

/// One incarnation-bearing dedicated-lane frame after validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncarnatedBulkFrame {
    /// SDK client that owned the correlation range when this record was admitted.
    pub incarnation: ClientIncarnation,

    /// Exact generation-7 frame bytes after removing the transport prefix.
    pub frame: Bytes,

    /// Validated raw record whose payload shares the frame allocation.
    pub record: BulkRecord,
}

/// Capability-gated control record establishing one topology-independent correlation-range owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayClientConnected {
    /// First correlation ID assigned to the connected client.
    pub id_start: u32,

    /// Exclusive upper bound of the connected client's ID range.
    pub id_end_exclusive: u32,

    /// Random identity for this exact ownership period of the range.
    pub incarnation: ClientIncarnation,
}

/// Capability-gated acknowledgement that a disconnected range is safe to reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayClientDisconnectedAck {
    /// First correlation ID assigned to the disconnected client.
    pub id_start: u32,

    /// Exclusive upper bound of the disconnected client's ID range.
    pub id_end_exclusive: u32,

    /// Exact ownership period whose control output has been drained.
    pub incarnation: ClientIncarnation,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl BulkTransportReady {
    /// Build the canonical readiness advertisement for a bound dual-port session.
    pub fn dual_port_v1(connection_id: [u8; 16]) -> Self {
        Self {
            profile: DUAL_PORT_V1_PROFILE.to_string(),
            port: AGENT_BULK_PORT_NAME.to_string(),
            connection_id,
        }
    }

    /// Validate every field against the host-observed binding identity.
    pub fn validate_dual_port_v1(&self, expected_id: [u8; 16]) -> ProtocolResult<()> {
        if self.profile != DUAL_PORT_V1_PROFILE {
            return Err(invalid_binding(format!(
                "unexpected profile {}",
                self.profile
            )));
        }
        if self.port != AGENT_BULK_PORT_NAME {
            return Err(invalid_binding(format!("unexpected port {}", self.port)));
        }
        if self.connection_id != expected_id {
            return Err(invalid_binding("connection ID does not match bulk port"));
        }
        Ok(())
    }
}

impl RelayLeaseReady {
    /// Advertise support for the first range-lease format.
    pub fn range_lease_v1() -> Self {
        Self {
            max_format: RELAY_LEASE_FORMAT_V1,
        }
    }

    /// Select the highest mutually supported backwards-readable format.
    pub fn select_supported(&self, host_max: u8) -> Option<u8> {
        let selected = self.max_format.min(host_max);
        (selected >= RELAY_LEASE_FORMAT_V1).then_some(selected)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Return the canonical half-open correlation range assigned to one relay client slot.
///
/// Correlation ID zero and every exact range boundary are deliberately left unassigned. Those gaps
/// make accidental cross-slot arithmetic observable instead of silently attributing a frame to a
/// neighbouring client.
pub fn relay_client_id_range(slot: u32) -> Option<(u32, u32)> {
    if slot >= AGENT_RELAY_MAX_CLIENTS {
        return None;
    }

    let offset = slot.checked_mul(AGENT_RELAY_ID_RANGE_STEP)?;
    Some((
        offset.checked_add(1)?,
        offset.checked_add(AGENT_RELAY_ID_RANGE_STEP)?,
    ))
}

/// Return the relay slot that canonically owns `id`, rejecting all unassigned gaps and tail IDs.
pub fn relay_client_slot(id: u32) -> Option<u32> {
    let slot = id / AGENT_RELAY_ID_RANGE_STEP;
    let (id_start, id_end_exclusive) = relay_client_id_range(slot)?;
    (id_start <= id && id < id_end_exclusive).then_some(slot)
}

/// Validate that two bounds name exactly one canonical relay-client range.
pub fn validate_relay_client_range(id_start: u32, id_end_exclusive: u32) -> Option<u32> {
    let slot = relay_client_slot(id_start)?;
    (relay_client_id_range(slot) == Some((id_start, id_end_exclusive))).then_some(slot)
}

/// Encode the guest's fixed-size dual-port binding hello.
pub fn encode_bulk_hello(connection_id: [u8; 16]) -> [u8; BULK_BINDING_SIZE] {
    encode_binding(BULK_HELLO_MAGIC, connection_id)
}

/// Encode the host acknowledgement for a validated guest hello.
pub fn encode_bulk_ack(connection_id: [u8; 16]) -> [u8; BULK_BINDING_SIZE] {
    encode_binding(BULK_ACK_MAGIC, connection_id)
}

/// Validate a guest hello and return its per-boot identity.
pub fn decode_bulk_hello(bytes: &[u8]) -> ProtocolResult<[u8; 16]> {
    decode_binding(bytes, BULK_HELLO_MAGIC, "hello")
}

/// Validate a host acknowledgement against the guest's per-boot identity.
pub fn decode_bulk_ack(bytes: &[u8], expected_id: [u8; 16]) -> ProtocolResult<()> {
    let actual_id = decode_binding(bytes, BULK_ACK_MAGIC, "acknowledgement")?;
    if actual_id != expected_id {
        return Err(invalid_binding(
            "acknowledgement connection ID does not match hello",
        ));
    }
    Ok(())
}

/// Decode one incarnation-prefixed generation-7 record from a stream buffer.
///
/// The 128-bit incarnation sits outside the generation-7 length prefix. The returned `frame`
/// can therefore be forwarded to an SDK byte-for-byte after the prefix is removed.
pub fn try_decode_incarnated_bulk_from_bytes(
    bytes: &mut BytesMut,
) -> ProtocolResult<Option<IncarnatedBulkFrame>> {
    let length_offset = CLIENT_INCARNATION_SIZE;
    if bytes.len() < length_offset + 4 {
        return Ok(None);
    }

    let frame_len = u32::from_be_bytes(
        bytes[length_offset..length_offset + 4]
            .try_into()
            .expect("checked dedicated bulk length width"),
    );
    if frame_len > MAX_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge {
            size: frame_len,
            max: MAX_FRAME_SIZE,
        });
    }
    let minimum = FRAME_HEADER_SIZE + BULK_HEADER_SIZE + 1;
    if frame_len < minimum as u32 {
        return Err(invalid_bulk_lane("dedicated bulk record has no payload"));
    }

    let total = CLIENT_INCARNATION_SIZE + 4 + frame_len as usize;
    if bytes.len() < total {
        return Ok(None);
    }

    let packet = bytes.split_to(total).freeze();
    let mut incarnation = [0u8; CLIENT_INCARNATION_SIZE];
    incarnation.copy_from_slice(&packet[..CLIENT_INCARNATION_SIZE]);
    let frame = packet.slice(CLIENT_INCARNATION_SIZE..);
    if frame[8] != FLAG_BULK {
        return Err(invalid_bulk_lane(
            "non-bulk frame arrived on dedicated bulk lane",
        ));
    }

    let id = u32::from_be_bytes(frame[4..8].try_into().expect("validated frame ID width"));
    let body = frame.slice(4 + FRAME_HEADER_SIZE..);
    let record = codec::decode_bulk_body(id, body, crate::bulk::MAX_BULK_RECORD_PAYLOAD)?;
    Ok(Some(IncarnatedBulkFrame {
        incarnation,
        frame,
        record,
    }))
}

/// Encode the fixed transport-level range-owner record sent on the ordered control lane.
pub fn encode_relay_client_connected(
    connected: RelayClientConnected,
) -> [u8; RELAY_CLIENT_LEASE_SIZE] {
    encode_relay_client_lease(RELAY_CLIENT_CONNECTED, connected)
}

/// Encode the guest acknowledgement that permits one disconnected slot to be reused.
pub fn encode_relay_client_disconnected_ack(
    ack: RelayClientDisconnectedAck,
) -> [u8; RELAY_CLIENT_LEASE_SIZE] {
    encode_relay_client_lease(
        RELAY_CLIENT_DISCONNECTED_ACK,
        RelayClientConnected {
            id_start: ack.id_start,
            id_end_exclusive: ack.id_end_exclusive,
            incarnation: ack.incarnation,
        },
    )
}

fn encode_relay_client_lease(
    event: u8,
    lease: RelayClientConnected,
) -> [u8; RELAY_CLIENT_LEASE_SIZE] {
    let mut frame = [0u8; RELAY_CLIENT_LEASE_SIZE];
    let frame_len = (RELAY_CLIENT_LEASE_SIZE - 4) as u32;
    frame[..4].copy_from_slice(&frame_len.to_be_bytes());
    // Bytes 4..9 are the ordinary zero-ID, zero-flags outer frame header.
    frame[9..13].copy_from_slice(&RELAY_CLIENT_MAGIC);
    frame[13] = RELAY_LEASE_FORMAT_V1;
    frame[14] = event;
    // Bytes 15..17 are reserved and deliberately remain zero.
    frame[17..21].copy_from_slice(&lease.id_start.to_be_bytes());
    frame[21..25].copy_from_slice(&lease.id_end_exclusive.to_be_bytes());
    frame[25..].copy_from_slice(&lease.incarnation);
    frame
}

/// Decode a complete transport-level range-owner record without consuming ordinary agent frames.
pub fn try_decode_relay_client_connected_from_bytes(
    bytes: &mut BytesMut,
) -> ProtocolResult<Option<RelayClientConnected>> {
    try_decode_relay_client_lease_from_bytes(bytes, RELAY_CLIENT_CONNECTED)
}

/// Decode the guest acknowledgement that permits one disconnected slot to be reused.
pub fn try_decode_relay_client_disconnected_ack_from_bytes(
    bytes: &mut BytesMut,
) -> ProtocolResult<Option<RelayClientDisconnectedAck>> {
    Ok(
        try_decode_relay_client_lease_from_bytes(bytes, RELAY_CLIENT_DISCONNECTED_ACK)?.map(
            |lease| RelayClientDisconnectedAck {
                id_start: lease.id_start,
                id_end_exclusive: lease.id_end_exclusive,
                incarnation: lease.incarnation,
            },
        ),
    )
}

fn try_decode_relay_client_lease_from_bytes(
    bytes: &mut BytesMut,
    expected_event: u8,
) -> ProtocolResult<Option<RelayClientConnected>> {
    if bytes.len() < 13 {
        return Ok(None);
    }
    if bytes[9..13] != RELAY_CLIENT_MAGIC {
        return Ok(None);
    }
    if bytes.len() < RELAY_CLIENT_LEASE_SIZE {
        return Ok(None);
    }
    let frame_len = u32::from_be_bytes(bytes[..4].try_into().expect("checked frame length width"));
    if frame_len as usize != RELAY_CLIENT_LEASE_SIZE - 4
        || bytes[4..9] != [0, 0, 0, 0, 0]
        || bytes[13] != RELAY_LEASE_FORMAT_V1
        || bytes[14] != expected_event
        || bytes[15..17] != [0, 0]
    {
        return Err(invalid_binding("malformed relay client lease frame"));
    }

    let frame = bytes.split_to(RELAY_CLIENT_LEASE_SIZE).freeze();
    let id_start = u32::from_be_bytes(frame[17..21].try_into().expect("checked range start width"));
    let id_end_exclusive =
        u32::from_be_bytes(frame[21..25].try_into().expect("checked range end width"));
    let mut incarnation = [0u8; CLIENT_INCARNATION_SIZE];
    incarnation.copy_from_slice(&frame[25..]);
    Ok(Some(RelayClientConnected {
        id_start,
        id_end_exclusive,
        incarnation,
    }))
}

fn encode_binding(magic: [u8; 4], connection_id: [u8; 16]) -> [u8; BULK_BINDING_SIZE] {
    let mut bytes = [0u8; BULK_BINDING_SIZE];
    bytes[..4].copy_from_slice(&magic);
    bytes[4] = BULK_BINDING_FORMAT_V1;
    bytes[5] = BULK_PROTOCOL_VERSION;
    bytes[8..].copy_from_slice(&connection_id);
    bytes
}

fn decode_binding(bytes: &[u8], expected_magic: [u8; 4], label: &str) -> ProtocolResult<[u8; 16]> {
    if bytes.len() != BULK_BINDING_SIZE {
        return Err(invalid_binding(format!(
            "{label} is {} bytes, expected {BULK_BINDING_SIZE}",
            bytes.len()
        )));
    }
    if bytes[..4] != expected_magic {
        return Err(invalid_binding(format!("invalid {label} magic")));
    }
    if bytes[4] != BULK_BINDING_FORMAT_V1 {
        return Err(invalid_binding(format!(
            "unsupported {label} format {}",
            bytes[4]
        )));
    }
    if bytes[5] != BULK_PROTOCOL_VERSION {
        return Err(invalid_binding(format!(
            "unsupported {label} minimum generation {}",
            bytes[5]
        )));
    }
    if bytes[6..8] != [0, 0] {
        return Err(invalid_binding(format!(
            "nonzero reserved bytes in {label}"
        )));
    }

    let mut connection_id = [0u8; 16];
    connection_id.copy_from_slice(&bytes[8..]);
    Ok(connection_id)
}

fn invalid_binding(message: impl Into<String>) -> ProtocolError {
    ProtocolError::InvalidBulkBinding(message.into())
}

fn invalid_bulk_lane(message: impl Into<String>) -> ProtocolError {
    ProtocolError::InvalidBulkFrame(message.into())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_client_ranges_reject_zero_boundaries_and_unused_tail() {
        for slot in 0..AGENT_RELAY_MAX_CLIENTS {
            let (start, end) = relay_client_id_range(slot).unwrap();
            assert_eq!(relay_client_slot(start), Some(slot));
            assert_eq!(relay_client_slot(end - 1), Some(slot));
            assert_eq!(relay_client_slot(end), None);
            assert_eq!(validate_relay_client_range(start, end), Some(slot));
            assert_eq!(validate_relay_client_range(start, end + 1), None);
        }

        assert_eq!(relay_client_slot(0), None);
        assert_eq!(relay_client_slot(u32::MAX), None);
        assert_eq!(relay_client_id_range(AGENT_RELAY_MAX_CLIENTS), None);
    }

    #[test]
    fn binding_round_trip_preserves_connection_identity() {
        let id = [0x5a; 16];
        assert_eq!(decode_bulk_hello(&encode_bulk_hello(id)).unwrap(), id);
        decode_bulk_ack(&encode_bulk_ack(id), id).unwrap();
        BulkTransportReady::dual_port_v1(id)
            .validate_dual_port_v1(id)
            .unwrap();
    }

    #[test]
    fn binding_rejects_every_fixed_field_and_stale_identity() {
        let id = [0x31; 16];
        for index in 0..8 {
            let mut hello = encode_bulk_hello(id);
            hello[index] ^= 0xff;
            assert!(decode_bulk_hello(&hello).is_err(), "field byte {index}");
        }

        let mut stale = id;
        stale[15] ^= 1;
        assert!(decode_bulk_ack(&encode_bulk_ack(stale), id).is_err());
        assert!(
            BulkTransportReady::dual_port_v1(stale)
                .validate_dual_port_v1(id)
                .is_err()
        );
    }

    #[test]
    fn binding_rejects_truncation_at_every_byte() {
        let hello = encode_bulk_hello([0x7c; 16]);
        for len in 0..BULK_BINDING_SIZE {
            assert!(decode_bulk_hello(&hello[..len]).is_err(), "length {len}");
        }
    }

    #[test]
    fn incarnation_prefix_round_trip_preserves_public_frame() {
        let incarnation = [0xa5; CLIENT_INCARNATION_SIZE];
        let record = BulkRecord {
            id: 17,
            kind: crate::bulk::BulkKind::Filesystem,
            flow: crate::bulk::BulkFlow::GuestToHost,
            offset: 41,
            payload: Bytes::from_static(b"payload"),
        };
        let mut public_frame = Vec::new();
        codec::encode_bulk_to_buf(&record, &mut public_frame).unwrap();
        let mut dedicated = BytesMut::new();
        dedicated.extend_from_slice(&incarnation);
        dedicated.extend_from_slice(&public_frame);

        let decoded = try_decode_incarnated_bulk_from_bytes(&mut dedicated)
            .unwrap()
            .unwrap();
        assert_eq!(decoded.incarnation, incarnation);
        assert_eq!(decoded.frame.as_ref(), public_frame);
        assert_eq!(decoded.record, record);
        assert!(dedicated.is_empty());
    }

    #[test]
    fn incarnation_decoder_waits_at_every_fragment_boundary() {
        let incarnation = [0x33; CLIENT_INCARNATION_SIZE];
        let record = BulkRecord {
            id: 99,
            kind: crate::bulk::BulkKind::Tcp,
            flow: crate::bulk::BulkFlow::HostToGuest,
            offset: 0,
            payload: Bytes::from_static(b"fragmented"),
        };
        let mut public_frame = Vec::new();
        codec::encode_bulk_to_buf(&record, &mut public_frame).unwrap();
        let mut wire = incarnation.to_vec();
        wire.extend_from_slice(&public_frame);

        for split in 0..wire.len() {
            let mut input = BytesMut::from(&wire[..split]);
            assert!(
                try_decode_incarnated_bulk_from_bytes(&mut input)
                    .unwrap()
                    .is_none(),
                "decoded at incomplete boundary {split}"
            );
            input.extend_from_slice(&wire[split..]);
            assert_eq!(
                try_decode_incarnated_bulk_from_bytes(&mut input)
                    .unwrap()
                    .unwrap()
                    .record,
                record
            );
        }
    }

    #[test]
    fn relay_client_lease_round_trip_and_fragmentation() {
        let connected = RelayClientConnected {
            id_start: 1,
            id_end_exclusive: 0x0102_0304,
            incarnation: [0x77; CLIENT_INCARNATION_SIZE],
        };
        let wire = encode_relay_client_connected(connected);
        for split in 0..wire.len() {
            let mut input = BytesMut::from(&wire[..split]);
            assert!(
                try_decode_relay_client_connected_from_bytes(&mut input)
                    .unwrap()
                    .is_none()
            );
            input.extend_from_slice(&wire[split..]);
            assert_eq!(
                try_decode_relay_client_connected_from_bytes(&mut input).unwrap(),
                Some(connected)
            );
            assert!(input.is_empty());
        }
    }

    #[test]
    fn relay_client_disconnect_ack_round_trip_and_event_separation() {
        let ack = RelayClientDisconnectedAck {
            id_start: 1,
            id_end_exclusive: 1024,
            incarnation: [0x6d; CLIENT_INCARNATION_SIZE],
        };
        let wire = encode_relay_client_disconnected_ack(ack);
        let mut input = BytesMut::from(wire.as_slice());
        assert_eq!(
            try_decode_relay_client_disconnected_ack_from_bytes(&mut input).unwrap(),
            Some(ack)
        );
        assert!(input.is_empty());

        let mut wrong_direction = BytesMut::from(wire.as_slice());
        assert!(try_decode_relay_client_connected_from_bytes(&mut wrong_direction).is_err());
        assert_eq!(wrong_direction.as_ref(), wire);
    }

    #[test]
    fn relay_client_lease_rejects_corrupt_fixed_fields_without_consuming_input() {
        let connected = RelayClientConnected {
            id_start: 1,
            id_end_exclusive: 1024,
            incarnation: [0x52; CLIENT_INCARNATION_SIZE],
        };
        // The magic remains intact in every case, so the decoder must recognize the bytes as a
        // transport lease, reject its fixed contract, and leave diagnosis to the caller.
        for index in [0, 4, 8, 13, 14, 15, 16] {
            let mut wire = encode_relay_client_connected(connected);
            wire[index] ^= 0xff;
            let mut input = BytesMut::from(wire.as_slice());
            let before = input.clone();
            assert!(
                try_decode_relay_client_connected_from_bytes(&mut input).is_err(),
                "fixed field byte {index}"
            );
            assert_eq!(input, before, "fixed field byte {index}");
        }
    }

    #[test]
    fn relay_client_lease_decoder_ignores_unknown_magic() {
        let connected = RelayClientConnected {
            id_start: 1,
            id_end_exclusive: 1024,
            incarnation: [0x19; CLIENT_INCARNATION_SIZE],
        };
        let mut wire = encode_relay_client_connected(connected);
        wire[9] ^= 0xff;
        let mut input = BytesMut::from(wire.as_slice());
        let before = input.clone();

        assert_eq!(
            try_decode_relay_client_connected_from_bytes(&mut input).unwrap(),
            None
        );
        assert_eq!(input, before);
    }

    #[test]
    fn relay_client_lease_decoder_leaves_agent_frames_untouched() {
        let message = crate::message::Message::with_payload(
            crate::message::MessageType::Ping,
            7,
            &crate::core::Ping {},
        )
        .unwrap();
        let mut wire = Vec::new();
        codec::encode_to_buf(&message, &mut wire).unwrap();
        let mut input = BytesMut::from(wire.as_slice());

        assert!(
            try_decode_relay_client_connected_from_bytes(&mut input)
                .unwrap()
                .is_none()
        );
        assert_eq!(input.as_ref(), wire);
    }
}
