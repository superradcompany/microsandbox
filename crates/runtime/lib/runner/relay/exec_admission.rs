//! Sandbox-wide execution admission and accounting at the untrusted client boundary.
//!
//! The relay shares one guest connection between every SDK client, so the guest's
//! advertised [`ExecLimits`] are enforced here, before client traffic can reach the
//! shared channel: a slot must be reserved per execution, stdin is charged against
//! the per-execution input allowance and queued per execution so one blocked stdin
//! cannot stall the connection, and guest output is charged against the output
//! allowance until the client acknowledges consumption. Peers that predate the
//! policy bypass all of this through the legacy path.

use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
};

use bytes::Bytes;
use tokio::sync::Notify;

use microsandbox_protocol::{
    codec,
    core::CoreError,
    exec::{
        EXEC_OUTPUT_EVENT_OVERHEAD, ExecLimits, ExecOutputAck, ExecStdin, ExecStdinAck,
        MAX_EXEC_CONTROL_BYTES,
    },
    message::{Message, MessageType},
};

use serde::{Deserialize, Deserializer, de::Visitor};

use super::ControlWrite;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Default)]
/// Shared execution accounting and wakeups for queued stdin.
pub(super) struct ExecutionTracker(
    /// Admission, accounting, and per-execution queues protected by one lock.
    Mutex<State>,
    /// Wakes the writer when another execution has pending input.
    Notify,
);

#[derive(Default)]
struct State {
    /// Effective sandbox policy from Ready; absent for legacy guests.
    policy: Option<ExecLimits>,
    /// Admitted controlled executions across all SDK connections.
    sessions: HashMap<u32, Session>,
    /// Execution IDs with queued stdin, scheduled in round-robin order.
    ready_inputs: VecDeque<u32>,
}

#[derive(Default)]
struct Session {
    /// Whether disconnect cleanup has stopped accepting and forwarding queued input.
    input_closed: bool,
    /// Ordered stdin retained under this execution’s allowance until forwarding.
    pending_input: VecDeque<PendingInput>,
    /// Whether the guest has accepted this execution; stdin must wait until then.
    started: bool,
    /// Whether the client has sent EOF; further stdin messages are invalid.
    eof: bool,
    /// Cumulative stdin payload accepted from the client, including queued input.
    input_sent: u64,
    /// Cumulative stdin bytes acknowledged by the guest after child delivery.
    input_consumed: u64,
    /// Cumulative guest output charge, including per-chunk overhead.
    output_sent: u64,
    /// Cumulative output charge acknowledged by the client.
    output_consumed: u64,
}

struct PendingInput {
    /// Frame and routing metadata awaiting forwarding; data is empty while payload is mutable.
    write: ControlWrite,
    /// Original protocol generation retained when encoding a coalesced chunk.
    version: u8,
    /// Mutable small-write buffer; None keeps the encoded frame in write.data.
    payload: Option<ExecStdin>,
}

#[derive(Deserialize)]
struct DataLength {
    /// Payload length decoded without allocating a copy of its bytes.
    #[serde(deserialize_with = "deserialize_data_length")]
    data: usize,
}

/// Outcome of reserving an execution slot at the client boundary.
pub(super) enum Admission {
    /// A slot was reserved under the advertised execution policy.
    Accepted,
    /// This peer uses the historical path without execution accounting.
    Legacy,
    /// All execution slots are still occupied.
    Full,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ExecutionTracker {
    /// Record the guest's advertised limits once Ready arrives.
    /// `None` keeps every execution on the legacy path.
    pub(super) fn install(&self, policy: Option<ExecLimits>) -> Result<(), String> {
        if let Some(policy) = policy {
            policy.validate().map_err(str::to_owned)?;
        }
        self.0.lock().unwrap().policy = policy;
        Ok(())
    }

    /// Reserve an execution slot for a new request. The slot is held until the guest
    /// reports a terminal event and, for disconnects, cleanup is acknowledged.
    pub(super) fn admit(&self, request: &Message) -> Result<Admission, String> {
        let mut state = self.0.lock().unwrap();
        let Some(policy) = state.policy.filter(|_| request.v >= 10) else {
            return Ok(Admission::Legacy);
        };
        if state.sessions.contains_key(&request.id) {
            return Err("execution correlation is already active".into());
        }
        if state.sessions.len() >= policy.max_executions as usize {
            return Ok(Admission::Full);
        }
        state.sessions.insert(request.id, Session::default());
        Ok(Admission::Accepted)
    }

    /// Whether this correlation currently holds an execution slot.
    pub(super) fn contains(&self, id: u32) -> bool {
        self.0.lock().unwrap().sessions.contains_key(&id)
    }

    /// Whether this stdin message must go through the per-execution queues
    /// instead of the legacy shared forwarding path.
    pub(super) fn routes_input(&self, message: &Message) -> bool {
        let state = self.0.lock().unwrap();
        state.policy.is_some() && (message.v >= 10 || state.sessions.contains_key(&message.id))
    }

    /// Whether any execution has queued stdin awaiting forwarding.
    pub(super) fn has_pending_input(&self) -> bool {
        !self.0.lock().unwrap().ready_inputs.is_empty()
    }

    /// Queue only already-accounted stdin. Its execution allowance owns the payload until
    /// the guest acknowledges it; no connection-wide byte or frame reservation is needed.
    pub(super) fn enqueue_input(
        &self,
        mut write: ControlWrite,
        message: &Message,
        payload_len: usize,
    ) -> Result<(), String> {
        let mut state = self.0.lock().unwrap();
        let Some(policy) = state.policy else {
            return Err("execution policy is unavailable".into());
        };
        let Some(session) = state.sessions.get_mut(&message.id) else {
            // Input already in flight may follow a guest terminal; never fall back to the
            // legacy shared queue after this execution has lost its slot.
            return Ok(());
        };
        if session.input_closed {
            return Ok(());
        }
        if let Some(tail) = session
            .pending_input
            .back_mut()
            .and_then(|input| input.payload.as_mut())
            && payload_len != 0
            && tail.data.len() + payload_len <= policy.stdin_chunk_size as usize
        {
            let payload = message.payload::<ExecStdin>().map_err(|e| e.to_string())?;
            tail.data.extend(payload.data);
        } else {
            let was_empty = session.pending_input.is_empty();
            // Keep the first and full-sized chunks in their original wire allocation. Only
            // small writes queued behind another chunk need a mutable coalescing buffer.
            let payload =
                if !was_empty && payload_len != 0 && payload_len < policy.stdin_chunk_size as usize
                {
                    Some(message.payload::<ExecStdin>().map_err(|e| e.to_string())?)
                } else {
                    None
                };
            if payload.is_some() {
                write.data = Bytes::new();
            }
            session.pending_input.push_back(PendingInput {
                write,
                version: message.v,
                payload,
            });
            if was_empty {
                state.ready_inputs.push_back(message.id);
            }
        }
        drop(state);
        self.1.notify_one();
        Ok(())
    }

    /// Round-robin execution input without blocking the shared connection reader.
    pub(super) fn take_input(
        &self,
        mut admit: impl FnMut(&mut ControlWrite) -> Result<bool, String>,
    ) -> Result<Option<ControlWrite>, String> {
        let mut state = self.0.lock().unwrap();
        for _ in 0..state.ready_inputs.len() {
            let id = state.ready_inputs.pop_front().unwrap();
            let Some(session) = state.sessions.get_mut(&id) else {
                continue;
            };
            let Some(input) = session.pending_input.front_mut() else {
                continue;
            };
            // Once considered for forwarding, freeze this chunk. Later small writes merge
            // into the next queued chunk, never repeatedly decode/re-encode this blocked head.
            if let Some(payload) = input.payload.take() {
                let mut message = Message::with_payload(MessageType::ExecStdin, id, &payload)
                    .map_err(|e| e.to_string())?;
                message.v = input.version;
                let mut wire = Vec::new();
                codec::encode_to_buf(&message, &mut wire).map_err(|e| e.to_string())?;
                input.write.data = Bytes::from(wire);
            }
            let admitted = admit(&mut input.write)?;
            let result = admitted.then(|| session.pending_input.pop_front().unwrap().write);
            if !session.pending_input.is_empty() {
                state.ready_inputs.push_back(id);
            }
            if result.is_some() {
                return Ok(result);
            }
        }
        Ok(None)
    }

    /// Wait until new stdin is queued, so the writer polls only when there is work.
    pub(super) async fn input_changed(&self) {
        self.1.notified().await;
    }

    /// Drop queued input as soon as its owner disconnects, retaining the execution slot
    /// until guest cleanup is acknowledged.
    pub(super) fn cancel_input(&self, start: u32, end: u32) {
        let mut state = self.0.lock().unwrap();
        for (id, session) in &mut state.sessions {
            if (start..end).contains(id) {
                session.input_closed = true;
                session.pending_input.clear();
            }
        }
        state.ready_inputs.retain(|id| !(start..end).contains(id));
    }

    /// Account one client-origin message before it is forwarded. Stdin is charged
    /// against the input allowance and returns its payload length for queueing;
    /// output acknowledgements return consumed output allowance. An error is a
    /// protocol violation and must close the offending client connection.
    pub(super) fn client_message(
        &self,
        message: &Message,
        wire_len: usize,
    ) -> Result<Option<usize>, String> {
        validate_control(message, wire_len)?;
        let mut state = self.0.lock().unwrap();
        let Some(policy) = state.policy else {
            return Ok(None);
        };
        let Some(session) = state.sessions.get_mut(&message.id) else {
            return Ok(None);
        };
        match message.t {
            MessageType::ExecStdin => {
                let data = message
                    .payload::<DataLength>()
                    .map_err(|e| e.to_string())?
                    .data;
                if !session.started || session.eof {
                    return Err("stdin arrived before execution acceptance or after EOF".into());
                }
                let sent = session
                    .input_sent
                    .checked_add(data as u64)
                    .ok_or("execution input counter overflow")?;
                if data > policy.stdin_chunk_size as usize
                    || sent - session.input_consumed > u64::from(policy.input_limit)
                {
                    return Err(
                        "stdin exceeds the sandbox execution allowance or chunk size".into(),
                    );
                }
                session.input_sent = sent;
                session.eof = data == 0;
                return Ok(Some(data));
            }
            MessageType::ExecOutputAck => {
                let consumed = message
                    .payload::<ExecOutputAck>()
                    .map_err(|e| e.to_string())?
                    .consumed;
                acknowledge(&mut session.output_consumed, consumed, session.output_sent)?;
            }
            _ => {}
        }
        Ok(None)
    }

    /// Account one guest-origin message. Acceptance opens stdin, stdin
    /// acknowledgements replenish input allowance, stdout and stderr are charged
    /// against the output allowance, and terminal events release the slot. An
    /// error means the shared guest channel is no longer trustworthy.
    pub(super) fn guest_message(&self, message: &Message, wire_len: usize) -> Result<(), String> {
        validate_control(message, wire_len)?;
        let mut state = self.0.lock().unwrap();
        let Some(policy) = state.policy else {
            return Ok(());
        };
        let Some(session) = state.sessions.get_mut(&message.id) else {
            return Ok(());
        };
        match message.t {
            MessageType::ExecStarted => session.started = true,
            MessageType::ExecStdinAck => {
                let consumed = message
                    .payload::<ExecStdinAck>()
                    .map_err(|e| e.to_string())?
                    .consumed;
                acknowledge(&mut session.input_consumed, consumed, session.input_sent)?;
            }
            MessageType::ExecStdout | MessageType::ExecStderr => {
                let length = message
                    .payload::<DataLength>()
                    .map_err(|e| e.to_string())?
                    .data;
                let sent = session
                    .output_sent
                    .checked_add(length as u64 + u64::from(EXEC_OUTPUT_EVENT_OVERHEAD))
                    .ok_or("execution output counter overflow")?;
                if length > policy.output_chunk_size as usize
                    || sent - session.output_consumed > u64::from(policy.output_limit)
                {
                    return Err("guest output exceeds the sandbox execution policy".into());
                }
                session.output_sent = sent;
            }
            MessageType::ExecExited | MessageType::ExecFailed => {
                state.sessions.remove(&message.id);
                state.ready_inputs.retain(|id| *id != message.id);
            }
            MessageType::CoreError => {
                let error = message.payload::<CoreError>().map_err(|e| e.to_string())?;
                if session.started
                    || error.offending_type.as_deref() != Some(MessageType::ExecRequest.as_str())
                {
                    // Other errors do not prove this request failed. Retain its reservation
                    // until disconnect cleanup confirms that no guest process remains.
                    return Err("execution protocol error requires client cleanup".into());
                }
                state.sessions.remove(&message.id);
                state.ready_inputs.retain(|id| *id != message.id);
            }
            _ => {}
        }
        Ok(())
    }

    /// Called after the guest acknowledges cleanup, before its client range is reusable.
    pub(super) fn disconnect(&self, start: u32, end: u32) {
        self.cancel_input(start, end);
        self.0
            .lock()
            .unwrap()
            .sessions
            .retain(|id, _| !(start..end).contains(id));
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Accept a cumulative acknowledgement: it may repeat the last offset but can
/// never move backwards or claim more than was ever sent.
fn acknowledge(previous: &mut u64, consumed: u64, sent: u64) -> Result<(), String> {
    if consumed < *previous || consumed > sent {
        return Err("invalid execution acknowledgement offset".into());
    }
    *previous = consumed;
    Ok(())
}

/// Bound every execution control message, so acknowledgement and signal
/// traffic cannot grow into a data channel.
fn validate_control(message: &Message, wire_len: usize) -> Result<(), String> {
    if message.t.is_exec_control() && wire_len > MAX_EXEC_CONTROL_BYTES {
        return Err("execution control message exceeds 4 KiB".into());
    }
    Ok(())
}

/// Count payload bytes for execution allowance checks.
fn deserialize_data_length<'de, D: Deserializer<'de>>(deserializer: D) -> Result<usize, D::Error> {
    struct Length;

    impl<'de> Visitor<'de> for Length {
        type Value = usize;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("payload bytes")
        }

        fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<usize, E> {
            Ok(bytes.len())
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<usize, A::Error> {
            let mut len = 0;
            while seq.next_element::<u8>()?.is_some() {
                len += 1;
            }
            Ok(len)
        }
    }

    // Ciborium's deserialize_bytes rejects byte strings larger than its 4 KiB scratch
    // buffer. deserialize_any selects the owned path for larger or segmented strings.
    deserializer.deserialize_any(Length)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use microsandbox_protocol::exec::{ExecStderr, ExecStdout};

    use super::*;

    #[test]
    fn rejected_request_releases_capacity_but_running_errors_require_cleanup() {
        use microsandbox_protocol::{
            core::{CoreError, CoreErrorKind},
            exec::ExecStarted,
        };

        let flows = ExecutionTracker::default();
        flows
            .install(Some(ExecLimits {
                max_executions: 1,
                ..ExecLimits::default()
            }))
            .unwrap();
        // A lazy-decoded request can reach admission before the guest rejects its payload.
        let request = Message::with_payload(MessageType::ExecRequest, 1, &()).unwrap();
        let next = Message::with_payload(MessageType::ExecRequest, 2, &()).unwrap();
        assert!(matches!(
            flows.admit(&request).unwrap(),
            Admission::Accepted
        ));
        assert!(matches!(flows.admit(&next).unwrap(), Admission::Full));
        let error = Message::with_payload(
            MessageType::CoreError,
            1,
            &CoreError {
                kind: CoreErrorKind::InvalidPayload,
                message: "invalid execution request".into(),
                offending_type: Some(MessageType::ExecRequest.as_str().into()),
                init_failure: None,
                workload_failure: None,
            },
        )
        .unwrap();
        let mut unrelated = error.payload::<CoreError>().unwrap();
        unrelated.offending_type = Some(MessageType::ExecSignal.as_str().into());
        let unrelated = Message::with_payload(MessageType::CoreError, 1, &unrelated).unwrap();
        assert!(flows.guest_message(&unrelated, 0).is_err());
        assert!(matches!(flows.admit(&next).unwrap(), Admission::Full));

        flows.guest_message(&error, 0).unwrap();
        assert!(matches!(flows.admit(&next).unwrap(), Admission::Accepted));

        let started =
            Message::with_payload(MessageType::ExecStarted, 2, &ExecStarted { pid: 42 }).unwrap();
        flows.guest_message(&started, 0).unwrap();
        let mut running_error = error;
        running_error.id = 2;
        assert!(flows.guest_message(&running_error, 0).is_err());
        assert!(matches!(flows.admit(&request).unwrap(), Admission::Full));
        flows.disconnect(2, 3);
        assert!(matches!(
            flows.admit(&request).unwrap(),
            Admission::Accepted
        ));
    }

    #[test]
    fn output_allowance_is_shared_and_replenished_by_consumption() {
        for output_chunk_size in [4096, 16384] {
            let flows = ExecutionTracker::default();
            let policy = ExecLimits {
                output_chunk_size,
                ..ExecLimits::default()
            };
            flows.install(Some(policy)).unwrap();
            let mut request = Message::with_payload(MessageType::ExecRequest, 1, &()).unwrap();
            request.v = 10;
            assert!(matches!(
                flows.admit(&request).unwrap(),
                Admission::Accepted
            ));
            let stdout = Message::with_payload(
                MessageType::ExecStdout,
                1,
                &ExecStdout {
                    data: vec![b'x'; policy.output_chunk_size as usize],
                },
            )
            .unwrap();
            let stderr = Message::with_payload(
                MessageType::ExecStderr,
                1,
                &ExecStderr {
                    data: vec![b'y'; policy.output_chunk_size as usize],
                },
            )
            .unwrap();
            let charge = u64::from(policy.output_chunk_size + EXEC_OUTPUT_EVENT_OVERHEAD);
            for _ in 0..u64::from(policy.output_limit) / charge {
                flows.guest_message(&stdout, 0).unwrap();
            }
            assert!(flows.guest_message(&stderr, 0).is_err());
            let ack = Message::with_payload(
                MessageType::ExecOutputAck,
                1,
                &ExecOutputAck { consumed: charge },
            )
            .unwrap();
            flows.client_message(&ack, 0).unwrap();
            flows.guest_message(&stderr, 0).unwrap();
            assert!(flows.guest_message(&stdout, 0).is_err());
        }
    }
}
