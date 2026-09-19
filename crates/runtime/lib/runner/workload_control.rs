//! Private lifecycle control and bounded input admission for a bundled guest transport.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use microsandbox_protocol::codec;
use microsandbox_protocol::core::{
    CoreError, Ready, WORKLOAD_TRANSPORT_BARRIER_VERSION, WORKLOAD_TRANSPORT_BULK_BYTES,
    WORKLOAD_TRANSPORT_BULK_FRAMES, WORKLOAD_TRANSPORT_CONTROL_BYTES,
    WORKLOAD_TRANSPORT_CONTROL_FRAMES, WorkloadFrozen, WorkloadThawed, WorkloadTransportCredit,
    WorkloadTransportPosition,
};
use microsandbox_protocol::message::{Message, MessageType};
use tokio::sync::{Notify, mpsc, oneshot};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Outside every leased SDK correlation range; restore activation uses it before the relay runs.
pub(crate) const WORKLOAD_CONTROL_ID: u32 = u32::MAX;
const PRIVATE_QUEUE_CAPACITY: usize = 2;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A complete trusted frame. Ordinary client data can never enter this mailbox.
pub(crate) struct LifecycleWrite(pub(crate) Bytes);

struct PendingReply {
    request: MessageType,
    attempt: String,
    reply: oneshot::Sender<Result<Message, String>>,
}

struct State {
    ready: Option<(u8, Ready)>,
    active: bool,
    closed: bool,
    gates: usize,
    fenced: bool,
    primary_parked: bool,
    bulk_parked: bool,
    dual_port: bool,
    position: WorkloadTransportPosition,
    credit: WorkloadTransportCredit,
    guest_bulk_bytes: u64,
    bulk_tail: usize,
    pending: Vec<PendingReply>,
    ordinary_writer: Option<super::relay::ControlWriter>,
}

/// Shared by the trusted coordinator and relay, never exposed through the SDK socket.
pub(crate) struct WorkloadControl {
    state: Mutex<State>,
    tx: mpsc::Sender<LifecycleWrite>,
    rx: Mutex<Option<mpsc::Receiver<LifecycleWrite>>>,
    pub(crate) changed: Notify,
}

/// A transient capture or resident pause keeps ordinary input source-owned until thaw succeeds.
pub(crate) struct InputGate {
    control: Arc<WorkloadControl>,
    released: AtomicBool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl WorkloadControl {
    pub(crate) fn new() -> Arc<Self> {
        let (tx, rx) = mpsc::channel(PRIVATE_QUEUE_CAPACITY);
        Arc::new(Self {
            state: Mutex::new(State {
                ready: None,
                active: false,
                closed: false,
                gates: 0,
                fenced: false,
                primary_parked: false,
                bulk_parked: true,
                dual_port: false,
                position: WorkloadTransportPosition::default(),
                credit: WorkloadTransportCredit::default(),
                guest_bulk_bytes: 0,
                bulk_tail: 0,
                pending: Vec::new(),
                ordinary_writer: None,
            }),
            tx,
            rx: Mutex::new(Some(rx)),
            changed: Notify::new(),
        })
    }

    pub(crate) fn install_ready(&self, version: u8, ready: Ready, dual_port: bool) {
        let mut state = self.state.lock().unwrap();
        if ready.workload_transport_barrier_version == Some(WORKLOAD_TRANSPORT_BARRIER_VERSION)
            && state.ready.is_none()
        {
            state.credit = WorkloadTransportCredit {
                control_bytes: WORKLOAD_TRANSPORT_CONTROL_BYTES,
                control_frames: WORKLOAD_TRANSPORT_CONTROL_FRAMES,
                bulk_bytes: WORKLOAD_TRANSPORT_BULK_BYTES,
                bulk_frames: WORKLOAD_TRANSPORT_BULK_FRAMES,
            };
        }
        state.ready = Some((version, ready));
        state.dual_port = dual_port;
        state.bulk_parked = !dual_port;
    }

    pub(crate) fn start(&self) -> mpsc::Receiver<LifecycleWrite> {
        self.state.lock().unwrap().active = true;
        self.rx
            .lock()
            .unwrap()
            .take()
            .expect("one lifecycle writer")
    }

    pub(crate) fn register_ordinary_writer(&self, writer: super::relay::ControlWriter) {
        self.state.lock().unwrap().ordinary_writer = Some(writer);
    }

    /// Bootstrap may write directly before Ready. Every later ordinary write joins the same FIFO.
    pub(crate) fn ordinary_writer(&self) -> Result<Option<super::relay::ControlWriter>, String> {
        let state = self.state.lock().unwrap();
        if state.closed {
            return Err("workload transport closed".into());
        }
        if state.ready.is_none() {
            return Ok(None);
        }
        if !state.active {
            return Err("ready workload transport writer is not running".into());
        }
        state
            .ordinary_writer
            .clone()
            .map(Some)
            .ok_or_else(|| "ready workload transport writer is unavailable".into())
    }

    pub(crate) fn ready(&self) -> Result<(u8, Ready), String> {
        let state = self.state.lock().unwrap();
        if !state.active || state.closed {
            return Err("workload control transport is not running".into());
        }
        let (version, ready) = state.ready.clone().ok_or("guest readiness unavailable")?;
        if ready.workload_transport_barrier_version != Some(WORKLOAD_TRANSPORT_BARRIER_VERSION) {
            return Err(format!(
                "guest lacks workload transport barrier version {WORKLOAD_TRANSPORT_BARRIER_VERSION}"
            ));
        }
        Ok((version, ready))
    }

    pub(crate) fn gate(self: &Arc<Self>) -> InputGate {
        let mut state = self.state.lock().unwrap();
        if state.gates == 0 {
            state.primary_parked = false;
            state.bulk_parked = !state.dual_port;
        }
        state.gates += 1;
        drop(state);
        self.changed.notify_waiters();
        InputGate {
            control: Arc::clone(self),
            released: AtomicBool::new(false),
        }
    }

    pub(crate) fn fence(&self) {
        self.state.lock().unwrap().fenced = true;
        self.changed.notify_waiters();
    }

    pub(crate) fn gated(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.gates != 0 || state.fenced
    }

    pub(crate) fn park(&self, bulk: bool) {
        let mut state = self.state.lock().unwrap();
        let mut changed = false;
        if state.gates != 0 || state.fenced {
            if bulk {
                changed = !state.bulk_parked;
                state.bulk_parked = true;
            } else {
                changed = !state.primary_parked;
                state.primary_parked = true;
            }
        }
        drop(state);
        if changed {
            self.changed.notify_waiters();
        }
    }

    pub(crate) async fn parked_position(&self) -> Result<WorkloadTransportPosition, String> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let state = self.state.lock().unwrap();
                if state.closed {
                    return Err("workload transport closed".into());
                }
                if state.primary_parked && state.bulk_parked {
                    return Ok(state.position);
                }
            }
            changed.await;
        }
    }

    /// Reserve the whole record before its first fragment. The writer must finish it before parking.
    pub(crate) fn admit(&self, bulk: bool, bytes: usize) -> Result<bool, String> {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return Err("workload transport closed".into());
        }
        if state.gates != 0 || state.fenced {
            return Ok(false);
        }
        match state
            .ready
            .as_ref()
            .and_then(|(_, ready)| ready.workload_transport_barrier_version)
        {
            None => return Ok(true),
            Some(WORKLOAD_TRANSPORT_BARRIER_VERSION) => {}
            Some(version) => {
                return Err(format!(
                    "unsupported workload transport barrier version {version}"
                ));
            }
        }
        let (sent_bytes, sent_frames, byte_limit, frame_limit) = if bulk {
            (
                state.position.bulk_bytes,
                state.position.bulk_frames,
                state.credit.bulk_bytes,
                state.credit.bulk_frames,
            )
        } else {
            (
                state.position.control_bytes,
                state.position.control_frames,
                state.credit.control_bytes,
                state.credit.control_frames,
            )
        };
        let next_bytes = sent_bytes
            .checked_add(bytes as u64)
            .ok_or("transport byte counter overflow")?;
        let next_frames = sent_frames
            .checked_add(1)
            .ok_or("transport frame counter overflow")?;
        if next_bytes > byte_limit || next_frames > frame_limit {
            return Ok(false);
        }
        if bulk {
            state.position.bulk_bytes = next_bytes;
            state.position.bulk_frames = next_frames;
        } else {
            state.position.control_bytes = next_bytes;
            state.position.control_frames = next_frames;
        }
        Ok(true)
    }

    pub(crate) fn update_credit(&self, credit: WorkloadTransportCredit) -> Result<(), String> {
        let mut state = self.state.lock().unwrap();
        let old = &state.credit;
        if credit.control_bytes < old.control_bytes
            || credit.control_frames < old.control_frames
            || credit.bulk_bytes < old.bulk_bytes
            || credit.bulk_frames < old.bulk_frames
        {
            return Err("workload transport credit regressed".into());
        }
        state.credit = credit;
        drop(state);
        self.changed.notify_waiters();
        Ok(())
    }

    pub(crate) fn restore(
        &self,
        position: WorkloadTransportPosition,
        credit: WorkloadTransportCredit,
        guest_bulk_bytes: u64,
    ) -> Result<(), String> {
        if position.control_bytes > credit.control_bytes
            || position.control_frames > credit.control_frames
            || position.bulk_bytes > credit.bulk_bytes
            || position.bulk_frames > credit.bulk_frames
        {
            return Err("captured workload input exceeds its credit limits".into());
        }
        let mut state = self.state.lock().unwrap();
        if state.active {
            return Err("cannot reseed an active workload transport".into());
        }
        state.position = position;
        state.credit = credit;
        state.guest_bulk_bytes = guest_bulk_bytes;
        Ok(())
    }

    pub(crate) fn observed_bulk(&self, wire_bytes: usize, tail: usize) -> Result<(), String> {
        let mut state = self.state.lock().unwrap();
        state.guest_bulk_bytes = state
            .guest_bulk_bytes
            .checked_add(wire_bytes as u64)
            .ok_or("guest bulk counter overflow")?;
        state.bulk_tail = tail;
        let needs_cut = state.gates != 0;
        drop(state);
        if needs_cut {
            self.changed.notify_waiters();
        }
        Ok(())
    }

    pub(crate) async fn wait_bulk_cut(&self, target: u64) -> Result<(), String> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let state = self.state.lock().unwrap();
                if state.closed {
                    return Err("workload transport closed".into());
                }
                if state.guest_bulk_bytes > target {
                    return Err("guest bulk crossed frozen transport cut".into());
                }
                if state.guest_bulk_bytes == target {
                    if state.bulk_tail != 0 {
                        return Err("guest bulk cut has an incomplete frame tail".into());
                    }
                    return Ok(());
                }
            }
            changed.await;
        }
    }

    pub(crate) async fn request(
        &self,
        mut message: Message,
        attempt: &str,
    ) -> Result<Message, String> {
        if !matches!(
            message.t,
            MessageType::WorkloadFreeze | MessageType::WorkloadThaw
        ) {
            return Err("non-lifecycle request on private workload channel".into());
        }
        message.id = WORKLOAD_CONTROL_ID;
        let mut data = Vec::new();
        codec::encode_to_buf(&message, &mut data).map_err(|error| error.to_string())?;
        let (tx, rx) = oneshot::channel();
        {
            let mut state = self.state.lock().unwrap();
            if !state.active || state.closed {
                return Err("workload transport closed".into());
            }
            // Do not reuse an abandoned operation until its actual reply has drained. Otherwise a
            // late acknowledgement could incorrectly complete a later attempt with the same ID.
            if state.pending.len() == PRIVATE_QUEUE_CAPACITY
                || state
                    .pending
                    .iter()
                    .any(|pending| pending.request == message.t && pending.attempt == attempt)
            {
                return Err("previous workload request has not drained".into());
            }
            self.tx
                .try_send(LifecycleWrite(Bytes::from(data)))
                .map_err(|error| error.to_string())?;
            state.pending.push(PendingReply {
                request: message.t,
                attempt: attempt.into(),
                reply: tx,
            });
        }
        rx.await
            .map_err(|_| "workload reply channel closed".to_string())?
    }

    /// Called before SDK routing. An SDK client cannot allocate this reserved correlation ID.
    pub(crate) fn requires_frozen_boundary(&self, message: &Message) -> Result<bool, String> {
        if message.t != MessageType::WorkloadFrozen {
            return Ok(false);
        }
        let frozen: WorkloadFrozen = message.payload().map_err(|error| error.to_string())?;
        Ok(self.state.lock().unwrap().pending.iter().any(|pending| {
            pending.request == MessageType::WorkloadFreeze
                && pending.attempt == frozen.attempt_id
                && !pending.reply.is_closed()
        }))
    }

    /// Consume only trusted reserved replies. A canceled operation still drains its acknowledgement.
    pub(crate) fn reply(&self, message: Message) -> Result<(), String> {
        if message.id != WORKLOAD_CONTROL_ID || message.flags != message.t.flags() {
            return Err("invalid private workload reply envelope".into());
        }
        if message.t == MessageType::WorkloadTransportCredit {
            return self.update_credit(message.payload().map_err(|error| error.to_string())?);
        }
        let (request, attempt) = match message.t {
            MessageType::WorkloadFrozen => (
                MessageType::WorkloadFreeze,
                message
                    .payload::<WorkloadFrozen>()
                    .map_err(|error| error.to_string())?
                    .attempt_id,
            ),
            MessageType::WorkloadThawed => (
                MessageType::WorkloadThaw,
                message
                    .payload::<WorkloadThawed>()
                    .map_err(|error| error.to_string())?
                    .attempt_id,
            ),
            MessageType::CoreError => {
                let error = message
                    .payload::<CoreError>()
                    .map_err(|error| error.to_string())?;
                let Some(request) = error
                    .offending_type
                    .as_deref()
                    .and_then(MessageType::from_wire_str)
                else {
                    return Err("private workload error omitted its operation".into());
                };
                let Some(failure) = error.workload_failure else {
                    return Err("private workload error omitted its attempt".into());
                };
                (request, failure.attempt_id)
            }
            _ => return Err("unexpected reserved workload reply".into()),
        };
        let mut state = self.state.lock().unwrap();
        if let Some(index) = state
            .pending
            .iter()
            .position(|pending| pending.request == request && pending.attempt == attempt)
        {
            let pending = state.pending.remove(index);
            let _ = pending.reply.send(Ok(message));
        }
        Ok(())
    }

    pub(crate) fn close(&self) {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        state.ordinary_writer = None;
        for pending in state.pending.drain(..) {
            let _ = pending.reply.send(Err("workload transport closed".into()));
        }
        drop(state);
        self.changed.notify_waiters();
    }
}

impl InputGate {
    /// Release only after confirmed thaw, or before any lifecycle request was admitted.
    pub(crate) fn release(&self) {
        if !self.released.swap(true, Ordering::AcqRel) {
            self.control.state.lock().unwrap().gates -= 1;
            self.control.changed.notify_waiters();
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for InputGate {
    fn drop(&mut self) {
        if !self.released.load(Ordering::Acquire) {
            // A dropped capture token without a confirmed thaw is an ambiguous guest state.
            // Never let cancellation turn that into permission to flush queued SDK input.
            self.control.fence();
            self.release();
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use microsandbox_protocol::core::{WorkloadFreeze, WorkloadThaw, WorkloadThawMode};

    fn transport() -> Arc<WorkloadControl> {
        let control = WorkloadControl::new();
        control.install_ready(
            9,
            Ready {
                workload_transport_barrier_version: Some(WORKLOAD_TRANSPORT_BARRIER_VERSION),
                ..Ready::default()
            },
            false,
        );
        control
    }

    #[test]
    fn input_gate_releases_explicitly_but_drop_fences() {
        let control = transport();
        let gate = control.gate();
        assert!(!control.admit(false, 1).unwrap());
        gate.release();
        gate.release();
        drop(gate);
        assert!(control.admit(false, 1).unwrap());
        drop(control.gate());
        assert!(!control.admit(false, 1).unwrap());
    }

    #[test]
    fn unsupported_private_contract_fails_instead_of_disabling_admission() {
        let control = WorkloadControl::new();
        control.install_ready(8, Ready::default(), false);
        assert!(control.admit(false, usize::MAX).unwrap());
        control.install_ready(
            9,
            Ready {
                workload_transport_barrier_version: Some(WORKLOAD_TRANSPORT_BARRIER_VERSION - 1),
                ..Default::default()
            },
            false,
        );
        assert!(control.admit(false, 1).unwrap_err().contains("unsupported"));
        assert!(control.admit(true, 1).unwrap_err().contains("unsupported"));
    }

    #[tokio::test]
    async fn stable_park_does_not_wake_its_own_waiter() {
        let control = transport();
        let gate = control.gate();
        control.park(false);
        let changed = control.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        control.park(false);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), changed)
                .await
                .is_err()
        );
        gate.release();
    }

    #[test]
    fn aggregate_credit_bounds_bytes_and_empty_frame_count() {
        let control = transport();
        assert!(
            control
                .admit(false, WORKLOAD_TRANSPORT_CONTROL_BYTES as usize)
                .unwrap()
        );
        assert!(!control.admit(false, 1).unwrap());
        let control = transport();
        for _ in 0..WORKLOAD_TRANSPORT_CONTROL_FRAMES {
            assert!(control.admit(false, 0).unwrap());
        }
        assert!(!control.admit(false, 0).unwrap());
    }

    #[tokio::test]
    async fn guest_bulk_cut_requires_complete_decoder_boundary() {
        let control = transport();
        control.observed_bulk(32, 1).unwrap();
        assert!(
            control
                .wait_bulk_cut(32)
                .await
                .unwrap_err()
                .contains("incomplete")
        );
        control.observed_bulk(0, 0).unwrap();
        control.wait_bulk_cut(32).await.unwrap();
        assert!(
            control
                .wait_bulk_cut(31)
                .await
                .unwrap_err()
                .contains("crossed")
        );
    }

    #[tokio::test]
    async fn canceled_reply_drains_before_same_attempt_can_be_reused() {
        let control = transport();
        let mut writes = control.start();
        let freeze = Message::with_payload(
            MessageType::WorkloadFreeze,
            0,
            &WorkloadFreeze {
                external_mount_tags: Vec::new(),
                attempt_id: "first".into(),
                host_input: WorkloadTransportPosition::default(),
            },
        )
        .unwrap();
        let task_control = Arc::clone(&control);
        let task_request = freeze.clone();
        let task = tokio::spawn(async move { task_control.request(task_request, "first").await });
        writes.recv().await.unwrap();
        task.abort();
        let _ = task.await;
        assert!(
            control
                .request(freeze.clone(), "first")
                .await
                .unwrap_err()
                .contains("not drained")
        );
        let stale = Message::with_payload(
            MessageType::WorkloadFrozen,
            WORKLOAD_CONTROL_ID,
            &WorkloadFrozen {
                external_mounts_synced: false,
                attempt_id: "first".into(),
                guest_bulk_bytes_target: 0,
                input_credit: WorkloadTransportCredit::default(),
            },
        )
        .unwrap();
        control.reply(stale).unwrap();
        let task_control = Arc::clone(&control);
        let thaw = Message::with_payload(
            MessageType::WorkloadThaw,
            0,
            &WorkloadThaw {
                attempt_id: "second".into(),
                mode: WorkloadThawMode::Continue,
            },
        )
        .unwrap();
        let task = tokio::spawn(async move { task_control.request(thaw, "second").await });
        writes.recv().await.unwrap();
        control
            .reply(
                Message::with_payload(
                    MessageType::WorkloadThawed,
                    WORKLOAD_CONTROL_ID,
                    &WorkloadThawed {
                        attempt_id: "first".into(),
                    },
                )
                .unwrap(),
            )
            .unwrap();
        assert!(!task.is_finished());
        control.close();
        assert!(task.await.unwrap().unwrap_err().contains("closed"));
    }

    #[test]
    fn restored_position_retains_outstanding_debt_and_credit_is_idempotent() {
        let control = transport();
        let position = WorkloadTransportPosition {
            control_bytes: 100,
            control_frames: 2,
            ..Default::default()
        };
        let credit = WorkloadTransportCredit {
            control_bytes: 110,
            control_frames: 3,
            ..Default::default()
        };
        control.restore(position, credit, 0).unwrap();
        assert!(control.admit(false, 10).unwrap());
        control.update_credit(credit).unwrap();
        assert!(!control.admit(false, 1).unwrap());
        assert!(
            control
                .update_credit(WorkloadTransportCredit::default())
                .is_err()
        );
    }
}
