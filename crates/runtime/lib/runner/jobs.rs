//! Runtime-owned execution and bounded attachment leases.
//!
//! The control dispatcher only admits work. Guest I/O lives in independent tasks, so an idle
//! command or paused VM cannot hold the host lifecycle dispatcher hostage.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use microsandbox_agent_client::{AgentClient, ExecController, TypedMessage};
use microsandbox_protocol::exec::{
    ExecExited, ExecFailed, ExecRequest, ExecResize, ExecStarted, ExecStderr, ExecStdin,
    ExecStdinError, ExecStdout,
};
use microsandbox_protocol::jobs::*;
use microsandbox_protocol::message::MessageType;
use sha2::{Digest as _, Sha256};
use tokio::sync::mpsc;

use crate::jobs::{JobStore, StoredJob};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const OUTPUT_BYTES: usize = 1024 * 1024;
const ATTACHMENT_LIFETIME: Duration = Duration::from_secs(30);
const MAX_ATTACHMENTS: usize = 16;
const INPUT_QUEUE: usize = 8;
// Bound deduplication memory without ever replaying an evicted launch in this runtime.
const MAX_ADMISSIONS: usize = 65_536;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(crate) struct JobManager {
    boot_id: String,
    agent_path: PathBuf,
    runtime: tokio::runtime::Handle,
    store: JobStore,
    entries: Mutex<BTreeMap<JobId, Entry>>,
    admitted: Mutex<BTreeSet<JobId>>,
    initialization_error: Option<String>,
}

struct Entry {
    record: StoredJob,
    output: VecDeque<JobOutput>,
    output_bytes: usize,
    capture_error: Option<String>,
    sequence: u64,
    input: Option<mpsc::Sender<Input>>,
    control: Option<mpsc::Sender<Control>>,
    resize: Option<mpsc::Sender<(u16, u16)>>,
    attachments: BTreeMap<String, Attachment>,
}

struct Attachment {
    read_only: bool,
    expires: Instant,
}

enum Input {
    Data(Vec<u8>),
    Eof,
}

enum Control {
    Signal(i32),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Entry {
    fn retain_output(&mut self, record: JobOutput) {
        self.output_bytes += output_memory_bytes(&record);
        self.output.push_back(record);
        while self.output_bytes > OUTPUT_BYTES {
            if let Some(pruned) = self.output.pop_front() {
                self.output_bytes -= output_memory_bytes(&pruned);
            }
        }
    }

    fn preserve_capture_error(&mut self) {
        if let Some(capture) = &self.capture_error
            && self
                .record
                .info
                .error
                .as_ref()
                .is_none_or(|error| !error.contains(capture))
        {
            self.record.info.error = Some(match self.record.info.error.take() {
                Some(error) => format!("{capture}; {error}"),
                None => capture.clone(),
            });
        }
        if let Some(error) = &mut self.record.info.error {
            truncate_diagnostic(error, 4096);
        }
    }
}

impl JobManager {
    pub(crate) fn open(
        boot_id: String,
        sandbox_directory: &Path,
        agent_path: &Path,
        runtime: tokio::runtime::Handle,
    ) -> Result<Arc<Self>, String> {
        let store = JobStore::new(sandbox_directory);
        let recovered = (|| -> Result<BTreeMap<JobId, Entry>, String> {
            let mut entries = BTreeMap::new();
            for mut record in store.list().map_err(|e| e.to_string())? {
                if record.info.state.is_active() {
                    record.info.state = JobState::Lost;
                    record.info.finished_at = Some(now());
                    record.info.error =
                        Some("previous runtime ended without a confirmed job exit".into());
                    store.write(&record).map_err(|e| e.to_string())?;
                }
                // Completed histories stay on disk; only active jobs need a resident output ring.
                let output = VecDeque::new();
                let sequence = 0;
                let output_bytes = 0;
                entries.insert(
                    record.info.id.clone(),
                    Entry {
                        record,
                        output,
                        output_bytes,
                        capture_error: None,
                        sequence,
                        input: None,
                        control: None,
                        resize: None,
                        attachments: BTreeMap::new(),
                    },
                );
            }
            Ok(entries)
        })();
        // Optional job history must never prevent an ordinary sandbox from booting.
        let (entries, initialization_error) = match recovered {
            Ok(entries) => (entries, None),
            Err(error) => (BTreeMap::new(), Some(error)),
        };
        Ok(Arc::new(Self {
            initialization_error,
            boot_id,
            agent_path: agent_path.into(),
            runtime,
            store,
            admitted: Mutex::new(entries.keys().cloned().collect()),
            entries: Mutex::new(entries),
        }))
    }

    pub(crate) fn active(&self) -> bool {
        self.entries
            .lock()
            .unwrap()
            .values()
            .any(|entry| entry.record.info.state.is_active())
    }

    /// Caller holds lifecycle admission, so Start cannot race a capture or resident pause.
    pub(crate) fn request(self: &Arc<Self>, request: JobRequest, running: bool) -> JobResponse {
        if let Some(error) = &self.initialization_error {
            return JobResponse::error(
                "history_error",
                format!("managed job history could not be recovered: {error}"),
            );
        }
        if request.version != JOB_PROTOCOL_VERSION {
            return JobResponse::error(
                "unsupported_feature",
                "unsupported managed-job protocol version",
            );
        }
        if matches!(request.operation, JobOperation::Hello) {
            return JobResponse::Hello {
                version: JOB_PROTOCOL_VERSION,
                runtime_boot_id: self.boot_id.clone(),
            };
        }
        if request.runtime_boot_id.as_deref() != Some(self.boot_id.as_str()) {
            return JobResponse::error(
                "runtime_changed",
                "job request targets a different runtime generation",
            );
        }
        if let JobOperation::Start {
            id,
            command,
            no_stdin,
            input_base64,
            timeout_ms,
        } = request.operation
        {
            return self.start(id, command, no_stdin, input_base64, timeout_ms, running);
        }
        let mut entries = self.entries.lock().unwrap();
        if let JobOperation::List { all, limit, cursor } = request.operation {
            if !(1..=100).contains(&limit) {
                return JobResponse::error(
                    "invalid_options",
                    "job page size must be between 1 and 100",
                );
            }
            let items = entries
                .values()
                .filter(|entry| {
                    (all || entry.record.info.state.is_active())
                        && cursor
                            .as_ref()
                            .is_none_or(|cursor| entry.record.info.id > *cursor)
                })
                .map(|entry| entry.record.info.clone());
            return match JobPage::bounded(items, limit) {
                Ok(page) => JobResponse::Page { page },
                Err(error) => JobResponse::error("history_error", error.to_string()),
            };
        }
        let id = match &request.operation {
            JobOperation::Inspect { id }
            | JobOperation::Read { id, .. }
            | JobOperation::Attach { id, .. }
            | JobOperation::Detach { id, .. }
            | JobOperation::Renew { id, .. }
            | JobOperation::Write { id, .. }
            | JobOperation::Resize { id, .. }
            | JobOperation::Signal { id, .. }
            | JobOperation::Eof { id } => id,
            _ => return JobResponse::error("unsupported_feature", "unsupported job operation"),
        };
        let Some(entry) = entries.get_mut(id) else {
            return JobResponse::error("job_not_found", "job was not found or its history expired");
        };
        entry
            .attachments
            .retain(|_, attachment| attachment.expires > Instant::now());
        match request.operation {
            JobOperation::Inspect { .. } => JobResponse::Info {
                info: entry.record.info.clone(),
            },
            JobOperation::Read {
                after, attachment, ..
            } => {
                if let Some(token) = attachment {
                    let Some(lease) = entry.attachments.get_mut(&token) else {
                        return JobResponse::error(
                            "attachment_expired",
                            "attachment no longer owns a lease",
                        );
                    };
                    lease.expires = Instant::now() + ATTACHMENT_LIFETIME;
                }
                if !entry.record.info.state.is_active() {
                    let info = entry.record.info.clone();
                    drop(entries);
                    return match self.store.output(&info.id) {
                        Ok(records) => {
                            let gap_before = records
                                .first()
                                .filter(|item| after.saturating_add(1) < item.sequence)
                                .map(|item| item.sequence);
                            let items: Vec<_> = records
                                .into_iter()
                                .filter(|item| item.sequence > after)
                                .take(4)
                                .collect();
                            let cursor = items.last().map_or(after, |item| item.sequence);
                            JobResponse::Output {
                                page: JobOutputPage {
                                    items,
                                    cursor,
                                    gap_before,
                                    info,
                                },
                            }
                        }
                        Err(error) => JobResponse::error("history_error", error.to_string()),
                    };
                }
                let items: Vec<_> = entry
                    .output
                    .iter()
                    .filter(|item| item.sequence > after)
                    .take(4)
                    .cloned()
                    .collect();
                let cursor = items.last().map_or(after, |item| item.sequence);
                let gap_before = entry
                    .output
                    .front()
                    .filter(|item| after.saturating_add(1) < item.sequence)
                    .map(|item| item.sequence);
                JobResponse::Output {
                    page: JobOutputPage {
                        items,
                        cursor,
                        gap_before,
                        info: entry.record.info.clone(),
                    },
                }
            }
            JobOperation::Attach {
                attachment,
                read_only,
                ..
            } => {
                if !valid_token(&attachment) {
                    return JobResponse::error("invalid_options", "invalid attachment token");
                }
                if !read_only
                    && (!entry.record.info.state.is_active() || entry.record.info.stdin_closed)
                {
                    return JobResponse::error(
                        "stdin_closed",
                        "job input is unavailable; attach read-only or read its logs",
                    );
                }
                if let Some(existing) = entry.attachments.get(&attachment) {
                    if existing.read_only != read_only {
                        return JobResponse::error(
                            "request_id_conflict",
                            "attachment token was already used with different options",
                        );
                    }
                } else if entry.attachments.len() >= MAX_ATTACHMENTS {
                    return JobResponse::error(
                        "resource_limit",
                        "too many attachments for this job",
                    );
                }
                if !read_only
                    && entry
                        .attachments
                        .iter()
                        .any(|(token, lease)| token != &attachment && !lease.read_only)
                {
                    return JobResponse::error(
                        "input_busy",
                        "another attachment owns this job's input",
                    );
                }
                entry.attachments.insert(
                    attachment,
                    Attachment {
                        read_only,
                        expires: Instant::now() + ATTACHMENT_LIFETIME,
                    },
                );
                let info = entry.record.info.clone();
                let mut cursor = entry.sequence;
                drop(entries);
                if !info.state.is_active() {
                    match self.store.output(&info.id) {
                        Ok(records) => cursor = records.last().map_or(0, |item| item.sequence),
                        Err(error) => {
                            return JobResponse::error("history_error", error.to_string());
                        }
                    }
                }
                JobResponse::Attached { info, cursor }
            }
            JobOperation::Detach { attachment, .. } => {
                entry.attachments.remove(&attachment);
                JobResponse::Ok
            }
            JobOperation::Renew { attachment, .. } => {
                if let Some(lease) = entry.attachments.get_mut(&attachment) {
                    lease.expires = Instant::now() + ATTACHMENT_LIFETIME;
                    JobResponse::Ok
                } else {
                    JobResponse::error("attachment_expired", "attachment lease expired")
                }
            }
            JobOperation::Write {
                attachment,
                data_base64,
                ..
            } => {
                if !owns_input(entry, &attachment) {
                    return JobResponse::error(
                        "input_not_owned",
                        "attachment does not own job input",
                    );
                }
                if entry.record.info.stdin_closed {
                    return JobResponse::error("stdin_closed", "job stdin is permanently closed");
                }
                if data_base64.len() > JOB_CHUNK_BYTES * 2 {
                    return JobResponse::error("invalid_options", "input chunk is too large");
                }
                match STANDARD.decode(data_base64) {
                    Ok(data) if data.len() <= JOB_CHUNK_BYTES => {
                        if data.is_empty() {
                            JobResponse::Ok
                        } else {
                            enqueue(entry, Input::Data(data))
                        }
                    }
                    _ => JobResponse::error("invalid_options", "invalid input bytes or chunk size"),
                }
            }
            JobOperation::Resize {
                attachment,
                rows,
                cols,
                ..
            } => {
                if !owns_input(entry, &attachment) {
                    return JobResponse::error(
                        "input_not_owned",
                        "attachment does not own job input",
                    );
                }
                if !entry.record.info.tty || rows == 0 || cols == 0 {
                    return JobResponse::error(
                        "invalid_options",
                        "resize requires a PTY and nonzero dimensions",
                    );
                }
                enqueue_control(entry, entry.resize.as_ref(), (rows, cols))
            }
            JobOperation::Signal { signal, .. } => {
                if !(1..=64).contains(&signal) {
                    return JobResponse::error(
                        "invalid_options",
                        "guest signal must be between 1 and 64",
                    );
                }
                enqueue_control(entry, entry.control.as_ref(), Control::Signal(signal))
            }
            JobOperation::Eof { .. } => {
                if entry.record.info.tty {
                    return JobResponse::error(
                        "invalid_options",
                        "eof applies to pipes; use terminal Ctrl-D for a PTY",
                    );
                }
                if entry.record.info.stdin_closed {
                    return JobResponse::Ok;
                }
                let response = enqueue(entry, Input::Eof);
                if matches!(response, JobResponse::Ok) {
                    entry.record.info.stdin_closed = true;
                    if let Err(error) = self.store.write(&entry.record) {
                        return JobResponse::error("persistence_failed", error.to_string());
                    }
                }
                response
            }
            _ => JobResponse::error("unsupported_feature", "unsupported job operation"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn start(
        self: &Arc<Self>,
        id: JobId,
        command: ExecRequest,
        no_stdin: bool,
        input_base64: Option<String>,
        timeout_ms: Option<u64>,
        running: bool,
    ) -> JobResponse {
        let bytes = match serde_json::to_vec(&(&command, no_stdin, &input_base64, timeout_ms)) {
            Ok(bytes) => bytes,
            Err(_) => return JobResponse::error("invalid_options", "invalid exec request"),
        };
        if bytes.len() > 128 * 1024
            || command.cmd.is_empty()
            || serde_json::to_vec(&(&command.cmd, &command.args))
                .map_or(true, |bytes| bytes.len() > 16 * 1024)
            || command.tty && no_stdin
            || timeout_ms == Some(0)
        {
            return JobResponse::error(
                "invalid_options",
                "invalid command size, stdin/PTY combination, or timeout",
            );
        }
        let initial_input = match input_base64 {
            Some(value) => match STANDARD.decode(value) {
                Ok(bytes) if bytes.len() <= 64 * 1024 && !command.tty && !no_stdin => Some(bytes),
                _ => {
                    return JobResponse::error(
                        "invalid_options",
                        "finite input requires pipes and at most 64 KiB",
                    );
                }
            },
            None => None,
        };
        let fingerprint = hex::encode(Sha256::digest(&bytes));
        let mut entries = self.entries.lock().unwrap();
        if let Some(entry) = entries.get(&id) {
            return if entry.record.fingerprint == fingerprint {
                JobResponse::Info {
                    info: entry.record.info.clone(),
                }
            } else {
                JobResponse::error(
                    "request_id_conflict",
                    "job identity was already used for a different command",
                )
            };
        }
        let mut admitted = self.admitted.lock().unwrap();
        if admitted.contains(&id) {
            return JobResponse::error(
                "job_expired",
                "this launch was already admitted and its history expired",
            );
        }
        if admitted.len() >= MAX_ADMISSIONS {
            return JobResponse::error(
                "resource_limit",
                "runtime admission history is full; restart the sandbox before launching more jobs",
            );
        }
        if !running {
            return JobResponse::error(
                "sandbox_not_running",
                "detached launch requires a running, unpaused sandbox",
            );
        }
        if entries
            .values()
            .filter(|entry| entry.record.info.state.is_active())
            .count()
            >= MAX_ACTIVE_JOBS
        {
            return JobResponse::error(
                "resource_limit",
                "sandbox has reached its active-job limit",
            );
        }
        while entries.len() >= MAX_RETAINED_JOBS {
            let oldest = entries
                .iter()
                .filter(|(_, entry)| {
                    !entry.record.info.state.is_active()
                        && entry
                            .attachments
                            .values()
                            .all(|lease| lease.expires <= Instant::now())
                })
                .min_by_key(|(_, entry)| entry.record.info.created_at)
                .map(|(id, _)| id.clone());
            let Some(oldest) = oldest else {
                return JobResponse::error(
                    "resource_limit",
                    "no completed job is eligible for pruning",
                );
            };
            if let Err(error) = self.store.remove(&oldest) {
                return JobResponse::error("persistence_failed", error.to_string());
            }
            entries.remove(&oldest);
        }
        let record = StoredJob {
            info: JobInfo::starting(
                id.clone(),
                self.boot_id.clone(),
                &command,
                no_stdin || initial_input.is_some(),
                now(),
            ),
            fingerprint,
        };
        if let Err(error) = self.store.write(&record) {
            return JobResponse::error("persistence_failed", error.to_string());
        }
        let info = record.info.clone();
        let (input, receiver) = mpsc::channel(INPUT_QUEUE);
        let (control, controls) = mpsc::channel(INPUT_QUEUE);
        let (resize, resizes) = mpsc::channel(INPUT_QUEUE);
        admitted.insert(id.clone());
        drop(admitted);
        entries.insert(
            id.clone(),
            Entry {
                record,
                output: VecDeque::new(),
                output_bytes: 0,
                capture_error: None,
                sequence: 0,
                input: Some(input),
                control: Some(control),
                resize: Some(resize),
                attachments: BTreeMap::new(),
            },
        );
        drop(entries);
        let manager = self.clone();
        self.runtime.spawn(async move {
            manager
                .run(
                    id,
                    command,
                    no_stdin,
                    initial_input,
                    timeout_ms,
                    receiver,
                    controls,
                    resizes,
                )
                .await;
        });
        JobResponse::Info { info }
    }

    fn update(&self, id: &JobId, change: impl FnOnce(&mut JobInfo)) {
        let mut entries = self.entries.lock().unwrap();
        if let Some(entry) = entries.get_mut(id) {
            change(&mut entry.record.info);
            // Guest diagnostics must fit durable metadata and the pre-reserved control reply.
            entry.preserve_capture_error();
            if let Some(failure) = &mut entry.record.info.failure {
                truncate_diagnostic(&mut failure.message, 4096);
                if let Some(stage) = &mut failure.stage {
                    truncate_diagnostic(stage, 1024);
                }
                if let Some(errno) = &mut failure.errno_name {
                    truncate_diagnostic(errno, 64);
                }
            }
            if !entry.record.info.state.is_active() {
                entry.input = None;
                entry.control = None;
                entry.resize = None;
                entry.output.clear();
                entry.output_bytes = 0;
            }
            if let Err(error) = self.store.write(&entry.record) {
                // Keep live ownership even if a disk write fails; inspection reports the failure.
                entry.record.info.error = Some(format!("persist job state: {error}"));
                entry.preserve_capture_error();
            }
        }
    }

    fn stop_output_capture(&self, id: &JobId, sequence: u64, error: &std::io::Error) {
        if let Some(entry) = self.entries.lock().unwrap().get_mut(id) {
            let mut diagnostic = format!(
                "job output capture stopped before sequence {sequence}: {error}; \
                 later output is live-only and will not be retained"
            );
            truncate_diagnostic(&mut diagnostic, 2048);
            entry.capture_error = Some(diagnostic);
        }
        // A full disk can also prevent saving metadata. Keep the cutoff in live state and
        // retry its persistence on later lifecycle updates without interrupting the process.
        self.update(id, |_| {});
    }

    #[allow(clippy::too_many_arguments)]
    async fn run(
        self: Arc<Self>,
        id: JobId,
        command: ExecRequest,
        no_stdin: bool,
        initial_input: Option<Vec<u8>>,
        timeout_ms: Option<u64>,
        mut input: mpsc::Receiver<Input>,
        mut controls: mpsc::Receiver<Control>,
        mut resizes: mpsc::Receiver<(u16, u16)>,
    ) {
        let outcome: Result<(), String> = async {
            let mut writer = Some(self.store.writer(&id).map_err(|e| e.to_string())?);
            let client = AgentClient::connect(&self.agent_path)
                .await
                .map_err(|e| e.to_string())?;
            let controller = ExecController::from_ready_body(client.ready().ready_bytes())
                .map_err(|error| error.to_string())?
                .ok_or("guest lacks managed execution control support")?;
            let stream = client
                .stream(TypedMessage::new(MessageType::ExecRequest, &command))
                .await
                .map_err(|e| e.to_string())?;
            let (sender, mut output) = stream.into_parts();
            let (started_tx, started_rx) = tokio::sync::watch::channel(false);
            let mut control_started = started_rx.clone();
            let control_sender = sender.clone();
            let control_manager = self.clone();
            let control_id = id.clone();
            let mut resize_started = started_rx.clone();
            let resize_sender = sender.clone();
            let resize_worker = tokio::spawn(async move {
                if resize_started.wait_for(|started| *started).await.is_err() {
                    return;
                }
                while let Some((rows, cols)) = resizes.recv().await {
                    if resize_sender
                        .send(TypedMessage::new(
                            MessageType::ExecResize,
                            &ExecResize { rows, cols },
                        ))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
            let _resize_guard = tokio_util::task::AbortOnDropHandle::new(resize_worker);
            // Independent tasks alone are insufficient: signals must also bypass the shared
            // AgentClient writer and input socket when the relay stops admitting stdin. Resize
            // has its own bounded worker so a blocked resize cannot hold up later termination.
            let control_worker = tokio::spawn(async move {
                if control_started.wait_for(|started| *started).await.is_err() {
                    return;
                }
                while let Some(control) = controls.recv().await {
                    match control {
                        Control::Signal(signal) => {
                            if let Err(error) = controller.signal(control_sender.id(), signal).await
                            {
                                control_manager.update(&control_id, |info| {
                                    info.error = Some(format!("signal delivery failed: {error}"));
                                });
                            }
                        }
                    }
                }
            });
            let _control_guard = tokio_util::task::AbortOnDropHandle::new(control_worker);
            // Input and output are independent: a blocked guest stdin must never stop output drain.
            let input_worker = tokio::spawn(async move {
                let mut started_rx = started_rx;
                if started_rx.wait_for(|started| *started).await.is_err() {
                    return;
                }
                if let Some(bytes) = initial_input.as_ref() {
                    for data in bytes.chunks(JOB_CHUNK_BYTES) {
                        if sender
                            .send(TypedMessage::new(
                                MessageType::ExecStdin,
                                &ExecStdin {
                                    data: data.to_vec(),
                                },
                            ))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                }
                if (no_stdin || initial_input.is_some())
                    && sender
                        .send(TypedMessage::new(
                            MessageType::ExecStdin,
                            &ExecStdin { data: Vec::new() },
                        ))
                        .await
                        .is_err()
                {
                    return;
                }
                while let Some(item) = input.recv().await {
                    let result = match item {
                        Input::Data(data) => {
                            sender
                                .send(TypedMessage::new(
                                    MessageType::ExecStdin,
                                    &ExecStdin { data },
                                ))
                                .await
                        }
                        Input::Eof => {
                            sender
                                .send(TypedMessage::new(
                                    MessageType::ExecStdin,
                                    &ExecStdin { data: Vec::new() },
                                ))
                                .await
                        }
                    };
                    if result.is_err() {
                        break;
                    }
                }
            });
            // Dropping this guard cancels the input sender on every exit/error path.
            let _input_guard = tokio_util::task::AbortOnDropHandle::new(input_worker);
            let mut started_tx = Some(started_tx);
            let mut timeout_task = None;
            let mut stdin_failure_recorded = false;
            while let Some(message) = output.recv().await.map_err(|e| e.to_string())? {
                let mut captured = None;
                match MessageType::from_wire_str(&message.t) {
                    Some(MessageType::ExecStarted) => {
                        let started = message
                            .payload::<ExecStarted>()
                            .map_err(|e| e.to_string())?;
                        self.update(&id, |info| {
                            info.pid = Some(started.pid);
                            info.started_at = Some(now());
                            info.state = JobState::Running;
                        });
                        if let Some(sender) = started_tx.take() {
                            let _ = sender.send(true);
                        }
                        if let Some(milliseconds) = timeout_ms {
                            let manager = self.clone();
                            let id = id.clone();
                            timeout_task = Some(tokio_util::task::AbortOnDropHandle::new(
                                tokio::spawn(async move {
                                    tokio::time::sleep(Duration::from_millis(milliseconds)).await;
                                    manager.update(&id, |info| {
                                        if info.state.is_active() {
                                            info.timed_out = true;
                                        }
                                    });
                                    let sender = manager
                                        .entries
                                        .lock()
                                        .unwrap()
                                        .get(&id)
                                        .and_then(|entry| entry.control.clone());
                                    if let Some(sender) = sender {
                                        let _ = sender.send(Control::Signal(9)).await;
                                    }
                                }),
                            ));
                        }
                    }
                    Some(MessageType::ExecStdout) => {
                        let payload = message.payload::<ExecStdout>().map_err(|e| e.to_string())?;
                        captured =
                            Some((if command.tty { "output" } else { "stdout" }, payload.data));
                    }
                    Some(MessageType::ExecStderr) => {
                        let payload = message.payload::<ExecStderr>().map_err(|e| e.to_string())?;
                        captured = Some(("stderr", payload.data));
                    }
                    Some(MessageType::ExecStdinError) => {
                        let payload = message
                            .payload::<ExecStdinError>()
                            .map_err(|e| e.to_string())?;
                        if payload.errno == Some(32) && !stdin_failure_recorded {
                            // EPIPE is a permanent loss of the guest reader, not a detachable lease.
                            // Saturated input can produce one error per queued chunk. Persist this
                            // transition once so repeated fsyncs cannot delay the following exit;
                            // every error still reaches the output log below.
                            stdin_failure_recorded = true;
                            self.update(&id, |info| info.stdin_closed = true);
                        }
                        captured = Some(("stdin_error", payload.message.into_bytes()));
                    }
                    Some(MessageType::ExecExited) => {
                        let exited = message.payload::<ExecExited>().map_err(|e| e.to_string())?;
                        self.update(&id, |info| {
                            info.state = JobState::Exited;
                            info.exit_code = Some(exited.code);
                            info.finished_at = Some(now());
                        });
                        drop(timeout_task);
                        return Ok(());
                    }
                    Some(MessageType::ExecFailed) => {
                        let failure = message.payload::<ExecFailed>().map_err(|e| e.to_string())?;
                        self.update(&id, |info| {
                            info.state = JobState::Failed;
                            info.failure = Some(failure);
                            info.finished_at = Some(now());
                        });
                        return Ok(());
                    }
                    _ => {}
                }
                if let Some((source, bytes)) = captured {
                    for bytes in bytes.chunks(JOB_CHUNK_BYTES) {
                        let mut entries = self.entries.lock().unwrap();
                        let entry = entries.get_mut(&id).ok_or("active job disappeared")?;
                        entry.sequence += 1;
                        let record = JobOutput::new(
                            entry.sequence,
                            now(),
                            source.into(),
                            STANDARD.encode(bytes),
                        );
                        entry.retain_output(record.clone());
                        drop(entries);
                        // Only the runtime actor writes output. Slow attached readers never own this path.
                        if let Some(active_writer) = writer.as_mut()
                            && let Err(error) = active_writer.append(&record)
                        {
                            writer = None;
                            self.stop_output_capture(&id, record.sequence, &error);
                        }
                    }
                }
            }
            Err("job agent connection ended without a terminal result".into())
        }
        .await;
        if let Err(error) = outcome {
            self.update(&id, |info| {
                if info.state.is_active() {
                    info.state = JobState::Lost;
                    info.finished_at = Some(now());
                    info.error = Some(error);
                }
            });
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn now() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn output_memory_bytes(record: &JobOutput) -> usize {
    // Tiny writes still allocate a record and two strings. Charge those allocations too,
    // with room for the deque's spare slots, so payload size cannot hide unbounded overhead.
    2 * std::mem::size_of::<JobOutput>() + record.source.capacity() + record.data_base64.capacity()
}

fn truncate_diagnostic(value: &mut String, limit: usize) {
    if value.len() > limit {
        let mut end = limit - " [truncated]".len();
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        value.truncate(end);
        value.push_str(" [truncated]");
    }
}

fn valid_token(token: &str) -> bool {
    token.len() == 32 && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn owns_input(entry: &mut Entry, token: &str) -> bool {
    if let Some(lease) = entry.attachments.get_mut(token)
        && !lease.read_only
    {
        lease.expires = Instant::now() + ATTACHMENT_LIFETIME;
        return true;
    }
    false
}

fn enqueue(entry: &Entry, input: Input) -> JobResponse {
    if !entry.record.info.state.is_active() {
        return JobResponse::error("job_not_running", "job no longer owns a running process");
    }
    match entry.input.as_ref().map(|sender| sender.try_send(input)) {
        Some(Ok(())) => JobResponse::Ok,
        Some(Err(mpsc::error::TrySendError::Full(_))) => JobResponse::error(
            "input_busy",
            "job input queue is full; retry after making progress",
        ),
        _ => JobResponse::error("job_not_running", "job input connection is unavailable"),
    }
}

fn enqueue_control<T>(entry: &Entry, sender: Option<&mpsc::Sender<T>>, control: T) -> JobResponse {
    if !entry.record.info.state.is_active() {
        return JobResponse::error("job_not_running", "job no longer owns a running process");
    }
    match sender.map(|sender| sender.try_send(control)) {
        Some(Ok(())) => JobResponse::Ok,
        Some(Err(mpsc::error::TrySendError::Full(_))) => JobResponse::error(
            "control_busy",
            "job control queue is full; retry after making progress",
        ),
        _ => JobResponse::error("job_not_running", "job control connection is unavailable"),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u64) -> JobId {
        JobId::parse(format!("job_{n:032x}")).unwrap()
    }
    fn command() -> ExecRequest {
        serde_json::from_value(serde_json::json!({ "cmd": "cat" })).unwrap()
    }
    fn manager(directory: &Path) -> Arc<JobManager> {
        JobManager::open(
            "boot-one".into(),
            directory,
            &directory.join("absent-agent.sock"),
            tokio::runtime::Handle::current(),
        )
        .unwrap()
    }
    fn request(manager: &Arc<JobManager>, operation: JobOperation) -> JobResponse {
        manager.request(
            JobRequest {
                version: JOB_PROTOCOL_VERSION,
                runtime_boot_id: Some("boot-one".into()),
                operation,
            },
            true,
        )
    }
    fn start(manager: &Arc<JobManager>, n: u64) -> JobResponse {
        request(
            manager,
            JobOperation::Start {
                id: id(n),
                command: command(),
                no_stdin: false,
                input_base64: None,
                timeout_ms: None,
            },
        )
    }
    fn error_code(response: JobResponse) -> String {
        match response {
            JobResponse::Error { code, .. } => code,
            other => panic!("expected error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn capture_cutoff_survives_metadata_failure_and_terminal_updates() {
        let directory = tempfile::tempdir().unwrap();
        let manager = manager(directory.path());
        start(&manager, 1);
        let blocker = directory
            .path()
            .join("jobs-v1")
            .join(id(1).as_str())
            .join("info.next");
        std::fs::create_dir(&blocker).unwrap();
        manager.stop_output_capture(&id(1), 7, &std::io::Error::other("disk full"));
        {
            let mut entries = manager.entries.lock().unwrap();
            let entry = entries.get_mut(&id(1)).unwrap();
            let error = entry.record.info.error.as_deref().unwrap();
            assert!(error.contains("stopped before sequence 7"));
            assert!(error.contains("persist job state"));
            assert!(entry.record.info.state.is_active());
            assert!(entry.input.is_some());
            assert!(entry.control.is_some());
            entry.sequence = 8;
            entry.retain_output(JobOutput::new(8, 1, "stdout".into(), "YQ==".into()));
        }
        let JobResponse::Output { page } = request(
            &manager,
            JobOperation::Read {
                id: id(1),
                after: 7,
                attachment: None,
            },
        ) else {
            panic!("live output must remain readable")
        };
        assert_eq!(page.items[0].sequence, 8);
        std::fs::remove_dir(blocker).unwrap();
        manager.update(&id(1), |info| {
            info.state = JobState::Exited;
            info.exit_code = Some(0);
            info.error = Some("another diagnostic".into());
        });
        let info = manager.store.read(&id(1)).unwrap().info;
        assert_eq!(info.exit_code, Some(0));
        let error = info.error.unwrap();
        assert!(error.contains("stopped before sequence 7"));
        assert!(error.contains("another diagnostic"));
        manager.update(&id(1), |_| {});
        assert_eq!(
            manager.store.read(&id(1)).unwrap().info.error.unwrap(),
            error
        );
    }

    #[tokio::test]
    async fn tiny_output_keeps_memory_bounded_and_reports_pruned_replay() {
        let directory = tempfile::tempdir().unwrap();
        let manager = manager(directory.path());
        start(&manager, 1);
        let mut entries = manager.entries.lock().unwrap();
        let entry = entries.get_mut(&id(1)).unwrap();
        for sequence in 1..=OUTPUT_BYTES as u64 / 4 {
            entry.sequence = sequence;
            entry.retain_output(JobOutput::new(
                sequence,
                1,
                "stdout".into(),
                STANDARD.encode(b"x"),
            ));
        }
        assert!(entry.output_bytes <= OUTPUT_BYTES);
        assert!(entry.output.len() < 8192);
        assert_eq!(
            entry.output_bytes,
            entry.output.iter().map(output_memory_bytes).sum::<usize>()
        );
        let first = entry.output.front().unwrap().sequence;
        assert!(first > 1);
        assert_eq!(entry.output.back().unwrap().sequence, entry.sequence);
        assert_eq!(entry.output.len() as u64, entry.sequence - first + 1);
        drop(entries);
        let JobResponse::Output { page } = request(
            &manager,
            JobOperation::Read {
                id: id(1),
                after: 0,
                attachment: None,
            },
        ) else {
            panic!("expected retained output page");
        };
        assert_eq!(page.gap_before, Some(first));
        assert_eq!(page.items[0].sequence, first);
    }

    #[tokio::test]
    async fn launch_is_fenced_and_deduplicated_even_after_pruning() {
        let directory = tempfile::tempdir().unwrap();
        let manager = manager(directory.path());
        let stale = manager.request(
            JobRequest {
                version: JOB_PROTOCOL_VERSION,
                runtime_boot_id: Some("previous".into()),
                operation: JobOperation::Start {
                    id: id(1),
                    command: command(),
                    no_stdin: false,
                    input_base64: None,
                    timeout_ms: None,
                },
            },
            true,
        );
        assert_eq!(error_code(stale), "runtime_changed");
        assert!(manager.entries.lock().unwrap().is_empty());
        assert!(matches!(start(&manager, 1), JobResponse::Info { .. }));
        assert!(matches!(start(&manager, 1), JobResponse::Info { .. }));
        assert_eq!(manager.entries.lock().unwrap().len(), 1);
        let mut changed = command();
        changed.cmd = "another".into();
        assert_eq!(
            error_code(request(
                &manager,
                JobOperation::Start {
                    id: id(1),
                    command: changed,
                    no_stdin: false,
                    input_base64: None,
                    timeout_ms: None
                }
            )),
            "request_id_conflict"
        );
        manager.entries.lock().unwrap().remove(&id(1));
        assert_eq!(error_code(start(&manager, 1)), "job_expired");
    }

    #[tokio::test]
    async fn lease_exclusion_detach_and_signal_bypass_stdin_backpressure() {
        let directory = tempfile::tempdir().unwrap();
        let manager = manager(directory.path());
        assert!(matches!(start(&manager, 1), JobResponse::Info { .. }));
        let first = "a".repeat(32);
        let second = "b".repeat(32);
        assert!(matches!(
            request(
                &manager,
                JobOperation::Attach {
                    id: id(1),
                    attachment: first.clone(),
                    read_only: false
                }
            ),
            JobResponse::Attached { .. }
        ));
        assert_eq!(
            error_code(request(
                &manager,
                JobOperation::Attach {
                    id: id(1),
                    attachment: second.clone(),
                    read_only: false
                }
            )),
            "input_busy"
        );
        for _ in 0..INPUT_QUEUE {
            assert!(matches!(
                request(
                    &manager,
                    JobOperation::Write {
                        id: id(1),
                        attachment: first.clone(),
                        data_base64: STANDARD.encode(b"input")
                    }
                ),
                JobResponse::Ok
            ));
        }
        assert_eq!(
            error_code(request(
                &manager,
                JobOperation::Write {
                    id: id(1),
                    attachment: first.clone(),
                    data_base64: STANDARD.encode(b"input")
                }
            )),
            "input_busy"
        );
        assert!(matches!(
            request(
                &manager,
                JobOperation::Signal {
                    id: id(1),
                    signal: 9
                }
            ),
            JobResponse::Ok
        ));
        assert!(matches!(
            request(
                &manager,
                JobOperation::Detach {
                    id: id(1),
                    attachment: first
                }
            ),
            JobResponse::Ok
        ));
        let entries = manager.entries.lock().unwrap();
        assert!(!entries[&id(1)].record.info.stdin_closed);
        assert!(entries[&id(1)].record.info.state.is_active());
        drop(entries);
        assert!(matches!(
            request(
                &manager,
                JobOperation::Attach {
                    id: id(1),
                    attachment: second,
                    read_only: false
                }
            ),
            JobResponse::Attached { .. }
        ));
    }

    #[tokio::test]
    async fn eof_is_ordered_permanent_and_distinct_from_detach() {
        let directory = tempfile::tempdir().unwrap();
        let manager = manager(directory.path());
        start(&manager, 1);
        let token = "c".repeat(32);
        request(
            &manager,
            JobOperation::Attach {
                id: id(1),
                attachment: token.clone(),
                read_only: false,
            },
        );
        assert!(matches!(
            request(&manager, JobOperation::Eof { id: id(1) }),
            JobResponse::Ok
        ));
        assert!(matches!(
            request(&manager, JobOperation::Eof { id: id(1) }),
            JobResponse::Ok
        ));
        assert_eq!(
            error_code(request(
                &manager,
                JobOperation::Write {
                    id: id(1),
                    attachment: token,
                    data_base64: STANDARD.encode(b"late")
                }
            )),
            "stdin_closed"
        );
        assert!(manager.store.read(&id(1)).unwrap().info.stdin_closed);
        assert!(matches!(
            request(
                &manager,
                JobOperation::Attach {
                    id: id(1),
                    attachment: "d".repeat(32),
                    read_only: true
                }
            ),
            JobResponse::Attached { .. }
        ));
    }

    #[tokio::test]
    async fn restart_marks_unconfirmed_jobs_lost_without_reexecuting() {
        let directory = tempfile::tempdir().unwrap();
        let manager = manager(directory.path());
        start(&manager, 1);
        let restored = JobManager::open(
            "boot-two".into(),
            directory.path(),
            &directory.path().join("other.sock"),
            tokio::runtime::Handle::current(),
        )
        .unwrap();
        assert!(!restored.active());
        assert_eq!(
            restored.store.read(&id(1)).unwrap().info.state,
            JobState::Lost
        );
        assert!(restored.entries.lock().unwrap()[&id(1)].input.is_none());
    }
    #[tokio::test]
    async fn damaged_history_disables_jobs_without_blocking_sandbox_boot() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("jobs-v1").join(id(1).as_str());
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("info.json"), b"broken metadata").unwrap();
        let manager = manager(directory.path());
        assert!(!manager.active());
        assert_eq!(
            error_code(request(&manager, JobOperation::Hello)),
            "history_error"
        );
    }
}
