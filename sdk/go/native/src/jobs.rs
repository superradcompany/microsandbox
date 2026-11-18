//! Additive managed-job ABI. Optional symbol discovery keeps older bundles usable.

use std::collections::HashMap;
use std::os::raw::{c_char, c_uchar};
use std::sync::{
    Arc, OnceLock, RwLock,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use microsandbox::sandbox::jobs::{
    Job, JobAttachment, JobError, JobId, JobListBuilder, JobLogOptions, JobLogStream, JobReplay,
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;

use crate::{FfiError, cstr, get, run_c};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone)]
enum Object {
    Job(Job),
    Attachment(Arc<JobAttachment>),
    Logs(Arc<LogReader>),
}
struct LogReader {
    stream: Mutex<JobLogStream>,
    closed: CancellationToken,
}

#[derive(Deserialize)]
struct Launch {
    cmd: String,
    #[serde(default)]
    args: Vec<String>,
    cwd: Option<String>,
    user: Option<String>,
    #[serde(default)]
    env: HashMap<String, String>,
    timeout_ms: Option<u64>,
    #[serde(default)]
    no_stdin: bool,
    input_base64: Option<String>,
    #[serde(default)]
    tty: bool,
    #[serde(default)]
    rlimits: Vec<microsandbox::sandbox::exec::Rlimit>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn objects() -> &'static RwLock<HashMap<u64, Object>> {
    static OBJECTS: OnceLock<RwLock<HashMap<u64, Object>>> = OnceLock::new();
    OBJECTS.get_or_init(Default::default)
}

fn insert(object: Object) -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    objects().write().unwrap().insert(id, object);
    id
}

fn job_error(error: JobError) -> FfiError {
    let id = match &error {
        JobError::LaunchUnconfirmed { id, .. } => Some(id.to_string()),
        _ => None,
    };
    FfiError::new(
        "job",
        json!({ "code": error.code(), "message": error.to_string(), "job_id": id }).to_string(),
    )
}
fn invalid(error: impl std::fmt::Display) -> FfiError {
    FfiError::invalid_argument(error.to_string())
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, FfiError> {
    value[key]
        .as_str()
        .ok_or_else(|| invalid(format!("missing string: {key}")))
}
fn number(value: &Value, key: &str) -> Result<u64, FfiError> {
    value[key]
        .as_u64()
        .ok_or_else(|| invalid(format!("missing unsigned integer: {key}")))
}
fn attach_replay(value: &Value) -> Result<JobReplay, FfiError> {
    if value["cursor"].is_string() && value["replay_bytes"].is_number() {
        return Err(invalid("replay_bytes and cursor conflict"));
    }
    Ok(if let Some(cursor) = value["cursor"].as_str() {
        JobReplay::After(cursor.into())
    } else if let Some(max) = value["replay_bytes"].as_u64() {
        JobReplay::Recent {
            max_bytes: usize::try_from(max).map_err(invalid)?,
        }
    } else {
        JobReplay::None
    })
}

/// Run a cancellable managed-job operation. Cancellation never terminates a job.
/// The caller supplies borrowed request text and a writable output buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_jobs(
    cancel_id: u64,
    sandbox_handle: u64,
    request: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        // Reserve the complete bounded response before any launch or stream consumption.
        if buf_len < 4 * 1024 * 1024 {
            return Err(invalid("job responses require a four MiB buffer"));
        }
        let request: Value = serde_json::from_str(&unsafe { cstr(request) }?).map_err(invalid)?;
        Ok(Box::pin(async move {
            dispatch(sandbox_handle, request)
                .await
                .map(|value| value.to_string())
        }))
    })
}

async fn dispatch(sandbox_handle: u64, value: Value) -> Result<Value, FfiError> {
    let op = text(&value, "op")?;
    if op == "start" {
        let sb = get(sandbox_handle)?;
        let launch: Launch = serde_json::from_value(value["options"].clone()).map_err(invalid)?;
        let input = launch
            .input_base64
            .map(|input| STANDARD.decode(input).map_err(invalid))
            .transpose()?;
        let job = sb
            .exec_detached_with(launch.cmd, |mut b| {
                b = b.args(launch.args).tty(launch.tty);
                if let Some(cwd) = launch.cwd {
                    b = b.cwd(cwd);
                }
                if let Some(user) = launch.user {
                    b = b.user(user);
                }
                for (key, value) in launch.env {
                    b = b.env(key, value);
                }
                for limit in launch.rlimits {
                    b = b.rlimit_range(limit.resource, limit.soft, limit.hard);
                }
                if let Some(ms) = launch.timeout_ms {
                    b = b.timeout(Duration::from_millis(ms));
                }
                if launch.no_stdin {
                    b = b.stdin_null();
                }
                if let Some(input) = input {
                    b = b.stdin_bytes(input);
                }
                b
            })
            .await
            .map_err(job_error)?;
        let id = job.id().to_string();
        return Ok(json!({ "handle": insert(Object::Job(job)), "id": id }));
    }
    if op == "get" || op == "list" {
        let sb = if sandbox_handle != 0 {
            let live = get(sandbox_handle)?;
            let handle = live
                .backend()
                .sandboxes()
                .get(live.backend().clone(), live.name())
                .await
                .map_err(FfiError::from)?;
            if live.id() != handle.id() {
                return Err(FfiError::new(
                    "sandbox_replaced",
                    "sandbox identity changed",
                ));
            }
            handle
        } else {
            let sb = microsandbox::Sandbox::get(text(&value, "name")?)
                .await
                .map_err(FfiError::from)?;
            if sb.id().to_string() != text(&value, "sandbox_id")? {
                return Err(FfiError::new(
                    "sandbox_replaced",
                    "sandbox identity changed",
                ));
            }
            sb
        };
        if op == "get" {
            let job = sb.get_job(text(&value, "id")?).await.map_err(job_error)?;
            let id = job.id().to_string();
            return Ok(json!({ "handle": insert(Object::Job(job)), "id": id }));
        }
        let mut b = JobListBuilder::default().all(value["all"].as_bool().unwrap_or(false));
        if let Some(limit) = value["limit"].as_u64() {
            b = b.limit(usize::try_from(limit).map_err(invalid)?);
        }
        if let Some(cursor) = value["cursor"].as_str() {
            b = b.cursor(JobId::parse(cursor).map_err(invalid)?);
        }
        return serde_json::to_value(sb.list_jobs_with(|_| b).await.map_err(job_error)?)
            .map_err(invalid);
    }
    let handle = number(&value, "handle")?;
    if op == "close" {
        let object = objects().write().unwrap().remove(&handle);
        match object {
            Some(Object::Attachment(attachment)) => attachment.detach().await.map_err(job_error)?,
            Some(Object::Logs(reader)) => reader.closed.cancel(),
            _ => {}
        }
        return Ok(Value::Null);
    }
    let object = objects()
        .read()
        .unwrap()
        .get(&handle)
        .cloned()
        .ok_or_else(|| FfiError::invalid_handle(handle))?;
    match object {
        Object::Job(job) => match op {
            "inspect" => {
                serde_json::to_value(job.inspect().await.map_err(job_error)?).map_err(invalid)
            }
            "wait" => serde_json::to_value(job.wait().await.map_err(job_error)?).map_err(invalid),
            "signal" => {
                let signal = i32::try_from(number(&value, "signal")?).map_err(invalid)?;
                job.signal(signal).await.map_err(job_error)?;
                Ok(Value::Null)
            }
            "kill" => {
                job.kill().await.map_err(job_error)?;
                Ok(Value::Null)
            }
            "eof" => {
                job.eof().await.map_err(job_error)?;
                Ok(Value::Null)
            }
            "logs" | "log_stream" => {
                let options: JobLogOptions =
                    serde_json::from_value(value["options"].clone()).map_err(invalid)?;
                if op == "logs" {
                    return serde_json::to_value(job.logs(&options).await.map_err(job_error)?)
                        .map_err(invalid);
                }
                let stream = job.log_stream(&options).await.map_err(job_error)?;
                Ok(
                    json!({ "handle": insert(Object::Logs(Arc::new(LogReader { stream: Mutex::new(stream), closed: CancellationToken::new() }))) }),
                )
            }
            "attach" => {
                let replay = attach_replay(&value)?;
                let read_only = value["read_only"].as_bool().unwrap_or(false);
                let attachment = job
                    .attach_with(|b| b.read_only(read_only).replay(replay))
                    .await
                    .map_err(job_error)?;
                Ok(json!({ "handle": insert(Object::Attachment(Arc::new(attachment))) }))
            }
            _ => Err(invalid("unknown job operation")),
        },
        Object::Attachment(attachment) => match op {
            "recv" => {
                serde_json::to_value(attachment.recv().await.map_err(job_error)?).map_err(invalid)
            }
            "write" => {
                attachment
                    .write_stdin(
                        STANDARD
                            .decode(text(&value, "data_base64")?)
                            .map_err(invalid)?,
                    )
                    .await
                    .map_err(job_error)?;
                Ok(Value::Null)
            }
            "resize" => {
                attachment
                    .resize(
                        u16::try_from(number(&value, "rows")?).map_err(invalid)?,
                        u16::try_from(number(&value, "cols")?).map_err(invalid)?,
                    )
                    .await
                    .map_err(job_error)?;
                Ok(Value::Null)
            }
            "detach" => {
                attachment.detach().await.map_err(job_error)?;
                Ok(Value::Null)
            }
            _ => Err(invalid("unknown attachment operation")),
        },
        Object::Logs(reader) => {
            if op != "next" {
                return Err(invalid("unknown log stream operation"));
            }
            let mut stream = reader.stream.lock().await;
            let item = tokio::select! { _ = reader.closed.cancelled() => None, item = stream.next() => item }.transpose().map_err(job_error)?;
            serde_json::to_value(item).map_err(invalid)
        }
    }
}
