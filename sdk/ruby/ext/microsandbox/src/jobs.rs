//! Runtime-owned jobs and temporary attachments for Ruby.

use std::future::Future;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use futures::StreamExt;
use magnus::{
    Error, RHash, RModule, RString, Ruby, Value, method, prelude::*, scan_args::scan_args,
    typed_data,
};
use microsandbox_core::sandbox::jobs::{
    Job, JobAttachment, JobError, JobId, JobListBuilder, JobLogOptions, JobLogStream, JobReplay,
    JobResult,
};
use tokio::sync::{Mutex, Notify};

use super::{
    RubySandbox, RubySandboxHandle, apply_exec_options, argument_error, block_without_gvl,
    exec_args_and_kwargs, keyword, reject_unknown_keywords,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[magnus::wrap(class = "Microsandbox::Job", free_immediately, size)]
struct RubyJob {
    inner: Job,
}
#[magnus::wrap(class = "Microsandbox::JobAttachment", free_immediately, size)]
struct RubyJobAttachment {
    inner: Arc<JobAttachment>,
}
#[magnus::wrap(class = "Microsandbox::JobLogStream", free_immediately, size)]
struct RubyJobLogStream {
    inner: Arc<LogReader>,
}
struct LogReader {
    stream: Mutex<Option<JobLogStream>>,
    closed: AtomicBool,
    notify: Notify,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RubySandbox {
    fn exec_detached(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        args: &[Value],
    ) -> Result<RubyJob, Error> {
        let (cmd, args, kw) = exec_args_and_kwargs(args)?;
        let opts = apply_exec_options(
            ruby,
            microsandbox_core::sandbox::ExecOptionsBuilder::default().stdin_pipe(),
            kw,
        )?;
        let sb = this.inner_clone()?;
        Ok(RubyJob {
            inner: run_job(ruby, async move {
                sb.exec_detached_with(cmd, |_| opts.args(args)).await
            })?,
        })
    }
    fn get_job(ruby: &Ruby, this: typed_data::Obj<Self>, id: String) -> Result<RubyJob, Error> {
        let sb = this.inner_clone()?;
        Ok(RubyJob {
            inner: run_job(ruby, async move { sb.get_job(id).await })?,
        })
    }
    fn jobs_json(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        args: &[Value],
    ) -> Result<String, Error> {
        let options = list_options(ruby, args)?;
        let sb = this.inner_clone()?;
        json(
            ruby,
            run_job(ruby, async move { sb.list_jobs_with(|_| options).await })?,
        )
    }
}
impl RubySandboxHandle {
    fn get_job(ruby: &Ruby, this: typed_data::Obj<Self>, id: String) -> Result<RubyJob, Error> {
        let sb = this.inner.clone();
        Ok(RubyJob {
            inner: run_job(ruby, async move { sb.get_job(id).await })?,
        })
    }
    fn jobs_json(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        args: &[Value],
    ) -> Result<String, Error> {
        let options = list_options(ruby, args)?;
        let sb = this.inner.clone();
        json(
            ruby,
            run_job(ruby, async move { sb.list_jobs_with(|_| options).await })?,
        )
    }
}
impl RubyJob {
    fn id(&self) -> String {
        self.inner.id().to_string()
    }
    fn inspect_json(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<String, Error> {
        let job = this.inner.clone();
        json(ruby, run_job(ruby, async move { job.inspect().await })?)
    }
    fn wait_json(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<String, Error> {
        let job = this.inner.clone();
        json(ruby, run_job(ruby, async move { job.wait().await })?)
    }
    fn signal(ruby: &Ruby, this: typed_data::Obj<Self>, signal: i32) -> Result<(), Error> {
        let job = this.inner.clone();
        run_job(ruby, async move { job.signal(signal).await })
    }
    fn kill(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<(), Error> {
        let job = this.inner.clone();
        run_job(ruby, async move { job.kill().await })
    }
    fn eof(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<(), Error> {
        let job = this.inner.clone();
        run_job(ruby, async move { job.eof().await })
    }
    fn logs_json(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        options: String,
    ) -> Result<String, Error> {
        let options: JobLogOptions =
            serde_json::from_str(&options).map_err(|e| argument_error(ruby, e.to_string()))?;
        let job = this.inner.clone();
        json(
            ruby,
            run_job(ruby, async move { job.logs(&options).await })?,
        )
    }
    fn log_stream(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        options: String,
    ) -> Result<RubyJobLogStream, Error> {
        let options: JobLogOptions =
            serde_json::from_str(&options).map_err(|e| argument_error(ruby, e.to_string()))?;
        let job = this.inner.clone();
        let stream = run_job(ruby, async move { job.log_stream(&options).await })?;
        Ok(RubyJobLogStream {
            inner: Arc::new(LogReader {
                stream: Mutex::new(Some(stream)),
                closed: AtomicBool::new(false),
                notify: Notify::new(),
            }),
        })
    }
    fn attach(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        args: &[Value],
    ) -> Result<RubyJobAttachment, Error> {
        let parsed = scan_args::<(), (), (), (), RHash, ()>(args)?;
        let kw = parsed.keywords;
        reject_unknown_keywords(ruby, kw, &["read_only", "replay_bytes", "cursor"])?;
        let read_only = keyword::<bool>(kw, "read_only")?.unwrap_or(false);
        let bytes = keyword::<usize>(kw, "replay_bytes")?;
        let cursor = keyword::<String>(kw, "cursor")?;
        if bytes.is_some() && cursor.is_some() {
            return Err(argument_error(ruby, "replay_bytes and cursor conflict"));
        }
        let replay = match (bytes, cursor) {
            (_, Some(cursor)) => JobReplay::After(cursor),
            (Some(max_bytes), _) => JobReplay::Recent { max_bytes },
            _ => JobReplay::None,
        };
        let job = this.inner.clone();
        Ok(RubyJobAttachment {
            inner: Arc::new(run_job(ruby, async move {
                job.attach_with(|b| b.read_only(read_only).replay(replay))
                    .await
            })?),
        })
    }
}
impl RubyJobAttachment {
    fn recv_json(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<Option<String>, Error> {
        let attachment = this.inner.clone();
        run_job(ruby, async move { attachment.recv().await })?
            .map(|event| json(ruby, event))
            .transpose()
    }
    fn write_stdin(ruby: &Ruby, this: typed_data::Obj<Self>, bytes: RString) -> Result<(), Error> {
        let data = unsafe { bytes.as_slice() }.to_vec();
        let attachment = this.inner.clone();
        run_job(ruby, async move { attachment.write_stdin(data).await })
    }
    fn resize(ruby: &Ruby, this: typed_data::Obj<Self>, rows: u16, cols: u16) -> Result<(), Error> {
        let attachment = this.inner.clone();
        run_job(ruby, async move { attachment.resize(rows, cols).await })
    }
    fn detach(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<(), Error> {
        let attachment = this.inner.clone();
        run_job(ruby, async move { attachment.detach().await })
    }
}
impl RubyJobLogStream {
    fn next_json(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<Option<String>, Error> {
        let reader = this.inner.clone();
        let item = run_job(ruby, async move {
            let notified = reader.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let mut guard = reader.stream.lock().await;
            if reader.closed.load(Ordering::Acquire) {
                return Ok(None);
            }
            let Some(stream) = guard.as_mut() else {
                return Ok(None);
            };
            tokio::select! { _ = notified => None, item = stream.next() => item }.transpose()
        })?;
        item.map(|entry| json(ruby, entry)).transpose()
    }
    fn close(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<(), Error> {
        let reader = this.inner.clone();
        reader.closed.store(true, Ordering::Release);
        reader.notify.notify_waiters();
        block_without_gvl(ruby, async move {
            reader.stream.lock().await.take();
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn json(ruby: &Ruby, value: impl serde::Serialize) -> Result<String, Error> {
    serde_json::to_string(&value).map_err(|e| argument_error(ruby, e.to_string()))
}
fn run_job<F, T>(ruby: &Ruby, future: F) -> Result<T, Error>
where
    F: Future<Output = JobResult<T>> + Send + 'static,
    T: Send + 'static,
{
    block_without_gvl(ruby, future)?.map_err(|error| {
        let details = serde_json::json!({ "code": error.code(), "message": error.to_string(), "job_id": match &error { JobError::LaunchUnconfirmed { id, .. } => Some(id.to_string()), _ => None } }).to_string();
        let class = ruby.class_object().const_get::<_, RModule>("Microsandbox").and_then(|module| module.const_get::<_, magnus::ExceptionClass>("JobError")).unwrap_or_else(|_| ruby.exception_runtime_error());
        Error::new(class, details)
    })
}
fn list_options(ruby: &Ruby, args: &[Value]) -> Result<JobListBuilder, Error> {
    let parsed = scan_args::<(), (), (), (), RHash, ()>(args)?;
    let kw = parsed.keywords;
    reject_unknown_keywords(ruby, kw, &["all", "limit", "cursor"])?;
    let mut b = JobListBuilder::default().all(keyword::<bool>(kw, "all")?.unwrap_or(false));
    if let Some(limit) = keyword::<usize>(kw, "limit")? {
        b = b.limit(limit);
    }
    if let Some(cursor) = keyword::<String>(kw, "cursor")? {
        b = b.cursor(JobId::parse(cursor).map_err(|e| argument_error(ruby, e))?);
    }
    Ok(b)
}

pub(super) fn init(ruby: &Ruby, module: RModule) -> Result<(), Error> {
    let sandbox: magnus::RClass = module.const_get("Sandbox")?;
    sandbox.define_method("exec_detached", method!(RubySandbox::exec_detached, -1))?;
    sandbox.define_method("get_job", method!(RubySandbox::get_job, 1))?;
    sandbox.define_method("_jobs_json", method!(RubySandbox::jobs_json, -1))?;
    let handle: magnus::RClass = module.const_get("SandboxHandle")?;
    handle.define_method("get_job", method!(RubySandboxHandle::get_job, 1))?;
    handle.define_method("_jobs_json", method!(RubySandboxHandle::jobs_json, -1))?;
    let job = module.define_class("Job", ruby.class_object())?;
    job.define_method("id", method!(RubyJob::id, 0))?;
    job.define_method("_inspect_json", method!(RubyJob::inspect_json, 0))?;
    job.define_method("_wait_json", method!(RubyJob::wait_json, 0))?;
    job.define_method("signal", method!(RubyJob::signal, 1))?;
    job.define_method("kill", method!(RubyJob::kill, 0))?;
    job.define_method("eof", method!(RubyJob::eof, 0))?;
    job.define_method("_logs_json", method!(RubyJob::logs_json, 1))?;
    job.define_method("_log_stream", method!(RubyJob::log_stream, 1))?;
    job.define_method("attach", method!(RubyJob::attach, -1))?;
    let attachment = module.define_class("JobAttachment", ruby.class_object())?;
    attachment.define_method("_recv_json", method!(RubyJobAttachment::recv_json, 0))?;
    attachment.define_method("write_stdin", method!(RubyJobAttachment::write_stdin, 1))?;
    attachment.define_method("resize", method!(RubyJobAttachment::resize, 2))?;
    attachment.define_method("detach", method!(RubyJobAttachment::detach, 0))?;
    let logs = module.define_class("JobLogStream", ruby.class_object())?;
    logs.define_method("_next_json", method!(RubyJobLogStream::next_json, 0))?;
    logs.define_method("close", method!(RubyJobLogStream::close, 0))?;
    Ok(())
}
