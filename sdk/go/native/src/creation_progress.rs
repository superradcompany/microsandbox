//! Bounded creation telemetry across the Go FFI. No callbacks into Go from worker threads.

use std::collections::HashMap;
use std::os::raw::{c_char, c_uchar};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

use tokio::sync::{Mutex, mpsc};

use super::{FfiError, run, run_c};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

type Event = microsandbox::CreationProgress;
type Entry = (mpsc::Sender<Event>, Arc<Mutex<mpsc::Receiver<Event>>>);

struct CreationTask(
    tokio::task::JoinHandle<microsandbox::MicrosandboxResult<microsandbox::Sandbox>>,
);

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for CreationTask {
    fn drop(&mut self) {
        // The C cancellation token must cancel creation, not merely detach its JoinHandle.
        self.0.abort();
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn registry() -> &'static RwLock<HashMap<u64, Entry>> {
    static REGISTRY: OnceLock<RwLock<HashMap<u64, Entry>>> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

pub(super) async fn create(
    builder: microsandbox::sandbox::SandboxBuilder,
    id: u64,
) -> Result<microsandbox::Sandbox, FfiError> {
    observe(id, || builder.create_with_progress()).await
}

pub(super) async fn restore(
    builder: microsandbox::sandbox::RestoreBuilder,
    id: u64,
) -> Result<microsandbox::Sandbox, FfiError> {
    observe(id, || builder.restore_with_progress()).await
}

async fn observe(
    id: u64,
    start: impl FnOnce() -> microsandbox::MicrosandboxResult<(
        microsandbox::CreationProgressHandle,
        tokio::task::JoinHandle<microsandbox::MicrosandboxResult<microsandbox::Sandbox>>,
    )>,
) -> Result<microsandbox::Sandbox, FfiError> {
    let sender = registry()
        .read()
        .map_err(|_| FfiError::internal("progress registry poisoned"))?
        .get(&id)
        .ok_or_else(|| FfiError::invalid_handle(id))?
        .0
        .clone();
    let (mut progress, task) = start().map_err(FfiError::from)?;
    let mut task = CreationTask(task);
    loop {
        tokio::select! {
            result = &mut task.0 => return result.map_err(|error| FfiError::internal(format!("creation task: {error}")))?.map_err(FfiError::from),
            event = progress.recv() => match event {
                Some(event) => { let _ = sender.try_send(event); }
                None => return (&mut task.0).await.map_err(|error| FfiError::internal(format!("creation task: {error}")))?.map_err(FfiError::from),
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_creation_progress_open(buf: *mut c_uchar, len: usize) -> *mut c_char {
    run(buf, len, || {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = mpsc::channel(64);
        registry()
            .write()
            .map_err(|_| FfiError::internal("progress registry poisoned"))?
            .insert(id, (sender, Arc::new(Mutex::new(receiver))));
        Ok(format!("{{\"handle\":{id}}}"))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_creation_progress_recv(
    cancel_id: u64,
    id: u64,
    buf: *mut c_uchar,
    len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, len, || {
        let receiver = registry()
            .read()
            .map_err(|_| FfiError::internal("progress registry poisoned"))?
            .get(&id)
            .ok_or_else(|| FfiError::invalid_handle(id))?
            .1
            .clone();
        Ok(Box::pin(async move {
            let event = receiver.lock().await.recv().await;
            serde_json::to_string(&event).map_err(|error| FfiError::internal(error.to_string()))
        }))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_creation_progress_close(
    id: u64,
    buf: *mut c_uchar,
    len: usize,
) -> *mut c_char {
    run(buf, len, || {
        registry()
            .write()
            .map_err(|_| FfiError::internal("progress registry poisoned"))?
            .remove(&id);
        Ok("{}".into())
    })
}
