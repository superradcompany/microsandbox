//! Startup telemetry on the existing PID pipe, independent of VM work.

use std::fs::File;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::sync::watch;

use crate::startup_progress::{StartupPhase, StartupProgress, StartupProgressCallback};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Keeps preparation EOF ordered after the outer runtime's boot-error publication.
/// The telemetry task lives inside `run`, but its final error is reported by `enter`.
#[derive(Clone, Default)]
pub(super) struct StartupFailureChannel {
    writer: Arc<Mutex<Option<File>>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl StartupFailureChannel {
    pub(super) fn retain(&self, writer: File) -> std::io::Result<File> {
        let mut retained = self
            .writer
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *retained = Some(writer);
        // Store the original before cloning: even a failed duplication must not let
        // EOF race the diagnostic that explains why startup failed.
        retained.as_ref().expect("writer just retained").try_clone()
    }

    pub(super) fn release(&self) {
        self.writer
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Publish the cause before triggering process exit, including asynchronous activation failures
/// that do not unwind through `enter`. The creator must not replace these with a missing socket.
pub(super) fn publish_failure(log_dir: &std::path::Path, error: &crate::RuntimeError) {
    if let Err(write_error) =
        crate::boot_error::BootError::from_runtime_error(error).write_atomic(log_dir)
    {
        tracing::error!(%write_error, %error, "failed to publish startup diagnostic");
    }
}

pub(super) fn start(
    file: File,
    runtime: &tokio::runtime::Runtime,
    initial_phase: StartupPhase,
    failure_channel: StartupFailureChannel,
) -> StartupProgressCallback {
    let initial = StartupProgress::phase(initial_phase);
    let (sender, mut receiver) = watch::channel(initial.clone());
    runtime.spawn(async move {
        let mut file = tokio::fs::File::from_std(file);
        loop {
            // A watch retains the newest cumulative state even when readers are slow. In
            // particular Activating is terminal on this channel and cannot be overwritten.
            let progress = receiver.borrow_and_update().clone();
            let Ok(mut bytes) = serde_json::to_vec(&progress) else {
                break;
            };
            bytes.push(b'\n');
            if file.write_all(&bytes).await.is_err() || file.flush().await.is_err() {
                // An older launcher (or an exited observer) may close after the PID reply.
                // Telemetry loss is never a reason to fail a healthy runtime.
                break;
            }
            if progress.phase == StartupPhase::Activating {
                // Only the flushed activation frame permits the normal channel EOF.
                // Failed preparation retains the extra writer outside the Tokio runtime.
                failure_channel.release();
                break;
            }
            if receiver.changed().await.is_err() {
                break;
            }
        }
    });
    let last = Mutex::new((Instant::now(), initial.phase));
    Arc::new(move |progress| {
        let mut last = last.lock().unwrap_or_else(|error| error.into_inner());
        if progress.phase != last.1
            || last.0.elapsed() >= Duration::from_millis(100)
            || progress.total_bytes == Some(progress.completed_bytes)
        {
            *last = (Instant::now(), progress.phase);
            sender.send_replace(progress);
        }
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, unix))]
mod tests {
    use std::io::{BufRead, Read};
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    use super::*;
    use crate::boot_error::{BootError, BootErrorStage};

    #[test]
    fn preparation_task_teardown_cannot_overtake_boot_diagnostic() {
        let log_dir = tempfile::tempdir().unwrap();
        let (mut reader, writer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        let channel = StartupFailureChannel::default();
        let writer = channel.retain(File::from(OwnedFd::from(writer))).unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let callback = start(
            writer,
            &runtime,
            StartupPhase::PreparingSnapshot,
            channel.clone(),
        );
        drop(callback);
        // Reproduce `run` returning before `enter` publishes its error. Even if the
        // telemetry task was never polled, its file is now closed by runtime teardown.
        drop(runtime);
        let mut bytes = [0; 4096];
        loop {
            match reader.read(&mut bytes) {
                Ok(0) => panic!("EOF overtook the boot diagnostic"),
                Ok(_) => continue,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("unexpected startup read error: {error}"),
            }
        }
        let error = crate::RuntimeError::Custom(
            "mount work: external source is missing (os error 2)".into(),
        );
        BootError::from_runtime_error(&error)
            .write_atomic(log_dir.path())
            .unwrap();
        channel.release();
        assert_eq!(reader.read(&mut bytes).unwrap(), 0);
        let saved = BootError::read(log_dir.path()).unwrap().unwrap();
        assert_eq!(saved.message, error.to_string());
        assert_eq!(saved.stage, BootErrorStage::Mount);
        assert_eq!(saved.errno, Some(2));
    }

    #[test]
    fn flushed_activation_releases_outer_channel_lease() {
        let (reader, writer) = UnixStream::pair().unwrap();
        reader
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let channel = StartupFailureChannel::default();
        let writer = channel.retain(File::from(OwnedFd::from(writer))).unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let _callback = start(writer, &runtime, StartupPhase::Activating, channel.clone());
        let mut reader = std::io::BufReader::new(reader);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let event: StartupProgress = serde_json::from_str(&line).unwrap();
        assert_eq!(event.phase, StartupPhase::Activating);
        assert_eq!(reader.read(&mut [0; 1]).unwrap(), 0);
        assert!(channel.writer.lock().unwrap().is_none());
    }

    #[test]
    fn asynchronous_activation_failure_keeps_its_actual_cause() {
        let log_dir = tempfile::tempdir().unwrap();
        let error = crate::RuntimeError::Custom(
            "restored kernel rejected identity-and-clock activation; workloads remain frozen"
                .into(),
        );
        publish_failure(log_dir.path(), &error);
        let saved = BootError::read(log_dir.path()).unwrap().unwrap();
        assert_eq!(saved.message, error.to_string());
    }
}
