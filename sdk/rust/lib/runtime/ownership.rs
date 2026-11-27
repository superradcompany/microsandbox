//! Exact Windows process ownership for runtimes predating the lifecycle lock.

use std::io::{self, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::time::Duration;

use microsandbox_db::entity::run;
use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, FILETIME, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    WaitForSingleObject,
};

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A kernel handle pins the process object even after Windows recycles its PID.
pub(crate) struct RuntimeProcess {
    pid: i32,
    birth: u64,
    handle: OwnedHandle,
}

/// Kept outside SQLite so old SDKs can continue to open the shared catalog.
#[derive(Serialize, Deserialize)]
struct Record {
    sandbox_id: i32,
    run_id: i32,
    pid: i32,
    birth: u64,
    lifecycle_lock: bool,
}

/// A matching record distinguishes an exited process from missing ownership evidence.
pub(crate) struct RecordedOwner {
    pub lifecycle_lock: bool,
    pub process: Option<RuntimeProcess>,
    /// The recorded PID is live but this token may not open it (ERROR_ACCESS_DENIED):
    /// a process of another account or a protected process now holds the PID, or the
    /// runtime itself belongs to one. Like [`microsandbox_utils::process::pid_is_alive`],
    /// that counts as alive, so the run is left alone rather than reported as an error
    /// or reconciled as exited.
    pub inaccessible: bool,
    pid: i32,
    birth: u64,
}

/// An I/O error from reading a runtime ownership record or capturing the PID it holds.
/// The original error stays the source, so callers keep its OS error code.
#[derive(Debug, thiserror::Error)]
#[error("{subject}: {source}")]
struct RecordIoError {
    subject: String,
    source: io::Error,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RuntimeProcess {
    pub(crate) fn capture(pid: i32) -> io::Result<Option<Self>> {
        if pid <= 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid runtime PID",
            ));
        }
        // SAFETY: rights only permit identity inspection and waiting, never termination.
        let raw = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                pid as u32,
            )
        };
        if raw.is_null() {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        // SAFETY: OpenProcess returned a new owned handle.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut creation: FILETIME = unsafe { std::mem::zeroed() };
        let mut exit = creation;
        let mut kernel = creation;
        let mut user = creation;
        if unsafe { GetProcessTimes(raw, &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(Self {
            pid,
            birth: (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime),
            handle,
        }))
    }

    pub(crate) fn alive(&self) -> io::Result<bool> {
        // WAIT_FAILED is an observation error, never evidence of process exit.
        match unsafe { WaitForSingleObject(self.handle.as_raw_handle(), 0) } {
            WAIT_TIMEOUT => Ok(true),
            WAIT_OBJECT_0 => Ok(false),
            _ => Err(io::Error::last_os_error()),
        }
    }

    pub(crate) fn publish(
        &self,
        directory: &Path,
        run: &run::Model,
        lifecycle_lock: bool,
    ) -> MicrosandboxResult<()> {
        if run.pid != Some(self.pid) || !self.alive()? {
            return Err(changed());
        }
        let record = Record {
            sandbox_id: run.sandbox_id,
            run_id: run.id,
            pid: self.pid,
            birth: self.birth,
            lifecycle_lock,
        };
        let mut file = tempfile::NamedTempFile::new_in(directory)?;
        serde_json::to_writer(&mut file, &record)?;
        file.flush()?;
        // The transition guard serializes publication with cooperative restart/removal.
        file.persist(directory.join("sdk-process.json"))
            .map_err(|error| error.error)?;
        Ok(())
    }

    /// Check the actual pipe server before handing the stream to the agent client.
    pub(crate) async fn connect_agent(
        &self,
        path: &Path,
        timeout: Duration,
    ) -> MicrosandboxResult<crate::agent::AgentClient> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if !self.alive()? {
                return Err(changed());
            }
            match tokio::net::windows::named_pipe::ClientOptions::new().open(path) {
                Ok(stream) => {
                    let mut pid = 0;
                    if unsafe { GetNamedPipeServerProcessId(stream.as_raw_handle(), &mut pid) } == 0
                    {
                        return Err(io::Error::last_os_error().into());
                    }
                    if pid != self.pid as u32 || !self.alive()? {
                        return Err(changed());
                    }
                    return Ok(crate::agent::AgentClient::connect_stream_with_timeout(
                        stream,
                        deadline.saturating_duration_since(tokio::time::Instant::now()),
                    )
                    .await?);
                }
                Err(error)
                    if error.raw_os_error() == Some(231)
                        && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

impl RecordedOwner {
    /// Whether the recorded runtime still holds its run. An exited or recycled process
    /// is not alive; one this token may not open is (see [`Self::inaccessible`]). There is
    /// no handle to an inaccessible PID, so it is captured again on every call and stops
    /// counting once it exits.
    pub(crate) fn alive(&self) -> io::Result<bool> {
        if self.inaccessible {
            let current = owner_from_capture(
                RuntimeProcess::capture(self.pid),
                self.pid,
                self.birth,
                self.lifecycle_lock,
            )?;
            if current.inaccessible {
                return Ok(true);
            }

            return current.alive();
        }

        Ok(self
            .process
            .as_ref()
            .map(RuntimeProcess::alive)
            .transpose()?
            .unwrap_or(false))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn recorded_owner(
    directory: &Path,
    run: &run::Model,
) -> MicrosandboxResult<Option<RecordedOwner>> {
    let path = directory.join("sdk-process.json");
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(record_error(&path, None, error).into()),
    };
    let record: Record = serde_json::from_slice(&bytes)?;
    // An old file must never bind an unrelated run, including after removal/recreation.
    if record.sandbox_id != run.sandbox_id || record.run_id != run.id || Some(record.pid) != run.pid
    {
        return Ok(None);
    }

    let owner = owner_from_capture(
        RuntimeProcess::capture(record.pid),
        record.pid,
        record.birth,
        record.lifecycle_lock,
    )
    .map_err(|error| record_error(&path, Some(record.pid), error))?;

    Ok(Some(owner))
}

fn changed() -> MicrosandboxError {
    MicrosandboxError::Runtime("runtime process identity changed during lifecycle operation".into())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Turns the capture of a recorded PID into its owner. ERROR_ACCESS_DENIED means the
/// PID is live but not openable by this token; like `pid_is_alive`, that is alive.
fn owner_from_capture(
    captured: io::Result<Option<RuntimeProcess>>,
    pid: i32,
    birth: u64,
    lifecycle_lock: bool,
) -> io::Result<RecordedOwner> {
    let (process, inaccessible) = match captured {
        Ok(process) => (process.filter(|process| process.birth == birth), false),
        Err(error) if error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => (None, true),
        Err(error) => return Err(error),
    };

    Ok(RecordedOwner {
        lifecycle_lock,
        process,
        inaccessible,
        pid,
        birth,
    })
}

/// Names the record (and the PID it holds) an I/O error came from; a bare OS error
/// from `msb list` gives no clue which sandbox or process failed. The original error
/// stays reachable as the source.
fn record_error(path: &Path, pid: Option<i32>, error: io::Error) -> io::Error {
    let subject = match pid {
        Some(pid) => format!("runtime pid {pid} recorded in {}", path.display()),
        None => path.display().to_string(),
    };

    io::Error::new(
        error.kind(),
        RecordIoError {
            subject,
            source: error,
        },
    )
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command, Stdio};

    use windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE;

    struct ChildFixture(Child);

    impl ChildFixture {
        fn start() -> Self {
            Self(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "runtime::ownership::tests::ownership_child",
                        "--ignored",
                    ])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            )
        }
    }

    impl Drop for ChildFixture {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn run(pid: i32) -> run::Model {
        run::Model {
            id: 17,
            sandbox_id: 11,
            pid: Some(pid),
            status: run::RunStatus::Running,
            exit_code: None,
            exit_signal: None,
            termination_reason: None,
            termination_detail: None,
            signals_sent: None,
            started_at: None,
            terminated_at: None,
        }
    }

    #[test]
    fn retained_owner_observes_real_exit_and_survives_record_reload() {
        let mut child = ChildFixture::start();
        let process = RuntimeProcess::capture(child.0.id() as i32)
            .unwrap()
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let run = run(process.pid);
        process.publish(directory.path(), &run, false).unwrap();
        let reattached = recorded_owner(directory.path(), &run).unwrap().unwrap();
        assert!(!reattached.lifecycle_lock);
        assert!(reattached.process.as_ref().unwrap().alive().unwrap());
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert!(!process.alive().unwrap());
        assert!(!reattached.process.as_ref().unwrap().alive().unwrap());
    }

    #[test]
    fn old_record_cannot_follow_a_replacement_run_or_recycled_pid() {
        let process = RuntimeProcess::capture(std::process::id() as i32)
            .unwrap()
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut run = run(process.pid);
        process.publish(directory.path(), &run, false).unwrap();
        run.id += 1;
        assert!(recorded_owner(directory.path(), &run).unwrap().is_none());
        run.id -= 1;
        let path = directory.path().join("sdk-process.json");
        let mut record: Record = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        record.birth -= 1;
        std::fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(
            recorded_owner(directory.path(), &run)
                .unwrap()
                .unwrap()
                .process
                .is_none()
        );
        assert!(process.alive().unwrap());
    }

    #[tokio::test]
    async fn shutdown_connection_rejects_a_different_pipe_owner() {
        let child = ChildFixture::start();
        let process = RuntimeProcess::capture(child.0.id() as i32)
            .unwrap()
            .unwrap();
        let path = format!(r"\\.\pipe\msb-owner-test-{}", std::process::id());
        let _server = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .create(&path)
            .unwrap();
        assert!(
            process
                .connect_agent(Path::new(&path), Duration::from_secs(1))
                .await
                .is_err()
        );
        assert!(process.alive().unwrap());
    }

    /// A recorded PID this token may not open (another account's or a protected process)
    /// counts as alive, as `pid_is_alive` does, instead of failing `msb list` with a bare
    /// "Access is denied (os error 5)". Each check captures it again, so a stop waiting
    /// on it finishes once it exits.
    #[test]
    fn an_inaccessible_recorded_pid_is_alive_until_it_exits() {
        let mut child = ChildFixture::start();
        let process = RuntimeProcess::capture(child.0.id() as i32)
            .unwrap()
            .unwrap();
        let (pid, birth) = (process.pid, process.birth);
        drop(process);
        let denied = io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32);

        let owner = owner_from_capture(Err(denied), pid, birth, false).unwrap();
        assert!(owner.inaccessible);
        assert!(owner.process.is_none());
        assert!(owner.alive().unwrap());

        child.0.kill().unwrap();
        child.0.wait().unwrap();

        assert!(!owner.alive().unwrap());
    }

    /// An exited PID is not alive, and other capture errors are still returned.
    #[test]
    fn only_access_denied_makes_an_inaccessible_owner() {
        let exited = owner_from_capture(Ok(None), 1, 1, false).unwrap();
        assert!(!exited.inaccessible);
        assert!(!exited.alive().unwrap());

        let other = io::Error::from_raw_os_error(ERROR_INVALID_HANDLE as i32);

        let error = owner_from_capture(Err(other), 1, 1, false).err().unwrap();
        assert_eq!(error.raw_os_error(), Some(ERROR_INVALID_HANDLE as i32));
    }

    /// Other I/O errors name the record and the PID it holds.
    #[test]
    fn record_errors_name_the_record_and_pid() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sdk-process.json");

        let error = record_error(
            &path,
            Some(4321),
            io::Error::from_raw_os_error(ERROR_INVALID_HANDLE as i32),
        );
        let message = error.to_string();
        let source = error
            .get_ref()
            .and_then(|inner| inner.source())
            .and_then(|source| source.downcast_ref::<io::Error>());
        assert!(message.contains("runtime pid 4321"), "{message}");
        assert!(message.contains(&path.display().to_string()), "{message}");
        assert_eq!(
            source.and_then(io::Error::raw_os_error),
            Some(ERROR_INVALID_HANDLE as i32)
        );

        // An unreadable record (here a directory in its place) names its path.
        std::fs::create_dir(&path).unwrap();

        let MicrosandboxError::Io(error) =
            recorded_owner(directory.path(), &run(4321)).err().unwrap()
        else {
            panic!("an unreadable record is no longer an I/O error");
        };
        let source = error
            .get_ref()
            .and_then(|inner| inner.source())
            .and_then(|source| source.downcast_ref::<io::Error>());
        assert!(
            error.to_string().contains(&path.display().to_string()),
            "{error}"
        );
        assert!(
            source.and_then(io::Error::raw_os_error).is_some(),
            "{error}"
        );
    }

    #[test]
    #[ignore = "subprocess fixture controlled by the ownership tests"]
    fn ownership_child() {
        // EOF also releases the fixture if its test parent exits unexpectedly.
        let _ = std::io::Read::read(&mut std::io::stdin(), &mut [0]);
    }
}
