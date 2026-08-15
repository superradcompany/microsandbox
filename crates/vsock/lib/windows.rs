use std::collections::VecDeque;
use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use msb_krun::backends::vsock::{
    VsockConnectRequest, VsockConnectState, VsockNotifier, VsockPortBackend, VsockShutdown,
    VsockStreamBackend,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_MORE_DATA, ERROR_PIPE_BUSY, GENERIC_READ, GENERIC_WRITE, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, OPEN_EXISTING, ReadFile, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
};
use windows_sys::Win32::System::IO::CancelSynchronousIo;
use windows_sys::Win32::System::Pipes::{PeekNamedPipe, WaitNamedPipeW};

use crate::common::{DEFAULT_MAX_ACTIVE_PEERS, PeerLease, PeerLimit};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const LOCAL_PIPE_PREFIX: &str = r"\\.\pipe\";
const MAX_BUFFERED_BYTES: usize = 8 * 1024 * 1024;
const IO_CHUNK_SIZE: usize = 64 * 1024;
const WORKER_WAIT: Duration = Duration::from_millis(10);
const PIPE_BUSY_WAIT_MS: u32 = 50;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Factory that connects guest streams to one existing local Windows named pipe.
pub struct WindowsNamedPipePortBackend {
    path: PathBuf,
    peers: PeerLimit,
}

struct WindowsNamedPipeBackend {
    shared: Arc<SharedState>,
    worker: JoinHandle<()>,
    _lease: PeerLease,
}

struct SharedState {
    state: Mutex<PipeState>,
    wake_worker: Condvar,
    notifier: VsockNotifier,
}

struct PipeState {
    connection: ConnectionState,
    incoming: VecDeque<u8>,
    outgoing: VecDeque<u8>,
    read_shutdown: bool,
    write_shutdown: bool,
    terminate: bool,
}

enum ConnectionState {
    Connecting,
    Connected,
    Failed(StoredError),
}

#[derive(Clone)]
struct StoredError {
    kind: io::ErrorKind,
    raw_os_error: Option<i32>,
    message: String,
}

struct PipeHandle(HANDLE);

// Windows named-pipe handles are process-wide opaque values and all access to
// this one is confined to its worker thread.
unsafe impl Send for PipeHandle {}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl WindowsNamedPipePortBackend {
    /// Create a route to an existing local `\\.\pipe\...` named pipe.
    pub fn new(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::with_max_active_peers(path, DEFAULT_MAX_ACTIVE_PEERS)
    }

    /// Create a route with an explicit cap on active guest connections.
    pub fn with_max_active_peers(path: impl AsRef<Path>, max: usize) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        validate_named_pipe_path(&path)?;
        if max == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "vsock stream peer limit must be non-zero",
            ));
        }
        Ok(Self {
            path,
            peers: PeerLimit::new(max),
        })
    }
}

impl StoredError {
    fn capture(error: io::Error) -> Self {
        Self {
            kind: error.kind(),
            raw_os_error: error.raw_os_error(),
            message: error.to_string(),
        }
    }

    fn to_io_error(&self) -> io::Error {
        self.raw_os_error
            .map(io::Error::from_raw_os_error)
            .unwrap_or_else(|| io::Error::new(self.kind, self.message.clone()))
    }
}

impl SharedState {
    fn fail(&self, error: io::Error) {
        let mut state = self.state.lock().unwrap();
        state.connection = ConnectionState::Failed(StoredError::capture(error));
        state.read_shutdown = true;
        state.write_shutdown = true;
        drop(state);
        let _ = self.notifier.notify();
    }

    fn close(&self) {
        let mut state = self.state.lock().unwrap();
        state.read_shutdown = true;
        state.write_shutdown = true;
        drop(state);
        let _ = self.notifier.notify();
    }
}

impl PipeHandle {
    fn raw(&self) -> HANDLE {
        self.0
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl VsockPortBackend for WindowsNamedPipePortBackend {
    fn connect(
        &self,
        _request: VsockConnectRequest,
        notifier: VsockNotifier,
    ) -> io::Result<Box<dyn VsockStreamBackend>> {
        let lease = self.peers.acquire()?;
        let shared = Arc::new(SharedState {
            state: Mutex::new(PipeState {
                connection: ConnectionState::Connecting,
                incoming: VecDeque::new(),
                outgoing: VecDeque::new(),
                read_shutdown: false,
                write_shutdown: false,
                terminate: false,
            }),
            wake_worker: Condvar::new(),
            notifier,
        });
        let worker_shared = Arc::clone(&shared);
        let path = self.path.clone();
        let worker = std::thread::Builder::new()
            .name("vsock named pipe".to_string())
            .spawn(move || named_pipe_worker(path, worker_shared))?;

        Ok(Box::new(WindowsNamedPipeBackend {
            shared,
            worker,
            _lease: lease,
        }))
    }
}

impl VsockStreamBackend for WindowsNamedPipeBackend {
    fn connect_state(&self) -> io::Result<VsockConnectState> {
        match &self.shared.state.lock().unwrap().connection {
            ConnectionState::Connecting => Ok(VsockConnectState::Connecting),
            ConnectionState::Connected => Ok(VsockConnectState::Connected),
            ConnectionState::Failed(error) => Err(error.to_io_error()),
        }
    }

    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut state = self.shared.state.lock().unwrap();
        if let ConnectionState::Failed(error) = &state.connection {
            return Err(error.to_io_error());
        }
        if state.incoming.is_empty() {
            return if state.read_shutdown {
                Ok(0)
            } else {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            };
        }

        let count = buf.len().min(state.incoming.len());
        for slot in &mut buf[..count] {
            *slot = state.incoming.pop_front().unwrap();
        }
        drop(state);
        self.shared.wake_worker.notify_one();
        Ok(count)
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self.shared.state.lock().unwrap();
        if let ConnectionState::Failed(error) = &state.connection {
            return Err(error.to_io_error());
        }
        if state.write_shutdown {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        if !matches!(state.connection, ConnectionState::Connected) {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }

        let count = buf
            .len()
            .min(MAX_BUFFERED_BYTES.saturating_sub(state.outgoing.len()));
        if count == 0 {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        state.outgoing.extend(&buf[..count]);
        drop(state);
        self.shared.wake_worker.notify_one();
        Ok(count)
    }

    fn shutdown(&self, how: VsockShutdown) -> io::Result<()> {
        let terminate = how == VsockShutdown::Both;
        let mut state = self.shared.state.lock().unwrap();
        match how {
            VsockShutdown::Read => state.read_shutdown = true,
            VsockShutdown::Write => state.write_shutdown = true,
            VsockShutdown::Both => {
                state.read_shutdown = true;
                state.write_shutdown = true;
                state.terminate = true;
            }
        }
        drop(state);
        self.shared.wake_worker.notify_one();
        if terminate {
            cancel_worker_io(&self.worker);
        }
        Ok(())
    }
}

impl Drop for WindowsNamedPipeBackend {
    fn drop(&mut self) {
        self.shared.state.lock().unwrap().terminate = true;
        self.shared.wake_worker.notify_one();
        // A named-pipe server can stop reading indefinitely. Cancel any
        // synchronous ReadFile/WriteFile owned by this worker so dropping a
        // guest connection cannot strand a thread outside the peer limit.
        cancel_worker_io(&self.worker);
    }
}

impl Drop for PipeHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.raw());
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn validate_named_pipe_path(path: &Path) -> io::Result<()> {
    let text = path.as_os_str().to_string_lossy();
    let Some(name) = text.get(LOCAL_PIPE_PREFIX.len()..) else {
        return Err(invalid_pipe_path());
    };
    if !text[..LOCAL_PIPE_PREFIX.len()].eq_ignore_ascii_case(LOCAL_PIPE_PREFIX)
        || name.is_empty()
        || name
            .split(['\\', '/'])
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(invalid_pipe_path());
    }
    Ok(())
}

fn invalid_pipe_path() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        r"vsock host path must be a local Windows named pipe such as \\.\pipe\api",
    )
}

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn cancel_worker_io(worker: &JoinHandle<()>) {
    unsafe {
        // ERROR_NOT_FOUND is expected when the worker is between operations or
        // has already exited, so cancellation is intentionally best-effort.
        CancelSynchronousIo(worker.as_raw_handle());
    }
}

fn connect_named_pipe(path: &Path, shared: &SharedState) -> io::Result<PipeHandle> {
    let path = wide_null(path.as_os_str());
    loop {
        if shared.state.lock().unwrap().terminate {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "vsock named-pipe connection was cancelled",
            ));
        }

        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                std::ptr::null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            return Ok(PipeHandle(handle));
        }

        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_PIPE_BUSY as i32) {
            return Err(error);
        }
        unsafe {
            WaitNamedPipeW(path.as_ptr(), PIPE_BUSY_WAIT_MS);
        }
    }
}

fn named_pipe_worker(path: PathBuf, shared: Arc<SharedState>) {
    let handle = match connect_named_pipe(&path, &shared) {
        Ok(handle) => handle,
        Err(error) => {
            shared.fail(error);
            return;
        }
    };
    {
        let mut state = shared.state.lock().unwrap();
        if state.terminate {
            return;
        }
        state.connection = ConnectionState::Connected;
    }
    let _ = shared.notifier.notify();

    loop {
        let mut progress = false;
        let outgoing = {
            let mut state = shared.state.lock().unwrap();
            if state.terminate {
                return;
            }
            let count = state.outgoing.len().min(IO_CHUNK_SIZE);
            let bytes = state.outgoing.drain(..count).collect::<Vec<_>>();
            if count > 0 {
                progress = true;
            }
            bytes
        };

        if !outgoing.is_empty() {
            let mut written = 0;
            let success = unsafe {
                WriteFile(
                    handle.raw(),
                    outgoing.as_ptr(),
                    outgoing.len() as u32,
                    &mut written,
                    std::ptr::null_mut(),
                )
            };
            if success == 0 {
                shared.fail(io::Error::last_os_error());
                return;
            }
            if written as usize != outgoing.len() {
                shared.fail(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "Windows named pipe accepted only part of a stream write",
                ));
                return;
            }
            let _ = shared.notifier.notify();
        }

        let read_capacity = {
            let state = shared.state.lock().unwrap();
            if state.read_shutdown {
                0
            } else {
                MAX_BUFFERED_BYTES.saturating_sub(state.incoming.len())
            }
        };
        if read_capacity > 0 {
            let mut available = 0;
            let peeked = unsafe {
                PeekNamedPipe(
                    handle.raw(),
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut available,
                    std::ptr::null_mut(),
                )
            };
            if peeked == 0 {
                shared.close();
                return;
            }
            if available > 0 {
                let count = (available as usize).min(read_capacity).min(IO_CHUNK_SIZE);
                let mut input = vec![0_u8; count];
                let mut read = 0;
                let success = unsafe {
                    ReadFile(
                        handle.raw(),
                        input.as_mut_ptr(),
                        count as u32,
                        &mut read,
                        std::ptr::null_mut(),
                    )
                };
                let error = (success == 0).then(io::Error::last_os_error);
                if let Some(error) = error
                    && error.raw_os_error() != Some(ERROR_MORE_DATA as i32)
                {
                    shared.fail(error);
                    return;
                }
                if read > 0 {
                    input.truncate(read as usize);
                    shared.state.lock().unwrap().incoming.extend(input);
                    let _ = shared.notifier.notify();
                    progress = true;
                }
            }
        }

        if !progress {
            let state = shared.state.lock().unwrap();
            let _ = shared.wake_worker.wait_timeout(state, WORKER_WAIT).unwrap();
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED;
    use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    use super::*;

    #[test]
    fn rejects_remote_and_ambiguous_pipe_paths() {
        assert!(validate_named_pipe_path(Path::new(r"\\.\pipe\api")).is_ok());
        assert!(validate_named_pipe_path(Path::new(r"\\server\pipe\api")).is_err());
        assert!(validate_named_pipe_path(Path::new(r"\\.\pipe\..\api")).is_err());
        assert!(validate_named_pipe_path(Path::new(r"C:\api")).is_err());
    }

    #[test]
    fn named_pipe_backend_moves_stream_bytes_in_both_directions() {
        let name = format!(r"\\.\pipe\msb-vsock-test-{}", std::process::id());
        let wide = wide_null(OsStr::new(&name));
        let server = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                std::ptr::null(),
            )
        };
        assert_ne!(server, INVALID_HANDLE_VALUE);
        let server = PipeHandle(server);
        let host = std::thread::spawn(move || {
            let connected = unsafe { ConnectNamedPipe(server.raw(), std::ptr::null_mut()) };
            if connected == 0 {
                assert_eq!(
                    io::Error::last_os_error().raw_os_error(),
                    Some(ERROR_PIPE_CONNECTED as i32)
                );
            }

            let mut request = [0_u8; 5];
            let mut read = 0;
            assert_ne!(
                unsafe {
                    ReadFile(
                        server.raw(),
                        request.as_mut_ptr(),
                        request.len() as u32,
                        &mut read,
                        std::ptr::null_mut(),
                    )
                },
                0
            );
            assert_eq!(&request[..read as usize], b"guest");

            let mut written = 0;
            assert_ne!(
                unsafe {
                    WriteFile(
                        server.raw(),
                        b"host".as_ptr(),
                        4,
                        &mut written,
                        std::ptr::null_mut(),
                    )
                },
                0
            );
            assert_eq!(written, 4);
        });

        let service = WindowsNamedPipePortBackend::new(&name).unwrap();
        let endpoint = service
            .connect(
                VsockConnectRequest {
                    guest_cid: 3,
                    guest_port: 4000,
                    host_port: 5000,
                },
                VsockNotifier::new().unwrap(),
            )
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while endpoint.connect_state().unwrap() != VsockConnectState::Connected {
            assert!(Instant::now() < deadline, "named-pipe connect timed out");
            std::thread::yield_now();
        }
        assert_eq!(endpoint.write(b"guest").unwrap(), 5);

        let mut response = [0_u8; 4];
        loop {
            match endpoint.read(&mut response) {
                Ok(4) => break,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "named-pipe read timed out");
                    std::thread::yield_now();
                }
                result => panic!("unexpected named-pipe read result: {result:?}"),
            }
        }
        assert_eq!(&response, b"host");
        host.join().unwrap();
    }
}
