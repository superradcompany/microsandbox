//! Cancel synchronous pipe/console I/O on its dedicated native worker.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::task::{Context, Poll, ready};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;
use windows_sys::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
use windows_sys::Win32::System::IO::CancelSynchronousIo;
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use super::Lease;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const BUFFER_SIZE: usize = 8192;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(crate) struct Stdio {
    requests: Option<mpsc::Sender<Request>>,
    worker: Option<JoinHandle<()>>,
    cancelled: Arc<AtomicBool>,
    reading: Option<oneshot::Receiver<io::Result<Vec<u8>>>>,
    writing: Option<oneshot::Receiver<io::Result<()>>>,
    buffered: Vec<u8>,
    offset: usize,
    _lease: Lease,
}

enum Request {
    Read(oneshot::Sender<io::Result<Vec<u8>>>),
    Write(Vec<u8>, oneshot::Sender<io::Result<()>>),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Stdio {
    pub(super) fn new(input: bool, lease: Lease) -> io::Result<Self> {
        let kind = if input {
            STD_INPUT_HANDLE
        } else {
            STD_OUTPUT_HANDLE
        };
        // Own a duplicate so cancellation never closes the caller's std handle.
        let source = unsafe { GetStdHandle(kind) };
        if source.is_null() || source == INVALID_HANDLE_VALUE {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "stdio handle is unavailable",
            ));
        }
        let mut duplicated = std::ptr::null_mut();
        let process = unsafe { GetCurrentProcess() };
        if unsafe {
            DuplicateHandle(
                process,
                source,
                process,
                &mut duplicated,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_handle(duplicated) };
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = cancelled.clone();
        let (requests, receiver) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("microsandbox-stdio".into())
            .spawn(move || run(file, receiver, worker_cancelled))?;
        Ok(Self {
            requests: Some(requests),
            worker: Some(worker),
            cancelled,
            reading: None,
            writing: None,
            buffered: Vec::new(),
            offset: 0,
            _lease: lease,
        })
    }

    fn send(&self, request: Request) -> io::Result<()> {
        self.requests
            .as_ref()
            .expect("stdio worker is live before drop")
            .send(request)
            .map_err(|_| worker_stopped())
    }

    fn poll_written(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(receiver) = &mut self.writing {
            let result = ready!(Pin::new(receiver).poll(cx));
            self.writing = None;
            result.map_err(|_| worker_stopped())??;
        }
        Poll::Ready(Ok(()))
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for Stdio {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        self.requests.take();
        if let Some(worker) = self.worker.take() {
            // A single cancel can race with the worker entering ReadFile after
            // checking the flag. Keep cancelling until it exits; this also joins
            // the worker, so it cannot consume another operation's stdin later.
            while !worker.is_finished() {
                unsafe { CancelSynchronousIo(worker.as_raw_handle() as HANDLE) };
                thread::sleep(Duration::from_millis(1));
            }
            let _ = worker.join();
        }
    }
}

impl AsyncRead for Stdio {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.offset == this.buffered.len() {
            if this.reading.is_none() {
                let (sender, receiver) = oneshot::channel();
                this.send(Request::Read(sender))?;
                this.reading = Some(receiver);
            }
            let receiver = this.reading.as_mut().expect("read request initialized");
            let result = ready!(Pin::new(receiver).poll(cx));
            this.reading = None;
            this.buffered = result.map_err(|_| worker_stopped())??;
            this.offset = 0;
        }
        // A cancelled read can be resumed with a smaller caller buffer.
        let count = buf.remaining().min(this.buffered.len() - this.offset);
        buf.put_slice(&this.buffered[this.offset..this.offset + count]);
        this.offset += count;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Stdio {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_written(cx))?;
        let count = buf.len().min(BUFFER_SIZE);
        if count == 0 {
            return Poll::Ready(Ok(0));
        }
        let (sender, receiver) = oneshot::channel();
        this.send(Request::Write(buf[..count].to_vec(), sender))?;
        this.writing = Some(receiver);
        // Acknowledge buffer ownership now. Flush/the next write waits for the
        // OS result; cancellation must not replay these bytes with a new buffer.
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_written(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn run(mut file: File, receiver: mpsc::Receiver<Request>, cancelled: Arc<AtomicBool>) {
    while let Ok(request) = receiver.recv() {
        if cancelled.load(Ordering::Acquire) {
            break;
        }
        match request {
            Request::Read(reply) => {
                let mut buffer = vec![0; BUFFER_SIZE];
                let result = file.read(&mut buffer).map(|count| {
                    buffer.truncate(count);
                    buffer
                });
                let _ = reply.send(result);
            }
            Request::Write(buffer, reply) => {
                let _ = reply.send(write(&mut file, &buffer, &cancelled));
            }
        }
    }
}

fn write(file: &mut File, mut buffer: &[u8], cancelled: &AtomicBool) -> io::Result<()> {
    while !buffer.is_empty() {
        if cancelled.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "stdio write cancelled",
            ));
        }
        // write_all retries Interrupted unconditionally. Observe cancellation
        // between writes so CancelSynchronousIo cannot cause an endless retry.
        match file.write(buffer) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => buffer = &buffer[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn worker_stopped() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "stdio worker stopped")
}
