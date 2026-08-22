//! OCI console bridging between containerd's host PTY and the guest process.

use std::io::ErrorKind;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use microsandbox::sandbox::exec::{ExecControl, ExecEvent, ExecHandle};
use microsandbox_runtime::oci::OciProcess;
use tokio::io::unix::AsyncFd;

use crate::process::{HostSignalForwarder, forward_host_signal};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const CONSOLE_RESIZE_POLL_INTERVAL: Duration = Duration::from_millis(250);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PtySize {
    pub(crate) rows: u16,
    pub(crate) cols: u16,
}

pub(crate) struct ConsoleBridge {
    fd: AsyncFd<OwnedFd>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) async fn wait_for_console_process_exit(
    id: &str,
    handle: &mut ExecHandle,
    console: &ConsoleBridge,
    host_signals: &mut HostSignalForwarder,
) -> Result<i32> {
    let stdin = handle
        .take_stdin()
        .ok_or_else(|| anyhow!("container `{id}` requested an OCI console without piped stdin"))?;
    let control = handle.control();
    let mut last_size = None;
    sync_console_size(&control, console, &mut last_size).await?;
    let mut resize_poll = tokio::time::interval(CONSOLE_RESIZE_POLL_INTERVAL);
    let mut input = [0u8; 4096];

    loop {
        tokio::select! {
            signal = host_signals.recv() => {
                forward_host_signal(&control, signal).await?;
            }
            _ = resize_poll.tick() => {
                sync_console_size(&control, console, &mut last_size).await?;
            }
            read = read_console_input(console, &mut input) => {
                match read.context("read OCI console input")? {
                    0 => {
                        let _ = stdin.close().await;
                    }
                    n => {
                        stdin.write(&input[..n]).await.context("write OCI console input to guest")?;
                    }
                }
            }
            event = handle.recv() => {
                match event {
                    Some(ExecEvent::Exited { code }) => return Ok(code),
                    Some(ExecEvent::Failed(payload)) => {
                        return Err(microsandbox::MicrosandboxError::ExecFailed(payload).into());
                    }
                    Some(ExecEvent::Stdout(data)) | Some(ExecEvent::Stderr(data)) => {
                        write_console_output(console, &data).await.context("write OCI console output")?;
                    }
                    Some(ExecEvent::Started { .. }) | Some(ExecEvent::StdinError(_)) => {}
                    None => bail!("OCI init process stream ended before exit event for `{id}`"),
                }
            }
        }
    }
}

pub(crate) fn open_console_bridge(path: &Path) -> Result<ConsoleBridge> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("open OCI console slave `{}`", path.display()))?;
    let fd: OwnedFd = file.into();
    set_nonblocking(fd.as_raw_fd()).context("set OCI console slave nonblocking")?;
    let fd = AsyncFd::new(fd).context("register OCI console slave with tokio")?;
    Ok(ConsoleBridge { fd })
}

pub(crate) fn process_console_size(process: &OciProcess) -> Option<PtySize> {
    let size = process.console_size()?;
    pty_size_from_rows_cols(size.height(), size.width())
}

async fn sync_console_size(
    control: &ExecControl,
    console: &ConsoleBridge,
    last_size: &mut Option<PtySize>,
) -> Result<()> {
    let Some(size) = console_size_from_fd(console.fd.get_ref().as_raw_fd()) else {
        return Ok(());
    };
    if Some(size) == *last_size {
        return Ok(());
    }

    control
        .resize(size.rows, size.cols)
        .await
        .context("resize OCI console PTY in guest")?;
    *last_size = Some(size);
    Ok(())
}

fn console_size_from_fd(fd: i32) -> Option<PtySize> {
    let mut size = std::mem::MaybeUninit::<libc::winsize>::zeroed();
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, size.as_mut_ptr()) } < 0 {
        return None;
    }
    let size = unsafe { size.assume_init() };
    pty_size_from_rows_cols(u64::from(size.ws_row), u64::from(size.ws_col))
}

fn pty_size_from_rows_cols(rows: u64, cols: u64) -> Option<PtySize> {
    if rows == 0 || cols == 0 {
        return None;
    }
    Some(PtySize {
        rows: rows.min(u64::from(u16::MAX)) as u16,
        cols: cols.min(u64::from(u16::MAX)) as u16,
    })
}

async fn read_console_input(console: &ConsoleBridge, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
        let mut guard = console.fd.readable().await?;
        match guard.try_io(|inner| read_fd(inner.get_ref().as_raw_fd(), buf)) {
            Ok(result) => return result,
            Err(_) => continue,
        }
    }
}

async fn write_console_output(console: &ConsoleBridge, mut data: &[u8]) -> std::io::Result<()> {
    while !data.is_empty() {
        let mut guard = console.fd.writable().await?;
        match guard.try_io(|inner| write_fd(inner.get_ref().as_raw_fd(), data)) {
            Ok(Ok(0)) => {
                return Err(std::io::Error::new(
                    ErrorKind::WriteZero,
                    "console write returned zero",
                ));
            }
            Ok(Ok(n)) => data = &data[n..],
            Ok(Err(error)) if error.kind() == ErrorKind::Interrupted => continue,
            Ok(Err(error)) => return Err(error),
            Err(_) => continue,
        }
    }
    Ok(())
}

fn read_fd(fd: i32, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == ErrorKind::Interrupted {
            continue;
        }
        return Err(error);
    }
}

fn write_fd(fd: i32, buf: &[u8]) -> std::io::Result<usize> {
    loop {
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == ErrorKind::Interrupted {
            continue;
        }
        return Err(error);
    }
}

fn set_nonblocking(fd: i32) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::os::fd::{AsRawFd, OwnedFd};

    use nix::fcntl::OFlag;
    use nix::pty::{grantpt, posix_openpt, ptsname_r, unlockpt};

    use super::*;

    #[test]
    fn console_size_from_fd_reads_pty_window_size() {
        let master = posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY).expect("open pty master");
        grantpt(&master).expect("grant pty");
        unlockpt(&master).expect("unlock pty");
        let slave_path = ptsname_r(&master).expect("pty slave path");
        let slave = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(slave_path)
            .expect("open pty slave");
        let fd: OwnedFd = slave.into();
        let size = libc::winsize {
            ws_row: 42,
            ws_col: 132,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        assert_eq!(
            unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ, &size) },
            0
        );
        assert_eq!(
            console_size_from_fd(fd.as_raw_fd()),
            Some(PtySize {
                rows: 42,
                cols: 132
            })
        );
    }

    #[test]
    fn pty_size_ignores_zero_and_clamps_large_values() {
        assert_eq!(pty_size_from_rows_cols(0, 80), None);
        assert_eq!(pty_size_from_rows_cols(24, 0), None);
        assert_eq!(
            pty_size_from_rows_cols(u64::MAX, u64::MAX),
            Some(PtySize {
                rows: u16::MAX,
                cols: u16::MAX,
            })
        );
    }
}
