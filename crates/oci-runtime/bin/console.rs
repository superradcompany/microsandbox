//! OCI console socket and PTY handling.

use std::io::IoSlice;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use anyhow::{Context, Result};
use nix::fcntl::OFlag;
use nix::pty::{PtyMaster, grantpt, posix_openpt, ptsname_r, unlockpt};
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug)]
struct OciConsole {
    master: PtyMaster,
    slave_path: PathBuf,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn setup_oci_console(console_socket: Option<&PathBuf>) -> Result<Option<PathBuf>> {
    let Some(console_socket) = console_socket else {
        return Ok(None);
    };

    let console = open_oci_console_pty().context("open OCI console PTY")?;
    send_console_fd(console_socket, console.master.as_raw_fd())
        .with_context(|| format!("send OCI console fd to `{}`", console_socket.display()))?;
    Ok(Some(console.slave_path))
}

fn open_oci_console_pty() -> Result<OciConsole> {
    let master = posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC)?;
    grantpt(&master)?;
    unlockpt(&master)?;
    let slave_path = PathBuf::from(ptsname_r(&master)?);
    Ok(OciConsole { master, slave_path })
}

fn send_console_fd(console_socket: &PathBuf, fd: i32) -> Result<()> {
    let stream = UnixStream::connect(console_socket)
        .with_context(|| format!("connect OCI console socket `{}`", console_socket.display()))?;
    let data = [0u8];
    let iov = [IoSlice::new(&data)];
    let fds = [fd];
    let cmsg = [ControlMessage::ScmRights(&fds)];
    sendmsg::<()>(stream.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)?;
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_oci_console_pty_returns_existing_slave() {
        let console = open_oci_console_pty().expect("open console pty");

        assert!(console.slave_path.starts_with("/dev/pts/"));
        assert!(console.slave_path.exists());
    }
}
