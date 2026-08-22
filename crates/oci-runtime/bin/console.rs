//! OCI console socket and PTY handling.

use std::io::IoSlice;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use anyhow::{Context, Result};
use nix::fcntl::OFlag;
use nix::pty::{PtyMaster, grantpt, posix_openpt, ptsname_r, unlockpt};
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use nix::sys::termios::{self, SetArg};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const PTY_MASTER_NAME: &[u8] = b"/dev/ptmx";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug)]
pub(crate) struct OciConsole {
    master: PtyMaster,
    slave: OwnedFd,
    slave_path: PathBuf,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl OciConsole {
    pub(crate) fn slave_path(&self) -> &PathBuf {
        &self.slave_path
    }

    pub(crate) fn into_slave(self) -> OwnedFd {
        self.slave
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn setup_oci_console(console_socket: Option<&PathBuf>) -> Result<Option<OciConsole>> {
    let Some(console_socket) = console_socket else {
        return Ok(None);
    };

    let console = open_oci_console_pty().context("open OCI console PTY")?;
    send_console_fd(console_socket, console.master.as_raw_fd(), PTY_MASTER_NAME)
        .with_context(|| format!("send OCI console fd to `{}`", console_socket.display()))?;
    Ok(Some(console))
}

fn open_oci_console_pty() -> Result<OciConsole> {
    let master = posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC)?;
    grantpt(&master)?;
    unlockpt(&master)?;
    let slave_path = PathBuf::from(ptsname_r(&master)?);
    let slave = configure_console_slave(&slave_path).context("configure OCI console slave")?;
    Ok(OciConsole {
        master,
        slave,
        slave_path,
    })
}

fn configure_console_slave(path: &PathBuf) -> Result<OwnedFd> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("open OCI console slave `{}`", path.display()))?;
    let fd: OwnedFd = file.into();
    let mut attrs = termios::tcgetattr(&fd).context("read OCI console termios")?;
    termios::cfmakeraw(&mut attrs);
    attrs
        .output_flags
        .remove(termios::OutputFlags::OPOST | termios::OutputFlags::ONLCR);
    termios::tcsetattr(&fd, SetArg::TCSANOW, &attrs).context("set OCI console termios")?;
    Ok(fd)
}

fn send_console_fd(console_socket: &PathBuf, fd: i32, name: &[u8]) -> Result<()> {
    let stream = UnixStream::connect(console_socket)
        .with_context(|| format!("connect OCI console socket `{}`", console_socket.display()))?;
    send_console_fd_to_stream(&stream, fd, name)
}

fn send_console_fd_to_stream(stream: &UnixStream, fd: i32, name: &[u8]) -> Result<()> {
    let iov = [IoSlice::new(name)];
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
    use std::io::IoSliceMut;
    use std::os::fd::FromRawFd;

    use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
    use nix::sys::termios::{LocalFlags, OutputFlags};

    use super::*;

    #[test]
    fn open_oci_console_pty_returns_existing_slave() {
        let console = open_oci_console_pty().expect("open console pty");

        assert!(console.slave_path.starts_with("/dev/pts/"));
        assert!(console.slave_path.exists());
    }

    #[test]
    fn open_oci_console_pty_keeps_host_slave_fully_raw() {
        let console = open_oci_console_pty().expect("open console pty");
        let attrs = termios::tcgetattr(&console.slave).expect("read console termios");

        assert!(!attrs.local_flags.contains(LocalFlags::ECHO));
        assert!(!attrs.local_flags.contains(LocalFlags::ICANON));
        assert!(!attrs.output_flags.contains(OutputFlags::OPOST));
        assert!(!attrs.output_flags.contains(OutputFlags::ONLCR));
    }

    #[test]
    fn host_console_does_not_translate_guest_newlines_again() {
        let console = open_oci_console_pty().expect("open console pty");
        let newline = b"\n";
        let written = unsafe {
            libc::write(
                console.slave.as_raw_fd(),
                newline.as_ptr().cast(),
                newline.len(),
            )
        };
        assert_eq!(written, newline.len() as isize);

        let mut output = [0u8; 4];
        let read = unsafe {
            libc::read(
                console.master.as_raw_fd(),
                output.as_mut_ptr().cast(),
                output.len(),
            )
        };

        assert_eq!(&output[..read as usize], b"\n");
    }

    #[test]
    fn setup_oci_console_sends_named_pty_master() {
        let console = open_oci_console_pty().expect("open console PTY");
        let (sender, receiver) = UnixStream::pair().expect("create console socket pair");
        send_console_fd_to_stream(&sender, console.master.as_raw_fd(), PTY_MASTER_NAME)
            .expect("send console descriptor");

        let mut name = [0u8; 64];
        let mut iov = [IoSliceMut::new(&mut name)];
        let mut cmsg_buffer = nix::cmsg_space!([i32; 1]);
        let (name_len, descriptor) = {
            let message = recvmsg::<()>(
                receiver.as_raw_fd(),
                &mut iov,
                Some(&mut cmsg_buffer),
                MsgFlags::empty(),
            )
            .expect("receive console descriptor");
            let descriptor = message
                .cmsgs()
                .expect("parse console control messages")
                .find_map(|message| match message {
                    ControlMessageOwned::ScmRights(mut descriptors) => descriptors.pop(),
                    _ => None,
                })
                .expect("receive PTY master descriptor");
            (message.bytes, descriptor)
        };
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };

        let name = name[..name_len].to_vec();
        let is_terminal = termios::tcgetattr(&descriptor).is_ok();

        assert_eq!(name, PTY_MASTER_NAME);
        assert!(is_terminal);
    }
}
