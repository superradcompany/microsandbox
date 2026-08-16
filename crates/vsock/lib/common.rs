use std::io;
#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(unix)]
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(unix)]
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
#[cfg(unix)]
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

pub(crate) const DEFAULT_MAX_ACTIVE_PEERS: usize = 256;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(crate) struct PeerLimit {
    active: Arc<AtomicUsize>,
    max: usize,
}

pub(crate) struct PeerLease {
    active: Arc<AtomicUsize>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PeerLimit {
    pub(crate) fn new(max: usize) -> Self {
        Self {
            active: Arc::new(AtomicUsize::new(0)),
            max,
        }
    }

    pub(crate) fn acquire(&self) -> io::Result<PeerLease> {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.max).then_some(active + 1)
            })
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "vsock route peer limit reached",
                )
            })?;
        Ok(PeerLease {
            active: Arc::clone(&self.active),
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for PeerLease {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[cfg(unix)]
pub(crate) fn validate_socket_path(path: &Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "vsock host socket path must be absolute",
        ));
    }
    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "vsock host socket path must not be empty",
        ));
    }
    nix::sys::socket::UnixAddr::new(path)
        .map(|_| ())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
}

#[cfg(unix)]
pub(crate) fn nonblocking_unix_socket(socket_type: SockType) -> io::Result<OwnedFd> {
    let fd = socket(AddressFamily::Unix, socket_type, SockFlag::empty(), None)
        .map_err(io::Error::from)?;

    // Some host implementations have historically ignored SOCK_NONBLOCK for
    // Unix sockets. Verify it explicitly so the VMM thread can never block.
    let flags = fcntl(&fd, FcntlArg::F_GETFL).map_err(io::Error::from)?;
    let flags = OFlag::from_bits_truncate(flags);
    fcntl(&fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).map_err(io::Error::from)?;
    let descriptor_flags = fcntl(&fd, FcntlArg::F_GETFD).map_err(io::Error::from)?;
    let descriptor_flags = FdFlag::from_bits_truncate(descriptor_flags);
    fcntl(
        &fd,
        FcntlArg::F_SETFD(descriptor_flags | FdFlag::FD_CLOEXEC),
    )
    .map_err(io::Error::from)?;

    #[cfg(target_os = "macos")]
    {
        let enabled: libc::c_int = 1;
        // SAFETY: `fd` is live and the option points to a correctly sized int.
        let result = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                &enabled as *const _ as *const libc::c_void,
                std::mem::size_of_val(&enabled) as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(fd)
}
