//! Linux local-branch backing and descriptor transfer over the existing control connection.

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Seals that make a completed generation immutable, including through retained writer handles.
pub const MEMORY_SEALS: i32 =
    libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Create empty, anonymous backing. The launcher owns it before requesting any source mutation.
pub fn create() -> io::Result<File> {
    let fd = unsafe {
        libc::memfd_create(
            c"msb-branch-memory".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Reject anything other than a fresh writable, sealable memory object before capture.
pub fn validate_empty(file: &File) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    if !file.metadata()?.is_file()
        || file.metadata()?.len() != 0
        || flags < 0
        || flags & libc::O_ACCMODE != libc::O_RDWR
        || seals != 0
    {
        return Err(io::Error::other(
            "branch requires empty writable sealable memory backing",
        ));
    }
    Ok(())
}

/// Seal a completed generation and reopen it read-only for the existing private-mapping API.
pub fn seal(file: &File) -> io::Result<File> {
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, MEMORY_SEALS) } < 0 {
        return Err(io::Error::last_os_error());
    }
    readonly(file, file.metadata()?.len())
}

/// Validate the exact transferred object, then acquire a read-only handle with its own lifetime.
pub fn readonly(file: &File, length: u64) -> io::Result<File> {
    let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    if seals < 0 || seals & MEMORY_SEALS != MEMORY_SEALS || file.metadata()?.len() != length {
        return Err(io::Error::other(
            "branch memory is unsealed or differs from captured geometry",
        ));
    }
    // This path refers only to a descriptor already owned by this process. No remote PID or
    // pathname is used as authority, and the original handle remains alive through the open.
    File::open(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

/// Send the first JSON byte and one descriptor atomically. Nonblocking callers retry WouldBlock.
pub fn send_first(socket: RawFd, file: &File, byte: u8) -> io::Result<()> {
    let mut byte = byte;
    let mut iov = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    // usize storage supplies cmsghdr alignment; CMSG_SPACE includes trailing padding.
    let mut control = [0usize; 8];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&msg);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<RawFd>(), file.as_raw_fd());
    }
    loop {
        let sent = unsafe { libc::sendmsg(socket, &msg, libc::MSG_NOSIGNAL) };
        if sent == 1 {
            return Ok(());
        }
        if sent >= 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Receive the first JSON byte and optional descriptor without consuming later request bytes.
/// Extra/truncated rights are rejected and every descriptor received on an error is closed.
pub fn receive_first(socket: RawFd) -> io::Result<Option<(u8, Option<File>)>> {
    let mut byte = 0u8;
    let mut iov = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 16];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    loop {
        msg.msg_controllen = std::mem::size_of_val(&control);
        msg.msg_flags = 0;
        let received = unsafe { libc::recvmsg(socket, &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if received == 0 {
            return Ok(None);
        }
        if received > 0 {
            break;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
    let mut files = Vec::new();
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&msg);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let bytes = (*header)
                    .cmsg_len
                    .saturating_sub(libc::CMSG_LEN(0) as usize);
                for index in 0..bytes / std::mem::size_of::<RawFd>() {
                    let fd = std::ptr::read_unaligned(
                        libc::CMSG_DATA(header).cast::<RawFd>().add(index),
                    );
                    files.push(File::from_raw_fd(fd));
                }
            }
            header = libc::CMSG_NXTHDR(&msg, header);
        }
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 || files.len() > 1 {
        return Err(io::Error::other("invalid branch descriptor count"));
    }
    Ok(Some((byte, files.pop())))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    #[test]
    fn sealed_memory_keeps_private_child_writes_isolated() {
        let mut backing = create().unwrap();
        backing.write_all(&vec![7u8; 4096]).unwrap();
        let file = seal(&backing).unwrap();
        let a = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        let b = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        assert_ne!(a, libc::MAP_FAILED);
        assert_ne!(b, libc::MAP_FAILED);
        drop((backing, file));
        unsafe {
            *a.cast::<u8>() = 9;
            assert_eq!(*b.cast::<u8>(), 7);
            assert_eq!(*a.cast::<u8>(), 9);
            assert_eq!(libc::munmap(a, 4096), 0);
            assert_eq!(libc::munmap(b, 4096), 0);
        }
    }

    #[test]
    fn handoff_survives_sender_exit_and_seals_all_writer_handles() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let file = create().unwrap();
        validate_empty(&file).unwrap();
        send_first(sender.as_raw_fd(), &file, b'{').unwrap();
        let (byte, received) = receive_first(receiver.as_raw_fd()).unwrap().unwrap();
        assert_eq!(byte, b'{');
        let mut received = received.unwrap();
        assert_ne!(
            unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        received.write_all(b"captured").unwrap();
        let mut reader = seal(&received).unwrap();
        assert!(received.write_all(b"corrupt").is_err());
        assert!(file.set_len(0).is_err());
        drop((file, received, sender));
        let mut content = String::new();
        reader.read_to_string(&mut content).unwrap();
        assert_eq!(content, "captured");
    }

    #[test]
    fn ordinary_control_requests_do_not_require_a_descriptor() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        sender.write_all(b"{\"op\":\"pause\"}\n").unwrap();
        let (byte, fd) = receive_first(receiver.as_raw_fd()).unwrap().unwrap();
        assert_eq!(byte, b'{');
        assert!(fd.is_none());
    }

    #[test]
    fn unsealed_or_wrong_length_backing_is_rejected() {
        let file = create().unwrap();
        assert!(readonly(&file, 0).is_err());
        file.set_len(4096).unwrap();
        assert!(validate_empty(&file).is_err());
        seal(&file).unwrap();
        assert!(readonly(&file, 8192).is_err());
    }
}
