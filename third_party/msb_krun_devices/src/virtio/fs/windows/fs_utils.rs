use std::io;

use super::super::super::linux_errno::linux_error;

pub fn ebadf() -> io::Error {
    linux_error(io::Error::from_raw_os_error(libc::EBADF))
}

pub fn einval() -> io::Error {
    linux_error(io::Error::from_raw_os_error(libc::EINVAL))
}
