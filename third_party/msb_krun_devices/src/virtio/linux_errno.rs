const LINUX_EPERM: i32 = 1;
const LINUX_ENOENT: i32 = 2;
const LINUX_ESRCH: i32 = 3;
const LINUX_EINTR: i32 = 4;
const LINUX_EIO: i32 = 5;
const LINUX_ENXIO: i32 = 6;
const LINUX_ENOEXEC: i32 = 8;
const LINUX_EBADF: i32 = 9;
const LINUX_ECHILD: i32 = 10;
const LINUX_EAGAIN: i32 = 11;
const LINUX_ENOMEM: i32 = 12;
const LINUX_EACCES: i32 = 13;
const LINUX_EFAULT: i32 = 14;
#[cfg(not(target_os = "windows"))]
const LINUX_ENOTBLK: i32 = 15;
const LINUX_EBUSY: i32 = 16;
const LINUX_EEXIST: i32 = 17;
const LINUX_EXDEV: i32 = 18;
const LINUX_ENODEV: i32 = 19;
const LINUX_ENOTDIR: i32 = 20;
const LINUX_EISDIR: i32 = 21;
const LINUX_EINVAL: i32 = 22;
const LINUX_ENFILE: i32 = 23;
const LINUX_EMFILE: i32 = 24;
const LINUX_ENOTTY: i32 = 25;
const LINUX_ETXTBSY: i32 = 26;
const LINUX_EFBIG: i32 = 27;
const LINUX_ENOSPC: i32 = 28;
const LINUX_ESPIPE: i32 = 29;
const LINUX_EROFS: i32 = 30;
const LINUX_EMLINK: i32 = 31;
const LINUX_EPIPE: i32 = 32;
const LINUX_EDOM: i32 = 33;
const LINUX_EDEADLK: i32 = 35;
const LINUX_ENAMETOOLONG: i32 = 36;
const LINUX_ENOLCK: i32 = 37;
const LINUX_ENOSYS: i32 = 38;
const LINUX_ENOTEMPTY: i32 = 39;
const LINUX_ELOOP: i32 = 40;
const LINUX_ENOMSG: i32 = 42;
const LINUX_EIDRM: i32 = 43;
const LINUX_ENOSTR: i32 = 60;
const LINUX_ENODATA: i32 = 61;
const LINUX_ETIME: i32 = 62;
const LINUX_ENOSR: i32 = 63;
#[cfg(not(target_os = "windows"))]
const LINUX_EREMOTE: i32 = 66;
const LINUX_ENOLINK: i32 = 67;
const LINUX_EPROTO: i32 = 71;
#[cfg(not(target_os = "windows"))]
const LINUX_EMULTIHOP: i32 = 72;
const LINUX_EBADMSG: i32 = 74;
const LINUX_EOVERFLOW: i32 = 75;
const LINUX_EILSEQ: i32 = 84;
#[cfg(not(target_os = "windows"))]
const LINUX_EUSERS: i32 = 87;
const LINUX_ENOTSOCK: i32 = 88;
const LINUX_EDESTADDRREQ: i32 = 89;
const LINUX_EMSGSIZE: i32 = 90;
const LINUX_EPROTOTYPE: i32 = 91;
const LINUX_ENOPROTOOPT: i32 = 92;
const LINUX_EPROTONOSUPPORT: i32 = 93;
#[cfg(not(target_os = "windows"))]
const LINUX_ESOCKTNOSUPPORT: i32 = 94;
const LINUX_EOPNOTSUPP: i32 = 95;
#[cfg(not(target_os = "windows"))]
const LINUX_EPFNOSUPPORT: i32 = 96;
const LINUX_EAFNOSUPPORT: i32 = 97;
const LINUX_EADDRINUSE: i32 = 98;
const LINUX_EADDRNOTAVAIL: i32 = 99;
const LINUX_ENETDOWN: i32 = 100;
const LINUX_ENETUNREACH: i32 = 101;
const LINUX_ENETRESET: i32 = 102;
const LINUX_ECONNABORTED: i32 = 103;
const LINUX_ECONNRESET: i32 = 104;
const LINUX_ENOBUFS: i32 = 105;
const LINUX_EISCONN: i32 = 106;
const LINUX_ENOTCONN: i32 = 107;
#[cfg(not(target_os = "windows"))]
const LINUX_ESHUTDOWN: i32 = 108;
#[cfg(not(target_os = "windows"))]
const LINUX_ETOOMANYREFS: i32 = 109;
const LINUX_ETIMEDOUT: i32 = 110;
const LINUX_ECONNREFUSED: i32 = 111;
#[cfg(not(target_os = "windows"))]
const LINUX_EHOSTDOWN: i32 = 112;
const LINUX_EHOSTUNREACH: i32 = 113;
const LINUX_EALREADY: i32 = 114;
const LINUX_EINPROGRESS: i32 = 115;
#[cfg(not(target_os = "windows"))]
const LINUX_ESTALE: i32 = 116;
#[cfg(not(target_os = "windows"))]
const LINUX_EDQUOT: i32 = 122;
const LINUX_ECANCELED: i32 = 125;
const LINUX_EOWNERDEAD: i32 = 130;
const LINUX_ENOTRECOVERABLE: i32 = 131;

// Errors to be directly used.
pub const LINUX_ERANGE: i32 = 34;

pub fn linux_error(error: std::io::Error) -> std::io::Error {
    std::io::Error::from_raw_os_error(linux_errno_raw(error.raw_os_error().unwrap_or(libc::EIO)))
}

pub fn linux_errno_raw(errno: i32) -> i32 {
    match errno {
        libc::EPERM => LINUX_EPERM,
        libc::ENOENT => LINUX_ENOENT,
        libc::ESRCH => LINUX_ESRCH,
        libc::EINTR => LINUX_EINTR,
        libc::EIO => LINUX_EIO,
        libc::ENXIO => LINUX_ENXIO,
        libc::ENOEXEC => LINUX_ENOEXEC,
        libc::EBADF => LINUX_EBADF,
        libc::ECHILD => LINUX_ECHILD,
        libc::EDEADLK => LINUX_EDEADLK,
        libc::ENOMEM => LINUX_ENOMEM,
        libc::EACCES => LINUX_EACCES,
        libc::EFAULT => LINUX_EFAULT,
        #[cfg(not(target_os = "windows"))]
        libc::ENOTBLK => LINUX_ENOTBLK,
        libc::EBUSY => LINUX_EBUSY,
        libc::EEXIST => LINUX_EEXIST,
        libc::EXDEV => LINUX_EXDEV,
        libc::ENODEV => LINUX_ENODEV,
        libc::ENOTDIR => LINUX_ENOTDIR,
        libc::EISDIR => LINUX_EISDIR,
        libc::EINVAL => LINUX_EINVAL,
        libc::ENFILE => LINUX_ENFILE,
        libc::EMFILE => LINUX_EMFILE,
        libc::ENOTTY => LINUX_ENOTTY,
        libc::ETXTBSY => LINUX_ETXTBSY,
        libc::EFBIG => LINUX_EFBIG,
        libc::ENOSPC => LINUX_ENOSPC,
        libc::ESPIPE => LINUX_ESPIPE,
        libc::EROFS => LINUX_EROFS,
        libc::EMLINK => LINUX_EMLINK,
        libc::EPIPE => LINUX_EPIPE,
        libc::EDOM => LINUX_EDOM,
        libc::EAGAIN => LINUX_EAGAIN,
        libc::EINPROGRESS => LINUX_EINPROGRESS,
        libc::EALREADY => LINUX_EALREADY,
        libc::ENOTSOCK => LINUX_ENOTSOCK,
        libc::EDESTADDRREQ => LINUX_EDESTADDRREQ,
        libc::EMSGSIZE => LINUX_EMSGSIZE,
        libc::EPROTOTYPE => LINUX_EPROTOTYPE,
        libc::ENOPROTOOPT => LINUX_ENOPROTOOPT,
        libc::EPROTONOSUPPORT => LINUX_EPROTONOSUPPORT,
        #[cfg(not(target_os = "windows"))]
        libc::ESOCKTNOSUPPORT => LINUX_ESOCKTNOSUPPORT,
        #[cfg(not(target_os = "windows"))]
        libc::EPFNOSUPPORT => LINUX_EPFNOSUPPORT,
        libc::EAFNOSUPPORT => LINUX_EAFNOSUPPORT,
        libc::EADDRINUSE => LINUX_EADDRINUSE,
        libc::EADDRNOTAVAIL => LINUX_EADDRNOTAVAIL,
        libc::ENETDOWN => LINUX_ENETDOWN,
        libc::ENETUNREACH => LINUX_ENETUNREACH,
        libc::ENETRESET => LINUX_ENETRESET,
        libc::ECONNABORTED => LINUX_ECONNABORTED,
        libc::ECONNRESET => LINUX_ECONNRESET,
        libc::ENOBUFS => LINUX_ENOBUFS,
        libc::EISCONN => LINUX_EISCONN,
        libc::ENOTCONN => LINUX_ENOTCONN,
        #[cfg(not(target_os = "windows"))]
        libc::ESHUTDOWN => LINUX_ESHUTDOWN,
        #[cfg(not(target_os = "windows"))]
        libc::ETOOMANYREFS => LINUX_ETOOMANYREFS,
        libc::ETIMEDOUT => LINUX_ETIMEDOUT,
        libc::ECONNREFUSED => LINUX_ECONNREFUSED,
        libc::ELOOP => LINUX_ELOOP,
        libc::ENAMETOOLONG => LINUX_ENAMETOOLONG,
        #[cfg(not(target_os = "windows"))]
        libc::EHOSTDOWN => LINUX_EHOSTDOWN,
        libc::EHOSTUNREACH => LINUX_EHOSTUNREACH,
        libc::ENOTEMPTY => LINUX_ENOTEMPTY,
        #[cfg(not(target_os = "windows"))]
        libc::EUSERS => LINUX_EUSERS,
        #[cfg(not(target_os = "windows"))]
        libc::EDQUOT => LINUX_EDQUOT,
        #[cfg(not(target_os = "windows"))]
        libc::ESTALE => LINUX_ESTALE,
        #[cfg(not(target_os = "windows"))]
        libc::EREMOTE => LINUX_EREMOTE,
        libc::ENOLCK => LINUX_ENOLCK,
        libc::ENOSYS => LINUX_ENOSYS,
        libc::EOVERFLOW => LINUX_EOVERFLOW,
        libc::ECANCELED => LINUX_ECANCELED,
        libc::EIDRM => LINUX_EIDRM,
        libc::ENOMSG => LINUX_ENOMSG,
        libc::EILSEQ => LINUX_EILSEQ,
        #[cfg(target_os = "macos")]
        libc::ENOATTR => LINUX_ENODATA,
        libc::EBADMSG => LINUX_EBADMSG,
        #[cfg(not(target_os = "windows"))]
        libc::EMULTIHOP => LINUX_EMULTIHOP,
        libc::ENODATA => LINUX_ENODATA,
        libc::ENOLINK => LINUX_ENOLINK,
        libc::ENOSR => LINUX_ENOSR,
        libc::ENOSTR => LINUX_ENOSTR,
        libc::EPROTO => LINUX_EPROTO,
        libc::ETIME => LINUX_ETIME,
        libc::EOPNOTSUPP => LINUX_EOPNOTSUPP,
        libc::ENOTRECOVERABLE => LINUX_ENOTRECOVERABLE,
        libc::EOWNERDEAD => LINUX_EOWNERDEAD,
        _ => LINUX_EIO,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_supported_host_errno_values() {
        assert_eq!(linux_errno_raw(libc::ENOSYS), LINUX_ENOSYS);
        assert_eq!(linux_errno_raw(libc::EPROTO), LINUX_EPROTO);
        assert_eq!(linux_errno_raw(libc::EOVERFLOW), LINUX_EOVERFLOW);
    }

    #[test]
    fn unknown_host_errno_falls_back_to_linux_eio() {
        assert_eq!(linux_errno_raw(i32::MAX), LINUX_EIO);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn translates_windows_enosys_collision() {
        // Windows ENOSYS numerically collides with Linux ELOOP, which caused the original bug.
        assert_eq!(libc::ENOSYS, LINUX_ELOOP);

        let error = linux_error(std::io::Error::from_raw_os_error(libc::ENOSYS));
        assert_eq!(error.raw_os_error(), Some(LINUX_ENOSYS));
    }
}
