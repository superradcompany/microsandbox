//! Guest-side ID map preparation, without changing filesystem ownership.

use std::fmt::Write;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use microsandbox_protocol::isolation::{
    WorkloadIdMapping, WorkloadIsolation, WorkloadUserNamespace,
};
use rustix::mount::{self, FsMountFlags, FsOpenFlags, MountAttrFlags, MoveMountFlags};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(crate) struct PreparedUserNamespace {
    proc: File,
    uid_map: String,
    gid_map: String,
    parent: OwnedFd,
    child: OwnedFd,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PreparedUserNamespace {
    pub(crate) fn new(policy: &WorkloadUserNamespace) -> io::Result<Self> {
        policy.validate().map_err(io::Error::other)?;
        let uid_map = format_map(&policy.uid_mappings)?;
        let gid_map = format_map(&policy.gid_mappings)?;
        let proc = File::open("/proc")?;
        let (parent, child) = mount_socket_pair()?;

        // Initial NEWUSER creation cannot use CLONE_PARENT. Adopt the application
        // when its short-lived launcher exits, including when agentd is not PID 1.
        if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            proc,
            uid_map,
            gid_map,
            parent,
            child,
        })
    }

    /// Only called by the privileged launcher, before releasing the child gate.
    pub(crate) fn write_maps(&self, pid: i32) -> io::Result<()> {
        self.write_map(pid, b"/uid_map\0", &self.uid_map)?;
        // The mapper has CAP_SETGID in the parent guest namespace. Keep setgroups
        // enabled so the application's requested supplementary groups still work.
        self.write_map(pid, b"/gid_map\0", &self.gid_map)
    }

    /// The child creates filesystem contexts in its PID/IPC/cgroup namespaces.
    /// The privileged launcher attaches them to the child's private mount tree.
    pub(crate) fn prepare_mounts(&self, policy: &WorkloadIsolation) -> io::Result<()> {
        for (_, kind, _) in special_mounts(policy) {
            let context = mount::fsopen(kind, FsOpenFlags::FSOPEN_CLOEXEC)?;
            mount::fsconfig_create(&context)?;
            send_context(self.child.as_raw_fd(), context.as_raw_fd())?;
        }
        let mut ack = 0u8;
        if unsafe { libc::recv(self.child.as_raw_fd(), (&mut ack as *mut u8).cast(), 1, 0) } != 1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(crate) fn attach_mounts(&self, policy: &WorkloadIsolation, pid: i32) -> io::Result<()> {
        let mut mounts: [Option<OwnedFd>; 3] = [None, None, None];
        for (index, (_, _, readonly)) in special_mounts(policy).enumerate() {
            let context = receive_context(self.parent.as_raw_fd())?;
            let mut attributes = MountAttrFlags::MOUNT_ATTR_NOSUID
                | MountAttrFlags::MOUNT_ATTR_NODEV
                | MountAttrFlags::MOUNT_ATTR_NOEXEC;
            if readonly {
                attributes |= MountAttrFlags::MOUNT_ATTR_RDONLY;
            }
            let filesystem = mount::fsmount(&context, FsMountFlags::FSMOUNT_CLOEXEC, attributes)?;
            mounts[index] = Some(filesystem);
        }
        // Create mounts in the privileged staging namespace, then attach them in
        // the application tree. Its empty /proc cannot pass mount-too-revealing checks.
        let namespace = self.open_child(pid, b"/ns/mnt\0", libc::O_RDONLY)?;
        let root = self.open_child(pid, b"/root\0", libc::O_RDONLY | libc::O_DIRECTORY)?;
        if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNS) } < 0
            || unsafe { libc::fchdir(root.as_raw_fd()) } < 0
            || unsafe { libc::chroot(c".".as_ptr()) } < 0
            || unsafe { libc::chdir(c"/".as_ptr()) } < 0
        {
            return Err(io::Error::last_os_error());
        }
        for ((path, _, _), filesystem) in special_mounts(policy).zip(mounts) {
            let filesystem = filesystem.ok_or_else(|| io::Error::from_raw_os_error(libc::EIO))?;
            mount::move_mount(
                &filesystem,
                c"",
                rustix::fs::CWD,
                path,
                MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
            )?;
        }
        if unsafe {
            libc::send(
                self.parent.as_raw_fd(),
                b"!".as_ptr().cast(),
                1,
                libc::MSG_NOSIGNAL,
            )
        } != 1
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn write_map(&self, pid: i32, suffix: &[u8], contents: &str) -> io::Result<()> {
        let fd = self.open_child(pid, suffix, libc::O_WRONLY | libc::O_NOFOLLOW)?;
        loop {
            let written =
                unsafe { libc::write(fd.as_raw_fd(), contents.as_ptr().cast(), contents.len()) };
            if written == contents.len() as isize {
                return Ok(());
            }
            if written >= 0 {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    fn open_child(&self, pid: i32, suffix: &[u8], flags: i32) -> io::Result<OwnedFd> {
        // Format the kernel-provided PID on the stack: no allocation after fork.
        let mut path = [0u8; 32];
        let mut cursor = 11;
        let mut number = pid as u32;
        loop {
            cursor -= 1;
            path[cursor] = b'0' + (number % 10) as u8;
            number /= 10;
            if number == 0 {
                break;
            }
        }
        path[11..11 + suffix.len()].copy_from_slice(suffix);
        let raw = unsafe {
            libc::openat(
                self.proc.as_raw_fd(),
                path[cursor..].as_ptr().cast(),
                flags | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn format_map(mappings: &[WorkloadIdMapping]) -> io::Result<String> {
    let mut result = String::new();
    for mapping in mappings {
        writeln!(
            result,
            "{} {} {}",
            mapping.container_id, mapping.guest_id, mapping.size
        )
        .map_err(io::Error::other)?;
    }
    // Linux requires the whole mapping in one write, smaller than a page.
    if result.len() >= 4096 {
        return Err(io::Error::other("user namespace ID map exceeds 4095 bytes"));
    }
    Ok(result)
}

fn special_mounts(
    policy: &WorkloadIsolation,
) -> impl Iterator<Item = (&'static std::ffi::CStr, &'static std::ffi::CStr, bool)> {
    [
        (true, c"/proc", c"proc", false),
        (policy.cgroup, c"/sys/fs/cgroup", c"cgroup2", true),
        (policy.ipc, c"/dev/mqueue", c"mqueue", false),
    ]
    .into_iter()
    .filter(|(enabled, ..)| *enabled)
    .map(|(_, path, kind, readonly)| (path, kind, readonly))
}

fn mount_socket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let pair = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let timeout = libc::timeval {
        tv_sec: 5,
        tv_usec: 0,
    };
    for fd in [&pair.0, &pair.1] {
        if unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&timeout as *const libc::timeval).cast(),
                size_of_val(&timeout) as _,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(pair)
}

fn send_context(socket: RawFd, fd: RawFd) -> io::Result<()> {
    let mut byte = 0u8;
    let mut iov = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 4];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as _) } as _;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as _) as _;
        *libc::CMSG_DATA(header).cast::<RawFd>() = fd;
        if libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL) != 1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn receive_context(socket: RawFd) -> io::Result<OwnedFd> {
    let mut byte = 0u8;
    let mut iov = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 4];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = size_of_val(&control) as _;
    let mut result = None;
    let received = unsafe { libc::recvmsg(socket, &mut message, libc::MSG_CMSG_CLOEXEC) };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut count = 0;
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let entries =
                    ((*header).cmsg_len as usize - libc::CMSG_LEN(0) as usize) / size_of::<RawFd>();
                for index in 0..entries {
                    result = Some(OwnedFd::from_raw_fd(
                        *libc::CMSG_DATA(header).cast::<RawFd>().add(index),
                    ));
                    count += 1;
                }
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    if received != 1 || count != 1 || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
    {
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }
    result.ok_or_else(|| io::Error::from_raw_os_error(libc::EIO))
}
