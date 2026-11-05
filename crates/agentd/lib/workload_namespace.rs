//! One guest namespace domain shared by OCI init and exec processes.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex};

use microsandbox_protocol::isolation::WorkloadIsolation;
use rustix::mount::{self, FsMountFlags, FsOpenFlags, MountAttrFlags, MoveMountFlags};

use crate::workload::WorkloadPlacement;
use crate::workload_user_namespace::PreparedUserNamespace;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const NAMESPACES: [(i32, &std::ffi::CStr); 7] = [
    (libc::CLONE_NEWUSER, c"/proc/self/ns/user"),
    (libc::CLONE_NEWNS, c"/proc/self/ns/mnt"),
    (libc::CLONE_NEWIPC, c"/proc/self/ns/ipc"),
    (libc::CLONE_NEWUTS, c"/proc/self/ns/uts"),
    (libc::CLONE_NEWPID, c"/proc/self/ns/pid"),
    (libc::CLONE_NEWCGROUP, c"/proc/self/ns/cgroup"),
    (libc::CLONE_NEWTIME, c"/proc/self/ns/time"),
];

// libc 0.2.190's GNU constant is truncated to c_int; clone3 requires the 64-bit flag.
const CLONE_INTO_CGROUP: u64 = 1 << 33;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(crate) struct NamespaceDomain {
    policy: WorkloadIsolation,
    state: Mutex<DomainState>,
}

enum DomainState {
    Fresh,
    Ready(Vec<OwnedFd>),
    Failed,
}

pub(crate) struct NamespaceParent {
    socket: OwnedFd,
    domain: Arc<NamespaceDomain>,
    initial: bool,
}

pub(crate) struct NamespaceChild {
    socket: OwnedFd,
    pid_read: OwnedFd,
    pid_write: OwnedFd,
    policy: WorkloadIsolation,
    handles: Vec<OwnedFd>,
    initial: bool,
    time_offsets: Vec<String>,
    user_namespace: Option<PreparedUserNamespace>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl NamespaceDomain {
    pub(crate) fn validate_user(&self, uid: u32, gid: u32) -> io::Result<()> {
        if let Some(user) = &self.policy.user {
            for (id, mappings) in [(uid, &user.uid_mappings), (gid, &user.gid_mappings)] {
                if !mappings.iter().any(|mapping| {
                    id >= mapping.container_id
                        && u64::from(id) < u64::from(mapping.container_id) + u64::from(mapping.size)
                }) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "requested application UID or GID is not mapped in the workload user namespace",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn new(policy: WorkloadIsolation) -> io::Result<Arc<Self>> {
        if (policy.pid || policy.cgroup || policy.ipc) && !policy.mount {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "guest PID, IPC and cgroup namespaces require a private mount namespace",
            ));
        }
        if let Some(user) = &policy.user {
            user.validate().map_err(io::Error::other)?;
            if !policy.pid || !policy.mount {
                return Err(io::Error::other(
                    "guest user namespaces require private PID and mount namespaces",
                ));
            }
        }
        if policy.hostname.as_ref().is_some_and(|name| {
            !policy.uts || name.is_empty() || name.len() > 63 || name.as_bytes().contains(&0)
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid workload hostname",
            ));
        }
        if let Some(time) = &policy.time {
            for offset in [&time.monotonic, &time.boottime].into_iter().flatten() {
                if offset.nanoseconds >= 1_000_000_000 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid time namespace nanoseconds",
                    ));
                }
            }
        }
        Ok(Arc::new(Self {
            policy,
            state: Mutex::new(DomainState::Fresh),
        }))
    }

    pub(crate) fn prepare(self: &Arc<Self>) -> io::Result<(NamespaceParent, NamespaceChild)> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("namespace state poisoned"))?;
        let (initial, handles) = match &*state {
            DomainState::Fresh => (true, Vec::new()),
            DomainState::Ready(handles) => (
                false,
                handles
                    .iter()
                    .map(OwnedFd::try_clone)
                    .collect::<io::Result<Vec<_>>>()?,
            ),
            DomainState::Failed => {
                return Err(io::Error::other("workload namespace initialization failed"));
            }
        };
        let (parent, child) = socket_pair()?;
        let (pid_read, pid_write) = pipe_pair()?;
        // Format before fork: the child's pre-exec path must not allocate.
        let mut time_offsets = Vec::new();
        if let Some(time) = &self.policy.time {
            for (clock, offset) in [("monotonic", &time.monotonic), ("boottime", &time.boottime)] {
                if let Some(offset) = offset {
                    time_offsets.push(format!(
                        "{clock} {} {}\n",
                        offset.seconds, offset.nanoseconds
                    ));
                }
            }
        }
        if initial {
            *state = DomainState::Failed;
        }
        let user_namespace = if initial {
            self.policy
                .user
                .as_ref()
                .map(PreparedUserNamespace::new)
                .transpose()?
        } else {
            None
        };
        Ok((
            NamespaceParent {
                socket: parent,
                domain: Arc::clone(self),
                initial,
            },
            NamespaceChild {
                socket: child,
                pid_read,
                pid_write,
                policy: self.policy.clone(),
                handles,
                initial,
                time_offsets,
                user_namespace,
            },
        ))
    }
}

impl NamespaceChild {
    /// Called only in the forked, single-threaded child, before privilege dropping.
    /// The short-lived launcher exits; the workload remains a direct child of agentd.
    pub(crate) fn enter(&self, placement: &WorkloadPlacement) -> io::Result<()> {
        let flags = namespace_flags(&self.policy);
        if self.initial {
            // Prepare a private mount tree under the launcher's guest privileges.
            let initial_flags = if self.user_namespace.is_some() {
                libc::CLONE_NEWNS | (flags & libc::CLONE_NEWTIME)
            } else {
                flags & !libc::CLONE_NEWCGROUP
            };
            if initial_flags != 0 {
                syscall_result(unsafe { libc::unshare(initial_flags) })?;
            }
            // unshare leaves this launcher outside the new time namespace. Offsets
            // must be written before clone3 creates its first member and freezes them.
            for offset in &self.time_offsets {
                let fd = unsafe {
                    libc::open(
                        c"/proc/self/timens_offsets".as_ptr(),
                        libc::O_WRONLY | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                let fd = unsafe { OwnedFd::from_raw_fd(fd) };
                let written =
                    unsafe { libc::write(fd.as_raw_fd(), offset.as_ptr().cast(), offset.len()) };
                if written < 0 {
                    return Err(io::Error::last_os_error());
                }
                if written as usize != offset.len() {
                    return Err(io::Error::from_raw_os_error(libc::EIO));
                }
            }
            if self.policy.mount {
                syscall_result(unsafe {
                    libc::mount(
                        std::ptr::null(),
                        c"/".as_ptr(),
                        std::ptr::null(),
                        libc::MS_REC | libc::MS_PRIVATE,
                        std::ptr::null(),
                    )
                })?;
            }
            if self.user_namespace.is_some() {
                // Inherited mounts become locked in a less-privileged mount namespace.
                // Remove management views from this private staging tree first.
                detach_mounts(c"/proc")?;
                if self.policy.cgroup {
                    detach_mounts(c"/sys/fs/cgroup")?;
                }
                if self.policy.ipc {
                    let result = unsafe { libc::mkdir(c"/dev/mqueue".as_ptr(), 0o755) };
                    if result < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
                    {
                        return Err(io::Error::last_os_error());
                    }
                    detach_mounts(c"/dev/mqueue")?;
                }
            }
        } else {
            for (fd, (flag, _)) in self.handles.iter().zip(active_namespaces(&self.policy)) {
                if flag != libc::CLONE_NEWCGROUP && flag != libc::CLONE_NEWUSER {
                    syscall_result(unsafe { libc::setns(fd.as_raw_fd(), flag) })?;
                }
            }
            if self.policy.mount {
                // setns alone does not replace a root/cwd pointing into the old mount tree.
                let root = self
                    .handles
                    .last()
                    .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
                syscall_result(unsafe { libc::fchdir(root.as_raw_fd()) })?;
                syscall_result(unsafe { libc::chroot(c".".as_ptr()) })?;
                syscall_result(unsafe { libc::chdir(c"/".as_ptr()) })?;
            }
        }

        // CLONE_PARENT makes the real command agentd's child, not a child of a monitor.
        // No shared memory or stack: this has fork semantics on supported Linux hosts.
        let mut args: libc::clone_args = unsafe { std::mem::zeroed() };
        if self.user_namespace.is_some() {
            // NEWUSER cannot be combined with CLONE_PARENT. Agentd is a subreaper:
            // the launcher exits after mapping IDs, adopting init back into agentd.
            args.flags = (flags & !(libc::CLONE_NEWCGROUP | libc::CLONE_NEWTIME)) as u64;
            args.exit_signal = libc::SIGCHLD as u64;
        } else {
            args.flags = libc::CLONE_PARENT as u64;
        }
        // CLONE_PARENT inherits the launcher's exit signal; clone3 requires zero here.
        if let Some(directory) = &placement.cgroup_directory {
            // Migration after fork can exceed pids.max. Create atomically in the target
            // cgroup so init, exec and ordinary descendants all obey the same ceiling.
            args.flags |= CLONE_INTO_CGROUP;
            args.cgroup = directory.as_raw_fd() as u64;
        }
        let pid =
            unsafe { libc::syscall(libc::SYS_clone3, &args, size_of::<libc::clone_args>()) } as i32;
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid > 0 {
            if let Some(user) = &self.user_namespace
                && let Err(error) = user.write_maps(pid)
            {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
                reap(pid);
                return Err(error);
            }
            let bytes = pid.to_ne_bytes();
            let sent = unsafe {
                libc::send(
                    self.socket.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    4,
                    libc::MSG_NOSIGNAL,
                )
            };
            let written = if sent == 4 {
                unsafe { libc::write(self.pid_write.as_raw_fd(), bytes.as_ptr().cast(), 4) }
            } else {
                -1
            };
            if written != 4 {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
            if written == 4
                && let Some(user) = &self.user_namespace
                && let Err(error) = user.attach_mounts(&self.policy, pid)
            {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
                reap(pid);
                return Err(error);
            }
            unsafe { libc::_exit(if written == 4 { 0 } else { 1 }) };
        }

        // Wait until the parent-side PID has been published before executing any workload code.
        let mut poll = libc::pollfd {
            fd: self.pid_read.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        syscall_result(unsafe { libc::poll(&mut poll, 1, 5000) })?;
        if poll.revents & libc::POLLIN == 0 {
            return Err(io::Error::from_raw_os_error(libc::ETIMEDOUT));
        }
        let mut pid_bytes = [0u8; 4];
        if unsafe { libc::read(self.pid_read.as_raw_fd(), pid_bytes.as_mut_ptr().cast(), 4) } != 4 {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        if placement.cgroup_directory.is_none() {
            placement.place_current()?;
        }
        if !self.initial && self.policy.user.is_some() {
            // Agentd's launcher keeps its guest privileges until atomic cgroup
            // placement. Only the application then enters the retained user namespace.
            let user = self
                .handles
                .first()
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
            syscall_result(unsafe { libc::setns(user.as_raw_fd(), libc::CLONE_NEWUSER) })?;
        }
        if !self.initial && self.policy.cgroup {
            // Keep the launcher in agentd's cgroup namespace until clone3 has
            // placed the child. nsdelegate forbids cross-boundary migration from
            // inside the workload namespace, even through an inherited handle.
            let (namespace, _) = self
                .handles
                .iter()
                .zip(active_namespaces(&self.policy))
                .find(|(_, (flag, _))| *flag == libc::CLONE_NEWCGROUP)
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
            syscall_result(unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWCGROUP) })?;
        }
        if self.policy.user.is_some() {
            syscall_result(unsafe { libc::setgroups(0, std::ptr::null()) })?;
            syscall_result(unsafe { libc::setresgid(0, 0, 0) })?;
            syscall_result(unsafe { libc::setresuid(0, 0, 0) })?;
        }
        if self.initial {
            if self.policy.cgroup {
                syscall_result(unsafe { libc::unshare(libc::CLONE_NEWCGROUP) })?;
            }
            if let Some(user) = &self.user_namespace {
                user.prepare_mounts(&self.policy)?;
            } else if self.policy.pid {
                mount_special(c"/proc", c"proc", false)?;
            }
            if self.user_namespace.is_none() && self.policy.cgroup {
                mount_special(c"/sys/fs/cgroup", c"cgroup2", true)?;
            }
            if self.user_namespace.is_none() && self.policy.ipc {
                let result = unsafe { libc::mkdir(c"/dev/mqueue".as_ptr(), 0o755) };
                if result < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
                    return Err(io::Error::last_os_error());
                }
                mount_special(c"/dev/mqueue", c"mqueue", false)?;
            }
            if let Some(hostname) = &self.policy.hostname {
                syscall_result(unsafe {
                    libc::sethostname(hostname.as_ptr().cast(), hostname.len())
                })?;
            }
        }
        // Pass owned namespace handles, not reusable PID-based paths. SCM_RIGHTS keeps
        // them alive even when a short-lived init exits before the parent receives them.
        send_namespaces(self.socket.as_raw_fd(), &self.policy)
    }
}

impl NamespaceParent {
    /// Adopt the actual workload PID and pin its namespace set before releasing the reaper.
    pub(crate) fn finish(self, helper_pid: Option<i32>, succeeded: bool) -> io::Result<i32> {
        let mut pid = 0i32;
        let bytes =
            unsafe { libc::recv(self.socket.as_raw_fd(), (&mut pid as *mut i32).cast(), 4, 0) };
        let result = if bytes == 4 && pid > 0 {
            receive_namespaces(
                self.socket.as_raw_fd(),
                active_namespaces(&self.domain.policy).count()
                    + usize::from(self.domain.policy.mount),
            )
        } else {
            Err(io::Error::other(
                "namespace launcher did not report the workload PID",
            ))
        };
        if let Some(helper) = helper_pid {
            reap(helper);
        }
        if !succeeded || result.is_err() {
            if bytes == 4 && pid > 0 {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
                reap(pid);
            }
            return Err(result
                .err()
                .unwrap_or_else(|| io::Error::other("isolated workload exec failed")));
        }
        if self.initial {
            *self
                .domain
                .state
                .lock()
                .map_err(|_| io::Error::other("namespace state poisoned"))? =
                DomainState::Ready(result?);
        }
        Ok(pid)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn namespace_flags(policy: &WorkloadIsolation) -> i32 {
    (if policy.user.is_some() {
        libc::CLONE_NEWUSER
    } else {
        0
    }) | (if policy.mount { libc::CLONE_NEWNS } else { 0 })
        | (if policy.ipc { libc::CLONE_NEWIPC } else { 0 })
        | (if policy.uts { libc::CLONE_NEWUTS } else { 0 })
        | (if policy.pid { libc::CLONE_NEWPID } else { 0 })
        | (if policy.time.is_some() {
            libc::CLONE_NEWTIME
        } else {
            0
        })
        | (if policy.cgroup {
            libc::CLONE_NEWCGROUP
        } else {
            0
        })
}

fn active_namespaces(
    policy: &WorkloadIsolation,
) -> impl Iterator<Item = (i32, &'static std::ffi::CStr)> {
    let flags = namespace_flags(policy);
    NAMESPACES
        .into_iter()
        .filter(move |(flag, _)| flags & flag != 0)
}

fn syscall_result(result: i32) -> io::Result<()> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn mount_special(path: &std::ffi::CStr, kind: &std::ffi::CStr, readonly: bool) -> io::Result<()> {
    let context = mount::fsopen(kind, FsOpenFlags::FSOPEN_CLOEXEC)?;
    mount::fsconfig_create(&context)?;
    let mut flags = MountAttrFlags::MOUNT_ATTR_NOSUID
        | MountAttrFlags::MOUNT_ATTR_NODEV
        | MountAttrFlags::MOUNT_ATTR_NOEXEC;
    if readonly {
        // Make only this view read-only; the shared cgroup superblock must remain
        // writable through agentd's separate management mount.
        flags |= MountAttrFlags::MOUNT_ATTR_RDONLY;
    }
    let filesystem = mount::fsmount(&context, FsMountFlags::FSMOUNT_CLOEXEC, flags)?;
    // Do not leave agentd's view hidden beneath the new mount. A workload with
    // mount privileges must not reveal management proc/cgroup views by unmounting it.
    detach_mounts(path)?;
    mount::move_mount(
        &filesystem,
        c"",
        rustix::fs::CWD,
        path,
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )?;
    Ok(())
}

fn detach_mounts(path: &std::ffi::CStr) -> io::Result<()> {
    loop {
        if unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH) } == 0 {
            continue;
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EINVAL) {
            break;
        }
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
    Ok(())
}

fn socket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    syscall_result(unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    })?;
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn pipe_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    syscall_result(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) })?;
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn reap(pid: i32) {
    loop {
        if unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) } >= 0
            || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
        {
            break;
        }
    }
}

fn send_namespaces(socket: RawFd, policy: &WorkloadIsolation) -> io::Result<()> {
    let mut fds = [-1; NAMESPACES.len() + 1];
    let mut count = 0;
    let result = (|| {
        for (_, name) in active_namespaces(policy) {
            let fd = unsafe { libc::open(name.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            fds[count] = fd;
            count += 1;
        }
        if policy.mount {
            let root = unsafe {
                libc::open(
                    c"/".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if root < 0 {
                return Err(io::Error::last_os_error());
            }
            fds[count] = root;
            count += 1;
        }
        let mut byte = 0u8;
        let mut iov = libc::iovec {
            iov_base: (&mut byte as *mut u8).cast(),
            iov_len: 1,
        };
        let mut control = [0usize; 16];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if count > 0 {
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen =
                unsafe { libc::CMSG_SPACE((count * size_of::<RawFd>()) as u32) } as _;
            unsafe {
                let header = libc::CMSG_FIRSTHDR(&msg);
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len = libc::CMSG_LEN((count * size_of::<RawFd>()) as u32) as _;
                std::ptr::copy_nonoverlapping(
                    fds.as_ptr(),
                    libc::CMSG_DATA(header).cast::<RawFd>(),
                    count,
                );
            }
        }
        if unsafe { libc::sendmsg(socket, &msg, libc::MSG_NOSIGNAL) } != 1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })();
    for fd in &fds[..count] {
        unsafe {
            libc::close(*fd);
        }
    }
    result
}

fn receive_namespaces(socket: RawFd, expected: usize) -> io::Result<Vec<OwnedFd>> {
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
    msg.msg_controllen = size_of_val(&control) as _;
    let received = unsafe { libc::recvmsg(socket, &mut msg, libc::MSG_CMSG_CLOEXEC) };
    let mut handles = Vec::new();
    if received > 0 {
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(&msg);
            while !header.is_null() {
                if (*header).cmsg_level == libc::SOL_SOCKET
                    && (*header).cmsg_type == libc::SCM_RIGHTS
                {
                    let count = ((*header).cmsg_len as usize - libc::CMSG_LEN(0) as usize)
                        / size_of::<RawFd>();
                    for index in 0..count {
                        handles.push(OwnedFd::from_raw_fd(
                            *libc::CMSG_DATA(header).cast::<RawFd>().add(index),
                        ));
                    }
                }
                header = libc::CMSG_NXTHDR(&msg, header);
            }
        }
    }
    if received != 1
        || msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || handles.len() != expected
    {
        return Err(io::Error::other(
            "workload namespace descriptor handoff failed",
        ));
    }
    Ok(handles)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use microsandbox_protocol::isolation::{WorkloadTimeNamespace, WorkloadTimeOffset};

    use super::*;

    #[test]
    fn time_namespace_validates_offsets_before_fork() {
        let mut policy = WorkloadIsolation {
            time: Some(WorkloadTimeNamespace {
                monotonic: Some(WorkloadTimeOffset {
                    seconds: 0,
                    nanoseconds: 1_000_000_000,
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(NamespaceDomain::new(policy.clone()).is_err());
        policy
            .time
            .as_mut()
            .unwrap()
            .monotonic
            .as_mut()
            .unwrap()
            .nanoseconds = 999_999_999;
        assert!(NamespaceDomain::new(policy.clone()).is_ok());
        assert_eq!(
            active_namespaces(&policy).collect::<Vec<_>>(),
            [(libc::CLONE_NEWTIME, c"/proc/self/ns/time")]
        );
    }
}
