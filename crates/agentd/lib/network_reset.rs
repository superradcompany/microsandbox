//! Abandon host-dependent TCP streams before a restored workload is thawed.
//!
//! Guest RAM cannot restore the external proxy or the remote peer. Use Linux's
//! socket-diagnostic cookies to destroy only the sockets admitted by a complete
//! dump. Never retry an application request or remove listening/local sockets.

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const SOCK_DIAG: u16 = 20;
const SOCK_DESTROY: u16 = 21;
const HEADER: usize = 16;
const REQUEST: usize = 56;
const DIAG: usize = 72;
const MAX_SOCKETS: usize = 65_536;
const MAX_NAMESPACES: usize = 1_024;
const RESET_BUDGET: Duration = Duration::from_secs(10);
// Linux TCP states 1..9 and 11 can refer to a peer. LISTEN (10) and CLOSED (7)
// are excluded below; TIME_WAIT (6) has no application to wake.
const STATES: u32 = 0x0ffe & !((1 << 6) | (1 << 7) | (1 << 10));

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct Diagnostic {
    fd: OwnedFd,
    sequence: u32,
    deadline: Instant,
}

#[derive(Clone, Debug)]
struct Socket {
    family: u8,
    state: u8,
    /// Kernel inet_diag_sockid, including its opaque cookie. Retaining the cookie
    /// prevents a close/reopen race from destroying a different socket at this tuple.
    id: [u8; 48],
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Socket {
    fn remote(&self) -> io::Result<IpAddr> {
        match i32::from(self.family) {
            libc::AF_INET => {
                Ok(Ipv4Addr::new(self.id[20], self.id[21], self.id[22], self.id[23]).into())
            }
            libc::AF_INET6 => Ok(normalize(
                Ipv6Addr::from(<[u8; 16]>::try_from(&self.id[20..36]).unwrap()).into(),
            )),
            _ => Err(invalid("unexpected socket family")),
        }
    }

    fn external(&self, local: &HashSet<IpAddr>) -> io::Result<bool> {
        if self.state >= 32 || STATES & (1 << self.state) == 0 {
            return Ok(false);
        }
        let remote = self.remote()?;
        Ok(!remote.is_loopback() && !remote.is_unspecified() && !local.contains(&remote))
    }
}

impl Diagnostic {
    fn open(deadline: Instant) -> io::Result<Self> {
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_SOCK_DIAG,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let timeout = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        let result = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&timeout as *const libc::timeval).cast(),
                mem::size_of_val(&timeout) as _,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            sequence: 0,
            deadline,
        })
    }

    fn exchange(
        &mut self,
        kind: u16,
        flags: u16,
        request: &[u8; REQUEST],
    ) -> io::Result<Vec<Socket>> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TCP reset deadline exceeded",
            ));
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| invalid("diagnostic sequence exhausted"))?;
        let mut bytes = [0; HEADER + REQUEST];
        bytes[0..4].copy_from_slice(&((HEADER + REQUEST) as u32).to_ne_bytes());
        bytes[4..6].copy_from_slice(&kind.to_ne_bytes());
        bytes[6..8].copy_from_slice(&flags.to_ne_bytes());
        bytes[8..12].copy_from_slice(&self.sequence.to_ne_bytes());
        bytes[HEADER..].copy_from_slice(request);
        let mut kernel: libc::sockaddr_nl = unsafe { mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as _;
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                0,
                (&kernel as *const libc::sockaddr_nl).cast(),
                mem::size_of_val(&kernel) as _,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if sent as usize != bytes.len() {
            return Err(invalid("short diagnostic request"));
        }
        let mut sockets = Vec::new();
        loop {
            if Instant::now() >= self.deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TCP reset deadline exceeded",
                ));
            }
            let mut buffer = [0u8; 65_536];
            let mut sender: libc::sockaddr_nl = unsafe { mem::zeroed() };
            let mut sender_len = mem::size_of_val(&sender) as libc::socklen_t;
            // MSG_TRUNC returns the full datagram length, allowing truncation to fail
            // explicitly rather than parsing a partial dump as complete.
            let received = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    libc::MSG_TRUNC,
                    (&mut sender as *mut libc::sockaddr_nl).cast(),
                    &mut sender_len,
                )
            };
            if received < 0 {
                return Err(io::Error::last_os_error());
            }
            if received == 0 || received as usize > buffer.len() || sender.nl_pid != 0 {
                return Err(invalid("invalid diagnostic datagram"));
            }
            let mut offset = 0;
            let received = received as usize;
            while offset < received {
                if received - offset < HEADER {
                    return Err(invalid("truncated diagnostic header"));
                }
                let header = &buffer[offset..offset + HEADER];
                let length = u32::from_ne_bytes(header[0..4].try_into().unwrap()) as usize;
                if length < HEADER || length > received - offset {
                    return Err(invalid("invalid diagnostic length"));
                }
                if u32::from_ne_bytes(header[8..12].try_into().unwrap()) != self.sequence {
                    return Err(invalid("unexpected diagnostic sequence"));
                }
                let message_flags = u16::from_ne_bytes(header[6..8].try_into().unwrap());
                if message_flags & 0x10 != 0 {
                    return Err(invalid("interrupted socket dump; workloads remain frozen"));
                }
                let body = &buffer[offset + HEADER..offset + length];
                match u16::from_ne_bytes(header[4..6].try_into().unwrap()) {
                    2 => {
                        if body.len() < 4 {
                            return Err(invalid("truncated diagnostic error"));
                        }
                        let code = i32::from_ne_bytes(body[..4].try_into().unwrap());
                        if code == 0 {
                            return Ok(sockets);
                        }
                        return Err(io::Error::from_raw_os_error(
                            code.checked_neg()
                                .ok_or_else(|| invalid("invalid diagnostic error"))?,
                        ));
                    }
                    3 => {
                        if body.len() >= 4 && i32::from_ne_bytes(body[..4].try_into().unwrap()) != 0
                        {
                            return Err(invalid("failed socket dump"));
                        }
                        return Ok(sockets);
                    }
                    SOCK_DIAG if kind == SOCK_DIAG => {
                        if body.len() < DIAG || sockets.len() >= MAX_SOCKETS {
                            return Err(invalid("invalid or oversized socket inventory"));
                        }
                        sockets.push(Socket {
                            family: body[0],
                            state: body[1],
                            id: body[4..52].try_into().unwrap(),
                        });
                    }
                    _ => return Err(invalid("unexpected diagnostic reply")),
                }
                offset += (length + 3) & !3;
            }
        }
    }

    fn dump(&mut self, family: u8) -> io::Result<Vec<Socket>> {
        let mut request = [0; REQUEST];
        request[0] = family;
        request[1] = libc::IPPROTO_TCP as u8;
        request[4..8].copy_from_slice(&STATES.to_ne_bytes());
        self.exchange(SOCK_DIAG, 1 | 0x300, &request)
    }

    fn destroy(&mut self, socket: &Socket) -> io::Result<()> {
        let mut request = [0; REQUEST];
        request[0] = socket.family;
        request[1] = libc::IPPROTO_TCP as u8;
        request[4..8].copy_from_slice(&STATES.to_ne_bytes());
        request[8..].copy_from_slice(&socket.id);
        match self.exchange(SOCK_DESTROY, 1 | 4, &request) {
            Ok(_) => Ok(()),
            // A socket may close due to a kernel timer even while workloads are frozen.
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn normalize(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        other => other,
    }
}

fn local_addresses() -> io::Result<HashSet<IpAddr>> {
    let mut addresses = HashSet::new();
    // getifaddrs owns the list until iteration finishes. Some entries have no IP address.
    for interface in nix::ifaddrs::getifaddrs()? {
        let Some(address) = interface.address else {
            continue;
        };
        if let Some(ipv4) = address.as_sockaddr_in() {
            addresses.insert(ipv4.ip().into());
        } else if let Some(ipv6) = address.as_sockaddr_in6() {
            addresses.insert(normalize(ipv6.ip().into()));
        }
    }
    Ok(addresses)
}

/// Probe support without touching a real stream. An established TCP socket can
/// never have both ports zero; ENOENT proves the destroy handler admitted the call.
pub(crate) fn supported() -> bool {
    let Ok(mut diagnostic) = Diagnostic::open(Instant::now() + Duration::from_secs(2)) else {
        return false;
    };
    for family in [libc::AF_INET, libc::AF_INET6] {
        let mut request = [0; REQUEST];
        request[0] = family as u8;
        request[1] = libc::IPPROTO_TCP as u8;
        request[4..8].copy_from_slice(&STATES.to_ne_bytes());
        request[48..56].fill(0xff);
        match diagnostic.exchange(SOCK_DESTROY, 1 | 4, &request) {
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
            _ => return false,
        }
    }
    true
}

fn reset_current_namespace(deadline: Instant, local: &HashSet<IpAddr>) -> io::Result<()> {
    let mut diagnostic = Diagnostic::open(deadline)?;
    // Finish inventories before deleting: mutation during a dump can skip entries.
    let mut sockets = diagnostic.dump(libc::AF_INET as u8)?;
    sockets.extend(diagnostic.dump(libc::AF_INET6 as u8)?);
    if sockets.len() > MAX_SOCKETS {
        return Err(invalid("socket inventory exceeds restore bound"));
    }
    for socket in sockets {
        if socket.external(local)? {
            diagnostic.destroy(&socket)?;
        }
    }
    Ok(())
}

/// Run only after the workload freeze/attempt has been validated. A dedicated
/// thread owns namespace changes; a pooled async worker must never retain setns.
pub(crate) fn reset_external_tcp() -> io::Result<()> {
    let deadline = Instant::now() + RESET_BUDGET;
    let original = File::open("/proc/self/ns/net")?;
    let own_identity = original.metadata()?.ino();
    let mut namespaces = BTreeMap::from([(own_identity, original)]);
    for process in fs::read_dir("/proc")? {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "network namespace inventory timed out",
            ));
        }
        let process = process?;
        if !process
            .file_name()
            .to_string_lossy()
            .bytes()
            .all(|byte| byte.is_ascii_digit())
        {
            continue;
        }
        let namespace = match File::open(process.path().join("ns/net")) {
            Ok(file) => file,
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(libc::ESRCH) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        namespaces
            .entry(namespace.metadata()?.ino())
            .or_insert(namespace);
        if namespaces.len() > MAX_NAMESPACES {
            return Err(invalid("too many network namespaces to reset safely"));
        }
    }
    std::thread::spawn(move || {
        let mut current = own_identity;
        let mut enter = |identity: u64, namespace: &File| -> io::Result<()> {
            if current != identity {
                if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                current = identity;
            }
            Ok(())
        };
        // A veth peer in another guest namespace can survive restore too.
        // Collect its addresses before considering a stream for destruction.
        let mut guest_addresses = HashSet::new();
        for (&id, ns) in &namespaces {
            enter(id, ns)?;
            guest_addresses.extend(local_addresses()?);
        }
        for (&id, ns) in &namespaces {
            enter(id, ns)?;
            reset_current_namespace(deadline, &guest_addresses)?;
        }
        Ok(())
    })
    .join()
    .map_err(|_| io::Error::other("TCP reset worker panicked"))?
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn socket(remote: IpAddr, state: u8) -> Socket {
        let mut id = [0; 48];
        let family = match remote {
            IpAddr::V4(address) => {
                id[20..24].copy_from_slice(&address.octets());
                libc::AF_INET
            }
            IpAddr::V6(address) => {
                id[20..36].copy_from_slice(&address.octets());
                libc::AF_INET6
            }
        };
        Socket {
            family: family as u8,
            state,
            id,
        }
    }

    #[test]
    fn only_external_peer_streams_are_selected() {
        let local = HashSet::from(["10.0.0.2".parse().unwrap(), "fd00::2".parse().unwrap()]);
        for address in [
            "127.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "10.0.0.2",
            "::ffff:10.0.0.2",
            "fd00::2",
            "0.0.0.0",
            "::",
        ] {
            assert!(
                !socket(address.parse().unwrap(), 1)
                    .external(&local)
                    .unwrap(),
                "{address}"
            );
        }
        for address in ["10.0.0.1", "2001:db8::1"] {
            for state in [1, 2, 3, 4, 5, 8, 9, 11] {
                assert!(
                    socket(address.parse().unwrap(), state)
                        .external(&local)
                        .unwrap()
                );
            }
            for state in [0, 6, 7, 10, 31, 255] {
                assert!(
                    !socket(address.parse().unwrap(), state)
                        .external(&local)
                        .unwrap()
                );
            }
        }
    }

    /// This checks the kernel ABI using only sockets owned by the test. The
    /// production inventory filter is exercised separately with external peers.
    #[test]
    #[ignore = "requires CAP_NET_ADMIN and INET_DIAG_DESTROY"]
    fn destroy_wakes_blocked_reader_and_preserves_other_connections() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::os::fd::AsRawFd;

        assert!(
            supported(),
            "TCP destruction must be available for this test"
        );
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let listener = TcpListener::bind(bind).unwrap();
            let addr = listener.local_addr().unwrap();
            let client = TcpStream::connect(addr).unwrap();
            let (_peer, _) = listener.accept().unwrap();
            let mut survivor = TcpStream::connect(addr).unwrap();
            let (mut survivor_peer, _) = listener.accept().unwrap();
            // Compare the actual kernel cookie as well as the address family:
            // even in a shared namespace, only this test's client can match.
            let mut cookie = 0u64;
            let mut len = mem::size_of_val(&cookie) as libc::socklen_t;
            assert_eq!(
                unsafe {
                    libc::getsockopt(
                        client.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_COOKIE,
                        (&mut cookie as *mut u64).cast(),
                        &mut len,
                    )
                },
                0
            );
            let family = if addr.is_ipv4() {
                libc::AF_INET
            } else {
                libc::AF_INET6
            };
            let mut diagnostic = Diagnostic::open(Instant::now() + RESET_BUDGET).unwrap();
            let target = diagnostic
                .dump(family as u8)
                .unwrap()
                .into_iter()
                .find(|s| {
                    let low = u32::from_ne_bytes(s.id[40..44].try_into().unwrap());
                    let high = u32::from_ne_bytes(s.id[44..48].try_into().unwrap());
                    cookie == u64::from(low) | (u64::from(high) << 32)
                })
                .expect("client socket missing from diagnostic inventory");
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let waiting = std::thread::spawn(move || (&client).read(&mut [0u8]));
            diagnostic.destroy(&target).unwrap();
            let error = waiting.join().unwrap().unwrap_err();
            assert!(matches!(
                error.raw_os_error(),
                Some(libc::ECONNABORTED | libc::ECONNRESET)
            ));
            survivor.write_all(b"x").unwrap();
            let mut reply = [0];
            survivor_peer.read_exact(&mut reply).unwrap();
            assert_eq!(reply, *b"x");
            let _fresh = TcpStream::connect(addr).unwrap();
            listener.accept().unwrap();
        }
    }

    #[test]
    fn current_namespace_addresses_include_loopback() {
        let addresses = local_addresses().unwrap();
        assert!(addresses.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }
}
