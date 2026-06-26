//! Windows-specific DNS-server discovery via IP Helper.

use std::alloc::{Layout, alloc, dealloc};
use std::io::{self, Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ptr::{NonNull, null_mut};

use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_INCLUDE_ALL_INTERFACES, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_FRIENDLY_NAME,
    GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    IP_ADAPTER_DNS_SERVER_ADDRESS_XP,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const DNS_PORT: u16 = 53;
const INITIAL_ADAPTER_BUFFER_SIZE: u32 = 15 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct AdapterAddresses {
    ptr: NonNull<IP_ADAPTER_ADDRESSES_LH>,
    layout: Layout,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AdapterAddresses {
    fn new(size: u32) -> io::Result<Self> {
        let layout = Layout::from_size_align(
            size as usize,
            std::mem::align_of::<IP_ADAPTER_ADDRESSES_LH>(),
        )
        .map_err(|err| Error::new(ErrorKind::InvalidInput, err))?;

        // SAFETY: `layout` has non-zero size and the requested alignment for
        // `IP_ADAPTER_ADDRESSES_LH`. The owned pointer is deallocated in Drop.
        let ptr = unsafe { NonNull::new(alloc(layout).cast::<IP_ADAPTER_ADDRESSES_LH>()) }
            .ok_or_else(|| Error::other("failed to allocate GetAdaptersAddresses buffer"))?;

        Ok(Self { ptr, layout })
    }

    fn as_mut_ptr(&mut self) -> *mut IP_ADAPTER_ADDRESSES_LH {
        self.ptr.as_ptr()
    }

    fn size(&self) -> u32 {
        self.layout.size() as u32
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for AdapterAddresses {
    fn drop(&mut self) {
        // SAFETY: `ptr` was allocated with this exact layout in `new`.
        unsafe {
            dealloc(self.ptr.as_ptr().cast(), self.layout);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn read_dns_servers() -> io::Result<Vec<SocketAddr>> {
    let mut adapters = query_adapter_addresses()?;
    let mut servers = Vec::new();

    // SAFETY: `adapters` owns a buffer filled by `GetAdaptersAddresses`.
    // The linked-list pointers remain valid while `adapters` is alive.
    unsafe {
        let mut adapter_ptr = adapters.as_mut_ptr();
        while !adapter_ptr.is_null() {
            let adapter = &*adapter_ptr;
            if adapter.OperStatus == IfOperStatusUp {
                collect_dns_servers(adapter.FirstDnsServerAddress, &mut servers);
            }
            adapter_ptr = adapter.Next;
        }
    }

    if servers.is_empty() {
        return Err(Error::new(
            ErrorKind::NotFound,
            "GetAdaptersAddresses returned no DNS servers",
        ));
    }

    Ok(servers)
}

fn query_adapter_addresses() -> io::Result<AdapterAddresses> {
    let flags = GAA_FLAG_SKIP_UNICAST
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_FRIENDLY_NAME
        | GAA_FLAG_INCLUDE_ALL_INTERFACES;
    let mut adapters = AdapterAddresses::new(INITIAL_ADAPTER_BUFFER_SIZE)?;

    loop {
        let mut size = adapters.size();
        // SAFETY: `adapters` points at a writable buffer of `size` bytes.
        let result = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.into(),
                flags,
                null_mut(),
                adapters.as_mut_ptr(),
                &mut size,
            )
        };

        match result {
            ERROR_SUCCESS => return Ok(adapters),
            ERROR_BUFFER_OVERFLOW if size > adapters.size() => {
                adapters = AdapterAddresses::new(size)?;
            }
            ERROR_BUFFER_OVERFLOW => {
                return Err(Error::other(
                    "GetAdaptersAddresses requested a non-growing buffer",
                ));
            }
            code => return Err(Error::from_raw_os_error(code as i32)),
        }
    }
}

unsafe fn collect_dns_servers(
    mut dns_ptr: *mut IP_ADAPTER_DNS_SERVER_ADDRESS_XP,
    servers: &mut Vec<SocketAddr>,
) {
    while !dns_ptr.is_null() {
        // SAFETY: caller guarantees `dns_ptr` points into the adapter buffer.
        let dns = unsafe { &*dns_ptr };
        if let Some(addr) = socket_addr_from_sockaddr(dns.Address.lpSockaddr) {
            push_unique(servers, addr);
        }
        dns_ptr = dns.Next;
    }
}

fn socket_addr_from_sockaddr(sockaddr: *const SOCKADDR) -> Option<SocketAddr> {
    if sockaddr.is_null() {
        return None;
    }

    // SAFETY: caller supplies a sockaddr pointer from IP Helper. The family
    // field determines which concrete sockaddr layout is valid.
    let family = unsafe { (*sockaddr).sa_family };
    match family {
        AF_INET => {
            // SAFETY: family says this is a SOCKADDR_IN.
            let addr = unsafe { &*sockaddr.cast::<SOCKADDR_IN>() };
            // SAFETY: `S_addr` is the active representation for IN_ADDR.
            let ip = Ipv4Addr::from(u32::from_be(unsafe { addr.sin_addr.S_un.S_addr }));
            Some(SocketAddr::new(IpAddr::V4(ip), DNS_PORT))
        }
        AF_INET6 => {
            // SAFETY: family says this is a SOCKADDR_IN6.
            let addr = unsafe { &*sockaddr.cast::<SOCKADDR_IN6>() };
            // SAFETY: `Byte` is the active representation for IN6_ADDR.
            let ip = Ipv6Addr::from(unsafe { addr.sin6_addr.u.Byte });
            Some(SocketAddr::new(IpAddr::V6(ip), DNS_PORT))
        }
        _ => None,
    }
}

fn push_unique(servers: &mut Vec<SocketAddr>, addr: SocketAddr) {
    if !servers.contains(&addr) {
        servers.push(addr);
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_unique_preserves_first_seen_order() {
        let mut servers = Vec::new();
        push_unique(&mut servers, "1.1.1.1:53".parse().unwrap());
        push_unique(&mut servers, "8.8.8.8:53".parse().unwrap());
        push_unique(&mut servers, "1.1.1.1:53".parse().unwrap());

        assert_eq!(
            servers,
            vec![
                "1.1.1.1:53".parse::<SocketAddr>().unwrap(),
                "8.8.8.8:53".parse::<SocketAddr>().unwrap(),
            ]
        );
    }
}
