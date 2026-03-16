//! macOS host backend: vmnet.framework.
//!
//! Creates a vmnet interface in shared mode using the vmnet.framework API.
//! Uses a C shim (`csrc/vmnet_shim.c`) to bridge Objective-C block callbacks
//! to Rust-compatible synchronous calls.
//!
//! The vmnet shared mode provides NATed internet access — equivalent to the
//! Linux TAP + nftables NAT approach, but handled entirely inside Apple's
//! framework. No host-side firewall rules are needed.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use super::FrameTransport;
use crate::config::InterfaceConfig;
use crate::ready::{MsbnetReady, MsbnetReadyIpv4, MsbnetReadyIpv6};

//--------------------------------------------------------------------------------------------------
// FFI Types
//--------------------------------------------------------------------------------------------------

/// Opaque vmnet interface handle.
type InterfaceRef = *mut libc::c_void;

/// Return codes from vmnet operations.
const VMNET_SUCCESS: u32 = 1000;

/// Result struct populated by the C shim.
#[repr(C)]
struct VmnetStartResult {
    status: u32,
    mac_address: [u8; 18],
    mtu: u64,
    max_packet_size: u64,
    start_address: [u8; 64],
    end_address: [u8; 64],
    subnet_mask: [u8; 64],
    nat66_prefix: [u8; 64],
}

/// Packet descriptor for vmnet_read/vmnet_write.
#[repr(C)]
struct VmPktDesc {
    vm_pkt_size: usize,
    vm_pkt_iov: *mut libc::iovec,
    vm_pkt_iovcnt: u32,
    vm_flags: u32,
}

//--------------------------------------------------------------------------------------------------
// FFI Functions
//--------------------------------------------------------------------------------------------------

unsafe extern "C" {
    fn vmnet_shim_start_shared(out_iface: *mut InterfaceRef, out_result: *mut VmnetStartResult);
    fn vmnet_shim_stop(iface: InterfaceRef) -> u32;
    fn vmnet_shim_set_event_fd(iface: InterfaceRef, notify_fd: libc::c_int) -> u32;

    fn vmnet_read(iface: InterfaceRef, packets: *mut VmPktDesc, pktcnt: *mut libc::c_int) -> u32;
    fn vmnet_write(iface: InterfaceRef, packets: *mut VmPktDesc, pktcnt: *mut libc::c_int) -> u32;
}

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// vmnet.framework-based network backend for macOS.
///
/// Creates a shared-mode vmnet interface that provides NATed internet access.
/// On drop, stops the vmnet interface.
pub struct VmnetLink {
    /// vmnet interface handle.
    iface: InterfaceRef,

    /// Pipe FD for packet-available notifications (read end).
    /// Used by the engine to detect when frames are ready to read.
    pub notify_fd: OwnedFd,

    /// Pipe FD registered with the vmnet callback (write end).
    ///
    /// This must stay open for the lifetime of the interface so the callback
    /// can signal packet availability.
    pub notify_write_fd: OwnedFd,

    /// MAC address assigned by vmnet.
    pub mac: String,

    /// MTU.
    pub mtu: u16,

    /// Maximum packet size.
    pub max_packet_size: usize,

    /// Gateway IPv4 address (vmnet's start_address).
    pub gateway_v4: String,

    /// Guest IPv4 address (derived: gateway + 1).
    pub guest_v4: String,

    /// Subnet mask.
    pub subnet_mask: String,

    /// IPv6 gateway address (NAT66 prefix + `::1`), if available.
    pub gateway_v6: Option<Ipv6Addr>,

    /// IPv6 guest address (NAT66 prefix + `::2`), if available.
    pub guest_v6: Option<Ipv6Addr>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl VmnetLink {
    /// Creates a new vmnet interface in shared mode.
    ///
    /// This is a privileged operation — may require sudo on some macOS versions.
    pub fn create(interface: &InterfaceConfig) -> std::io::Result<Self> {
        if interface.mac.is_some()
            || interface.mtu.is_some()
            || interface.ipv4.is_some()
            || interface.ipv6.is_some()
        {
            return Err(std::io::Error::other(
                "custom network interface overrides are not supported with vmnet shared mode",
            ));
        }

        let mut iface: InterfaceRef = std::ptr::null_mut();
        let mut result: VmnetStartResult = unsafe { std::mem::zeroed() };

        unsafe {
            vmnet_shim_start_shared(&mut iface, &mut result);
        }

        if iface.is_null() || result.status != VMNET_SUCCESS {
            return Err(std::io::Error::other(format!(
                "vmnet_start_interface failed with status {}",
                result.status
            )));
        }

        // Extract strings from the result.
        let mac = c_str_from_bytes(&result.mac_address);
        let mtu = u16::try_from(result.mtu).map_err(|_| {
            std::io::Error::other(format!("vmnet reported MTU {} exceeds u16 range", result.mtu))
        })?;
        let max_packet_size = result.max_packet_size as usize;
        let gateway_v4 = c_str_from_bytes(&result.start_address);
        let subnet_mask = c_str_from_bytes(&result.subnet_mask);

        // Derive guest IP: gateway + 1.
        let guest_v4 = derive_guest_ip(&gateway_v4);

        // Extract NAT66 prefix and derive IPv6 addresses.
        let nat66_prefix = c_str_from_bytes(&result.nat66_prefix);
        let (gateway_v6, guest_v6) = derive_ipv6_addresses(&nat66_prefix);

        if gateway_v6.is_none() {
            return Err(std::io::Error::other(
                "vmnet did not provide a NAT66 IPv6 prefix; dual-stack networking requires IPv6",
            ));
        }

        // Create a pipe for packet-available notifications.
        let mut pipe_fds = [0i32; 2];
        if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
            unsafe { vmnet_shim_stop(iface) };
            return Err(std::io::Error::last_os_error());
        }

        let notify_read = unsafe { OwnedFd::from_raw_fd(pipe_fds[0]) };
        let notify_write = unsafe { OwnedFd::from_raw_fd(pipe_fds[1]) };

        // Make the read end non-blocking for AsyncFd.
        unsafe {
            let flags = libc::fcntl(pipe_fds[0], libc::F_GETFL);
            if flags == -1 {
                vmnet_shim_stop(iface);
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(pipe_fds[0], libc::F_SETFL, flags | libc::O_NONBLOCK) == -1 {
                vmnet_shim_stop(iface);
                return Err(std::io::Error::last_os_error());
            }

            let flags = libc::fcntl(pipe_fds[1], libc::F_GETFL);
            if flags == -1 {
                vmnet_shim_stop(iface);
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(pipe_fds[1], libc::F_SETFL, flags | libc::O_NONBLOCK) == -1 {
                vmnet_shim_stop(iface);
                return Err(std::io::Error::last_os_error());
            }
        }

        // Register the packet-available event callback.
        let ret = unsafe { vmnet_shim_set_event_fd(iface, notify_write.as_raw_fd()) };
        if ret != VMNET_SUCCESS {
            unsafe { vmnet_shim_stop(iface) };
            return Err(std::io::Error::other(format!(
                "vmnet_interface_set_event_callback failed with status {ret}"
            )));
        }

        Ok(Self {
            iface,
            notify_fd: notify_read,
            notify_write_fd: notify_write,
            mac,
            mtu,
            max_packet_size,
            gateway_v4,
            guest_v4,
            subnet_mask,
            gateway_v6,
            guest_v6,
        })
    }

    /// Reads one ethernet frame from the vmnet interface.
    ///
    /// Returns the number of bytes read, or 0 if no packets are available.
    pub fn read_frame(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Drain all queued wakeups before asking vmnet for packets.
        let mut drain = [0u8; 64];
        loop {
            let n = unsafe {
                libc::read(
                    self.notify_fd.as_raw_fd(),
                    drain.as_mut_ptr().cast(),
                    drain.len(),
                )
            };
            if n <= 0 {
                break;
            }
        }

        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };

        let mut pkt = VmPktDesc {
            vm_pkt_size: buf.len(),
            vm_pkt_iov: &mut iov,
            vm_pkt_iovcnt: 1,
            vm_flags: 0,
        };

        let mut pktcnt: libc::c_int = 1;
        let ret = unsafe { vmnet_read(self.iface, &mut pkt, &mut pktcnt) };

        if ret != VMNET_SUCCESS {
            return Err(std::io::Error::other(format!(
                "vmnet_read failed with status {ret}"
            )));
        }

        if pktcnt == 0 {
            return Ok(0);
        }

        Ok(pkt.vm_pkt_size)
    }

    /// Writes one ethernet frame to the vmnet interface.
    pub fn write_frame(&self, buf: &[u8]) -> std::io::Result<()> {
        let mut iov = libc::iovec {
            iov_base: buf.as_ptr() as *mut _,
            iov_len: buf.len(),
        };

        let mut pkt = VmPktDesc {
            vm_pkt_size: buf.len(),
            vm_pkt_iov: &mut iov,
            vm_pkt_iovcnt: 1,
            vm_flags: 0,
        };

        let mut pktcnt: libc::c_int = 1;
        let ret = unsafe { vmnet_write(self.iface, &mut pkt, &mut pktcnt) };

        if ret != VMNET_SUCCESS {
            return Err(std::io::Error::other(format!(
                "vmnet_write failed with status {ret}"
            )));
        }

        Ok(())
    }

    /// Builds the `MsbnetReady` payload from the resolved parameters.
    pub fn ready_info(&self) -> MsbnetReady {
        MsbnetReady {
            pid: std::process::id(),
            backend: "macos_vmnet".to_string(),
            ifname: "vmnet0".to_string(),
            guest_iface: "eth0".to_string(),
            mac: self.mac.clone(),
            mtu: self.mtu,
            ipv4: Some(MsbnetReadyIpv4 {
                address: self.guest_v4.clone(),
                prefix_len: subnet_mask_to_prefix(&self.subnet_mask),
                gateway: self.gateway_v4.clone(),
                dns: vec![self.gateway_v4.clone()],
            }),
            ipv6: self.gateway_v6.map(|gw| MsbnetReadyIpv6 {
                address: self.guest_v6.unwrap().to_string(),
                prefix_len: 64,
                gateway: gw.to_string(),
                dns: vec![gw.to_string()],
            }),
        }
    }

    /// Returns the raw FD for the notification pipe (read end).
    ///
    /// The engine uses this with AsyncFd to detect when frames are available.
    pub fn as_raw_fd(&self) -> RawFd {
        use std::os::fd::AsRawFd;
        self.notify_fd.as_raw_fd()
    }
}

impl Drop for VmnetLink {
    fn drop(&mut self) {
        unsafe {
            vmnet_shim_stop(self.iface);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl FrameTransport for VmnetLink {
    fn ready_fd(&self) -> RawFd {
        self.notify_fd.as_raw_fd()
    }

    fn read_frame(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        VmnetLink::read_frame(self, buf)
    }

    fn write_frame(&self, buf: &[u8]) -> std::io::Result<()> {
        VmnetLink::write_frame(self, buf)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Extracts a Rust String from a null-terminated C byte array.
fn c_str_from_bytes(bytes: &[u8]) -> String {
    let nul_pos = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..nul_pos]).to_string()
}

/// Derives IPv6 gateway and guest addresses from a NAT66 prefix string.
///
/// The prefix is a ULA like `"fd9b:5a14:ba57:e3d3::"`. Gateway gets `::1`,
/// guest gets `::2`. Returns `(None, None)` if the prefix is empty or invalid.
fn derive_ipv6_addresses(prefix: &str) -> (Option<Ipv6Addr>, Option<Ipv6Addr>) {
    if prefix.is_empty() {
        return (None, None);
    }

    let base = prefix.trim_end_matches("::");
    let gateway: Option<Ipv6Addr> = format!("{base}::1").parse().ok();
    let guest: Option<Ipv6Addr> = format!("{base}::2").parse().ok();

    match (gateway, guest) {
        (Some(gw), Some(g)) => (Some(gw), Some(g)),
        _ => (None, None),
    }
}

/// Derives the guest IP from the gateway (start) address by incrementing
/// the host address by one (correctly carrying across octets).
fn derive_guest_ip(gateway: &str) -> String {
    if let Ok(ip) = gateway.parse::<Ipv4Addr>() {
        let host_u32 = u32::from(ip);
        Ipv4Addr::from(host_u32.wrapping_add(1)).to_string()
    } else {
        gateway.to_string()
    }
}

/// Converts a dotted-decimal subnet mask to a prefix length.
fn subnet_mask_to_prefix(mask: &str) -> u8 {
    if let Ok(ip) = mask.parse::<Ipv4Addr>() {
        let bits = u32::from_be_bytes(ip.octets());
        bits.count_ones() as u8
    } else {
        24 // sensible default
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_guest_ip() {
        assert_eq!(derive_guest_ip("192.168.64.1"), "192.168.64.2");
        assert_eq!(derive_guest_ip("10.0.0.1"), "10.0.0.2");
    }

    #[test]
    fn test_subnet_mask_to_prefix() {
        assert_eq!(subnet_mask_to_prefix("255.255.255.0"), 24);
        assert_eq!(subnet_mask_to_prefix("255.255.0.0"), 16);
        assert_eq!(subnet_mask_to_prefix("255.255.255.252"), 30);
    }

    #[test]
    fn test_subnet_mask_to_prefix_edge_cases() {
        assert_eq!(subnet_mask_to_prefix("255.255.255.255"), 32);
        assert_eq!(subnet_mask_to_prefix("0.0.0.0"), 0);
        assert_eq!(subnet_mask_to_prefix("garbage"), 24); // fallback
    }

    #[test]
    fn test_derive_ipv6_addresses() {
        let (gw, guest) = derive_ipv6_addresses("fd9b:5a14:ba57:e3d3::");
        assert_eq!(gw.unwrap(), "fd9b:5a14:ba57:e3d3::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(guest.unwrap(), "fd9b:5a14:ba57:e3d3::2".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_derive_ipv6_addresses_empty() {
        let (gw, guest) = derive_ipv6_addresses("");
        assert!(gw.is_none());
        assert!(guest.is_none());
    }

    #[test]
    fn test_derive_ipv6_addresses_invalid() {
        let (gw, guest) = derive_ipv6_addresses("garbage");
        assert!(gw.is_none());
        assert!(guest.is_none());
    }
}
