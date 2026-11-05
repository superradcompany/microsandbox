//! Admit OCI guest traffic only after Docker has configured the host namespace.

use nix::ifaddrs::getifaddrs;
use nix::net::if_::InterfaceFlags;

use crate::{RuntimeError, RuntimeResult};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn namespace_has_network_interface() -> RuntimeResult<bool> {
    let mut interfaces = getifaddrs()
        .map_err(|error| RuntimeError::Custom(format!("inspect OCI network namespace: {error}")))?;
    Ok(interfaces.any(|interface| {
        usable_interface(interface.flags)
            && interface.address.is_some_and(|address| {
                address.as_sockaddr_in().is_some() || address.as_sockaddr_in6().is_some()
            })
    }))
}

fn usable_interface(flags: InterfaceFlags) -> bool {
    flags.contains(InterfaceFlags::IFF_UP) && !flags.contains(InterfaceFlags::IFF_LOOPBACK)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_and_down_interfaces_do_not_enable_oci_networking() {
        assert!(!usable_interface(InterfaceFlags::empty()));
        assert!(!usable_interface(InterfaceFlags::IFF_LOOPBACK));
        assert!(!usable_interface(
            InterfaceFlags::IFF_LOOPBACK | InterfaceFlags::IFF_UP
        ));
        assert!(usable_interface(
            InterfaceFlags::IFF_UP | InterfaceFlags::IFF_BROADCAST
        ));
    }

    #[test]
    #[ignore = "run under unshare --user --map-root-user --net"]
    fn empty_network_namespace_has_no_network_interface() {
        assert!(!namespace_has_network_interface().unwrap());
    }

    #[test]
    #[ignore = "run in a namespace with an UP non-loopback interface and an IP address"]
    fn configured_network_namespace_has_network_interface() {
        assert!(namespace_has_network_interface().unwrap());
    }
}
