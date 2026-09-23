//! macOS-specific DNS-server discovery via `SystemConfiguration.framework`.
//!
//! Unlike Linux, macOS doesn't treat `/etc/resolv.conf` as authoritative.
//! The live resolver state is stored in the System Configuration dynamic
//! store and is managed by `configd`. On VPN + split-DNS setups
//! `/etc/resolv.conf` is typically either missing, stale, or points at
//! only one leg of the resolver table — following it there gets us the
//! wrong answer.
//!
//! This module queries `State:/Network/Global/DNS` and returns the
//! primary nameserver list (the set `configd` tells the system resolver
//! to use). That's the fix for the most common macOS failure mode: "I
//! connected to a VPN and DNS stopped working inside the sandbox."
//!
//! What this intentionally does *not* handle: per-domain split-DNS
//! routing (e.g. `*.corp.example.com → 10.0.0.53`, everything else →
//! `8.8.8.8`). That routing lives in the per-service `Setup:/Network/
//! Service/<uuid>/DNS` / `State:/Network/Service/<uuid>/DNS` keys and
//! requires a match engine to implement. Tracked as future work.

use std::io::{self, Error, ErrorKind};
use std::net::{IpAddr, SocketAddr};

use core_foundation::array::CFArray;
use core_foundation::base::{CFType, TCFType, ToVoid};
use core_foundation::dictionary::CFDictionary;
use core_foundation::propertylist::CFPropertyList;
use core_foundation::string::CFString;
use system_configuration::dynamic_store::SCDynamicStoreBuilder;
use system_configuration::sys::schema_definitions::kSCPropNetDNSServerAddresses;

/// Read the primary DNS servers from the macOS dynamic store.
///
/// Returns the list of `SocketAddr`s on port 53 in the order `configd`
/// has configured them. Returns an empty `Vec` (not `Err`) when the
/// `Global/DNS` key exists but carries no `ServerAddresses`. Returns
/// `Err` only when we can't create the store or the key is entirely
/// absent (rare on a running system, but possible in degenerate
/// network-off states).
pub fn read_dns_servers() -> io::Result<Vec<SocketAddr>> {
    const DNS_PORT: u16 = 53;

    let store = SCDynamicStoreBuilder::new("microsandbox-network")
        .build()
        .ok_or_else(|| Error::other("SCDynamicStoreBuilder::build failed"))?;

    let key = CFString::from_static_string("State:/Network/Global/DNS");
    let dict = match store
        .get(key)
        .and_then(CFPropertyList::downcast_into::<CFDictionary>)
    {
        Some(d) => d,
        None => {
            return Err(Error::new(
                ErrorKind::NotFound,
                "State:/Network/Global/DNS is absent",
            ));
        }
    };

    let addresses = match dict
        .find(unsafe { kSCPropNetDNSServerAddresses }.to_void())
        .map(|ptr| unsafe { CFType::wrap_under_get_rule(*ptr) })
        .and_then(CFType::downcast_into::<CFArray>)
    {
        Some(a) => a,
        None => return Ok(Vec::new()), // key present, no servers listed
    };

    let mut out = Vec::with_capacity(addresses.len() as usize);
    for ptr in &addresses {
        let Some(cfstr) = unsafe { CFType::wrap_under_get_rule(*ptr) }.downcast_into::<CFString>()
        else {
            continue;
        };

        let s = cfstr.to_string();
        match s.parse::<IpAddr>() {
            Ok(ip) => out.push(SocketAddr::new(ip, DNS_PORT)),
            Err(_) => {
                tracing::warn!(
                    address = %s,
                    "skipping SCDynamicStore nameserver entry that isn't a parseable IP"
                );
            }
        }
    }

    Ok(out)
}
