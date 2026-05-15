use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use microsandbox_network::config::InterfaceOverrides;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fluent builder for per-NIC overrides on the guest interface
/// (`microsandbox_network::config::InterfaceOverrides`). Chainable
/// setters mutate in place; `.build()` is implicit when passed to
/// `NetworkBuilder.interface(b => b.mtu(9000))`.
#[napi(js_name = "InterfaceOverridesBuilder")]
pub struct JsInterfaceOverridesBuilder {
    inner: InterfaceOverrides,
    errors: Vec<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsInterfaceOverridesBuilder {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: InterfaceOverrides::default(),
            errors: Vec::new(),
        }
    }

    /// Set the guest MAC address from a colon- or dash-delimited 6-byte
    /// string (e.g. `"aa:bb:cc:dd:ee:ff"`). Invalid input is recorded
    /// and surfaced when the parent `NetworkBuilder.build()` runs.
    #[napi]
    pub fn mac(&mut self, mac: String) -> &Self {
        match parse_mac(&mac) {
            Ok(bytes) => self.inner.mac = Some(bytes),
            Err(e) => self.errors.push(e),
        }
        self
    }

    /// Set the interface MTU. Default: 1500.
    #[napi]
    pub fn mtu(&mut self, mtu: u32) -> Result<&Self> {
        let mtu = u16::try_from(mtu)
            .map_err(|_| napi::Error::from_reason("mtu out of range (0..=65535)"))?;
        self.inner.mtu = Some(mtu);
        Ok(self)
    }

    /// Set the guest IPv4 address (e.g. `"100.96.0.5"`).
    #[napi(js_name = "ipv4")]
    pub fn ipv4(&mut self, address: String) -> &Self {
        match Ipv4Addr::from_str(&address) {
            Ok(a) => self.inner.ipv4_address = Some(a),
            Err(_) => self
                .errors
                .push(format!("invalid IPv4 address `{address}`")),
        }
        self
    }

    /// Set the guest IPv6 address (e.g. `"fd42:6d73:62::5"`).
    #[napi(js_name = "ipv6")]
    pub fn ipv6(&mut self, address: String) -> &Self {
        match Ipv6Addr::from_str(&address) {
            Ok(a) => self.inner.ipv6_address = Some(a),
            Err(_) => self
                .errors
                .push(format!("invalid IPv6 address `{address}`")),
        }
        self
    }
}

impl JsInterfaceOverridesBuilder {
    /// Internal: extract the configured `InterfaceOverrides`. Surfaces
    /// the first accumulated parse error as a typed napi error.
    pub(crate) fn take_built(&mut self) -> Result<InterfaceOverrides> {
        if let Some(e) = self.errors.first() {
            return Err(napi::Error::from_reason(e.clone()));
        }
        Ok(std::mem::take(&mut self.inner))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn parse_mac(s: &str) -> std::result::Result<[u8; 6], String> {
    let cleaned = s.replace(['-', '.'], ":");
    let parts: Vec<&str> = cleaned.split(':').collect();
    if parts.len() != 6 {
        return Err(format!(
            "invalid MAC address `{s}`: expected 6 hex octets separated by `:` or `-`"
        ));
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16)
            .map_err(|_| format!("invalid MAC address `{s}`: octet `{p}` is not hex"))?;
    }
    Ok(out)
}
