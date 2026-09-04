use std::cell::RefCell;
use std::rc::Rc;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use microsandbox::sandbox::SecretSource;
use microsandbox_network::{
    OutboundProxy, OutboundProxyBuilder as RustOutboundProxyBuilder, OutboundProxyConfig,
    Socks4ProxyBuilder as RustSocks4ProxyBuilder, Socks5ProxyBuilder as RustSocks5ProxyBuilder,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Selects the protocol for an outbound proxy.
#[napi(js_name = "OutboundProxyBuilder")]
pub struct JsOutboundProxyBuilder {
    inner: Option<RustOutboundProxyBuilder>,
    selection: SharedOutboundProxySelection,
}

pub(crate) type SharedOutboundProxySelection = Rc<RefCell<Option<OutboundProxySelection>>>;

pub(crate) enum OutboundProxySelection {
    Socks4(RustSocks4ProxyBuilder),
    Socks5(RustSocks5ProxyBuilder),
}

/// Builds a SOCKS4 outbound proxy.
#[napi(js_name = "Socks4ProxyBuilder")]
pub struct JsSocks4ProxyBuilder {
    selection: SharedOutboundProxySelection,
}

/// Builds a SOCKS5 outbound proxy.
#[napi(js_name = "Socks5ProxyBuilder")]
pub struct JsSocks5ProxyBuilder {
    selection: SharedOutboundProxySelection,
}

/// Host-side source for secret material.
#[napi(object, js_name = "SecretSourceInput")]
pub struct JsSecretSourceInput {
    /// Source kind. Currently only `env` is supported for proxy credentials.
    pub kind: String,
    /// Host environment variable name.
    pub var: String,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsOutboundProxyBuilder {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Some(RustOutboundProxyBuilder::new()),
            selection: Rc::new(RefCell::new(None)),
        }
    }

    pub(crate) fn selection(&self) -> SharedOutboundProxySelection {
        Rc::clone(&self.selection)
    }

    /// Select a SOCKS4 proxy at `address`.
    #[napi]
    pub fn socks4(&mut self, address: String) -> Result<JsSocks4ProxyBuilder> {
        let builder = self
            .inner
            .take()
            .ok_or_else(|| napi::Error::from_reason("OutboundProxyBuilder already consumed"))?;
        self.selection.replace(Some(OutboundProxySelection::Socks4(
            builder.socks4(address),
        )));
        Ok(JsSocks4ProxyBuilder {
            selection: Rc::clone(&self.selection),
        })
    }

    /// Select a SOCKS5 proxy at `address`.
    #[napi]
    pub fn socks5(&mut self, address: String) -> Result<JsSocks5ProxyBuilder> {
        let builder = self
            .inner
            .take()
            .ok_or_else(|| napi::Error::from_reason("OutboundProxyBuilder already consumed"))?;
        self.selection.replace(Some(OutboundProxySelection::Socks5(
            builder.socks5(address),
        )));
        Ok(JsSocks5ProxyBuilder {
            selection: Rc::clone(&self.selection),
        })
    }
}

#[napi]
impl JsSocks4ProxyBuilder {
    /// Set the optional user ID sent during the SOCKS4 handshake.
    #[napi]
    pub fn user_id(&mut self, user_id: String) -> Result<&Self> {
        let builder = self
            .selection
            .take()
            .ok_or_else(|| napi::Error::from_reason("Socks4ProxyBuilder already consumed"))?;
        let OutboundProxySelection::Socks4(builder) = builder else {
            return Err(napi::Error::from_reason(
                "Socks4ProxyBuilder selection was replaced",
            ));
        };
        self.selection.replace(Some(OutboundProxySelection::Socks4(
            builder.user_id(user_id),
        )));
        Ok(self)
    }
}

#[napi]
impl JsSocks5ProxyBuilder {
    /// Set username authentication and a host-side password source.
    #[napi]
    pub fn credentials(
        &mut self,
        username: String,
        password: JsSecretSourceInput,
    ) -> Result<&Self> {
        if password.kind != "env" {
            return Err(napi::Error::from_reason(format!(
                "unsupported SOCKS5 password source {:?}; only env is supported",
                password.kind
            )));
        }
        let builder = self
            .selection
            .take()
            .ok_or_else(|| napi::Error::from_reason("Socks5ProxyBuilder already consumed"))?;
        let OutboundProxySelection::Socks5(builder) = builder else {
            return Err(napi::Error::from_reason(
                "Socks5ProxyBuilder selection was replaced",
            ));
        };
        self.selection.replace(Some(OutboundProxySelection::Socks5(
            builder.credentials(username, SecretSource::env(password.var)),
        )));
        Ok(self)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn take_selected_proxy(
    selection: &SharedOutboundProxySelection,
) -> Result<OutboundProxy> {
    let selection = selection.borrow_mut().take().ok_or_else(|| {
        napi::Error::from_reason("proxy callback must select a SOCKS4 or SOCKS5 proxy builder")
    })?;
    match selection {
        OutboundProxySelection::Socks4(builder) => builder.build(),
        OutboundProxySelection::Socks5(builder) => builder.build(),
    }
    .map_err(|error| napi::Error::from_reason(error.to_string()))
}
