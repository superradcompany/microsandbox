//! TCP connection tracking, proxying, and host-side upstream dialing.

pub mod connection;
pub(crate) mod deferred_close;
pub(crate) mod deny;
pub mod proxy;
pub(crate) mod upstream;

#[cfg(test)]
pub(crate) mod test_support;
