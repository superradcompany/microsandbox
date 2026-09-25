//! Incoming decoding for previous process-launch contracts.

pub mod launch;
#[cfg(feature = "net")]
mod network;
mod v0_5_9;
mod v0_6_10;

pub(super) use launch::decode;

#[cfg(test)]
mod tests;
