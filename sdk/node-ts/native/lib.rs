// napi's `#[napi]` macro generates registration code that references
// each exported function in the cdylib build, keeping them live. The
// test compile target omits that registration, so those functions look
// unused under `cargo test` / `cargo check --tests`. Silence dead_code
// in test builds only — production builds still lint it normally.
#![cfg_attr(test, allow(dead_code))]

mod dns_builder;
mod error;
mod exec;
mod fs;
mod helpers;
mod image;
mod metrics;
mod sandbox;
mod sandbox_handle;
mod setup;
mod types;
mod volume;
