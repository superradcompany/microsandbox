// napi's `#[napi]` macro generates registration code that references
// each exported function in the cdylib build, keeping them live. The
// test compile target omits that registration, so those functions look
// unused under `cargo test` / `cargo check --tests`. Silence dead_code
// in test builds only — production builds still lint it normally.
#![cfg_attr(test, allow(dead_code))]

mod attach_options_builder;
mod dns_builder;
mod error;
mod exec;
mod exec_options_builder;
mod fs;
mod image;
mod image_builder;
mod init_options_builder;
mod interface_overrides_builder;
mod metrics;
mod mount_builder;
mod network_builder;
mod network_policy_builder;
mod patch_builder;
mod pull_progress;
mod registry_builder;
mod sandbox;
mod sandbox_builder;
mod sandbox_handle;
mod secret_builder;
mod setup;
mod snapshot;
mod snapshot_builder;
mod tls_builder;
mod types;
mod volume;
mod volume_builder;
