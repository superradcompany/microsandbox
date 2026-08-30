//! Secret injection configuration types.
//!
//! The data types ([`SecretsConfig`], [`SecretEntry`], [`HostPattern`],
//! [`SecretInjection`], [`ViolationAction`]) and their validation live in the
//! shared `microsandbox-types` crate so the cloud control plane, the SDKs, and
//! this engine all speak one contract.

pub use microsandbox_types::{
    HostPattern, MAX_SECRET_PLACEHOLDER_BYTES, SecretConfigError, SecretEntry, SecretInjection,
    SecretSource, SecretsConfig, ViolationAction,
};
