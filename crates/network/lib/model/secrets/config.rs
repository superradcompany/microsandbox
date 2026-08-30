//! Secret substitution configuration types.
//!
//! The data types ([`SecretsConfig`], [`SecretEntry`], [`HostPattern`],
//! [`SecretSubstitution`], [`SecretViolationAction`]) and their validation live in the
//! shared `microsandbox-types` crate so the cloud control plane, the SDKs, and
//! this engine all speak one contract.

pub use microsandbox_types::{
    HostPattern, MAX_SECRET_PLACEHOLDER_BYTES, SecretConfigError, SecretEntry, SecretSource,
    SecretSubstitution, SecretViolationAction, SecretsConfig,
};
