//! Adapters for the cloud request contracts used by v0.6 SDKs.
//! Create requests used an untagged `image` before the source-tagged v0.7 format;
//! secret policies used `injection` and `on_violation`.
//! These adapters also accept current requests without changing their meaning.

pub(crate) mod secrets;
