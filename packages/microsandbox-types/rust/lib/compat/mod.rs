//! Previous contracts named after the release that introduced their wire shape.
//! Later releases reuse a contract until its shape changes. Cloud dispatch spans
//! versions; current domain and cloud types remain outside here.

pub(crate) mod cloud;
/// Field presence for typed compatibility readers.
pub mod field;
/// Local secret policies introduced in v0.5.0.
pub mod v0_5_0;
/// Alternate catalog and cloud-create shapes introduced in v0.6.5.
pub mod v0_6_5;
/// Tagged cloud secret policies introduced in v0.6.7.
pub mod v0_6_7;
/// Secret substitution policies introduced in v0.7.0.
pub mod v0_7_0;
