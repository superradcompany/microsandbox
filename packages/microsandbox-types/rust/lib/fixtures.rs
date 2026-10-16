//! Shared fixtures for cross-language conformance tests.
//!
//! Gated behind the `test-support` feature so the embedded payload never reaches
//! a normal runtime or SDK build.

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// The canonical hide_path-pattern disposition matrix.
///
/// A JSON array of `{"pattern", "readonly", "expect": "accept"|"reject"}` cases
/// pinned by [`crate::validate_hide_path_list`]. The Rust, CLI, Python, Node, and Go
/// test suites all load this one file and assert the same disposition, so a
/// pattern accepted by one language is accepted (or refused) by every other.
pub const HIDE_PATH_FIXTURE_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/hide_path/patterns.json"
));
