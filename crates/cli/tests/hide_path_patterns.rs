//! CLI consumer of the shared deny-pattern disposition fixture.
//!
//! The CLI delegates `deny` validation to the shared
//! `microsandbox_types::validate_hide_path_list` (via the SDK/runtime), so it must
//! produce the same disposition as every other SDK for the fixture matrix,
//! embedded here as `microsandbox_types::fixtures::HIDE_PATH_FIXTURE_JSON`.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Case {
    pattern: String,
    readonly: bool,
    expect: String,
}

fn fixture_cases() -> Vec<Case> {
    serde_json::from_str(microsandbox_types::fixtures::HIDE_PATH_FIXTURE_JSON)
        .expect("parse shared deny fixture")
}

#[test]
fn hide_path_pattern_fixture_dispositions_match_shared_validator() {
    let cases = fixture_cases();
    assert!(!cases.is_empty(), "fixture must not be empty");

    for case in cases {
        let result =
            microsandbox_types::validate_hide_path_list(&[case.pattern.clone()], case.readonly);
        match case.expect.as_str() {
            "accept" => assert!(
                result.is_ok(),
                "expected accept for pattern {:?} readonly={}: got {:?}",
                case.pattern,
                case.readonly,
                result.err()
            ),
            "reject" => assert!(
                result.is_err(),
                "expected reject for pattern {:?} readonly={}",
                case.pattern,
                case.readonly
            ),
            other => panic!("unknown fixture expectation {other:?}"),
        }
    }
}
