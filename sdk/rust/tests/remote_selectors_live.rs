//! Opt-in provider reads. Credentials are supplied through the environment, never fixtures.
#![cfg(feature = "cloud")]
use microsandbox::{Sandbox, Snapshot, Volume};

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires MSB_REMOTE_SELECTOR_LIVE=1 and an authorized provider account"]
async fn remote_selector_reads() {
    assert_eq!(
        std::env::var("MSB_REMOTE_SELECTOR_LIVE").as_deref(),
        Ok("1")
    );
    let results = [
        (
            "sandbox_list",
            Sandbox::remote().unwrap().list().await.map(|_| ()),
        ),
        (
            "volume_list",
            Volume::remote().unwrap().list().await.map(|_| ()),
        ),
        (
            "snapshot_list",
            Snapshot::remote().unwrap().list().await.map(|_| ()),
        ),
    ];
    let rejected = std::env::var("MSB_REMOTE_EXPECT_AUTH_REJECTION").as_deref() == Ok("1");
    let mut failed = false;
    for (feature, result) in results {
        let status = result
            .as_ref()
            .err()
            .map(|error| error.to_string().contains("401"))
            .unwrap_or(false);
        println!(
            "selector-live {feature}: {}",
            if result.is_ok() {
                "PASS"
            } else if status {
                "HTTP_401"
            } else {
                "FAIL"
            }
        );
        failed |= if rejected { !status } else { result.is_err() };
    }
    assert!(
        !failed,
        "live selector results did not match the expected account access"
    );
}
