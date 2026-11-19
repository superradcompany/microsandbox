//! Restore an archive created by the portable-defaults CLI smoke after its source was removed.
#![cfg(feature = "local")]

use std::path::PathBuf;

use microsandbox::snapshot::Snapshot;

#[tokio::test]
#[ignore = "requires a portable-defaults smoke archive and a disposable local MSB_HOME"]
async fn read_saved_disk_defaults_and_override_them_on_a_checkpoint() {
    let path = PathBuf::from(std::env::var_os("MSB_PORTABLE_DEFAULTS_ARCHIVE").unwrap());
    let group = Snapshot::load("portable-defaults", &[path])
        .await
        .unwrap()
        .snapshot;
    let member = group.head().await.unwrap().unwrap();
    for (name, expected) in [
        ("inherited", "/tmp\nsource\ndisk-ok"),
        ("explicit", "/root\ndestination\ndisk-ok"),
    ] {
        let sandbox = if name == "inherited" {
            group.spawn_sandbox_with(|b| b.name(name)).await
        } else {
            member
                .spawn_sandbox_with(|b| {
                    b.name(name).workdir("/root").env("APP_MODE", "destination")
                })
                .await
        }
        .unwrap();
        let output = sandbox
            .shell(r#"pwd; echo "$APP_MODE"; cat /tmp/roundtrip"#)
            .await;
        sandbox.stop().await.unwrap();
        let output = output.unwrap();
        assert_eq!(output.status().code, 0);
        assert_eq!(output.stdout().unwrap().trim(), expected);
    }
}
