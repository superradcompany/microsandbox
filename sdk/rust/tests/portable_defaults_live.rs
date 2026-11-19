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

#[tokio::test]
#[ignore = "requires a portable-defaults smoke archive and a disposable local MSB_HOME"]
async fn archive_build_then_create_preserves_caller_environment_intent() {
    use microsandbox::sandbox::SandboxBuilder;
    use microsandbox::{Sandbox, SandboxConfigPatch, SandboxSpecPatch};
    let path = PathBuf::from(std::env::var_os("MSB_PORTABLE_DEFAULTS_ARCHIVE").unwrap());
    for (name, replace, expected) in [
        ("rebuilt-inherited", false, "source"),
        ("rebuilt-cleared", true, "unset"),
    ] {
        let mut builder = Sandbox::builder(name)
            .override_snapshot_paths(vec![path.clone()], None)
            .snapshot_launch_options(false, false);
        if replace {
            builder = builder.overlay(
                SandboxConfigPatch::new().spec(SandboxSpecPatch::new().replace_env(Vec::new())),
            );
        }
        let config = builder.build().await.unwrap();
        let sandbox = SandboxBuilder::from(config).create().await.unwrap();
        let result = sandbox
            .shell(r#"echo "${APP_MODE-unset}"; cat /tmp/roundtrip"#)
            .await;
        sandbox.stop().await.unwrap();
        let result = result.unwrap();
        assert_eq!(result.status().code, 0);
        assert_eq!(
            result.stdout().unwrap().trim(),
            format!("{expected}\ndisk-ok")
        );
    }
}
