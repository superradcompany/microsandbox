use std::path::Path;
use std::sync::Arc;

use super::PreparedSnapshotImport;
use crate::backend::{Backend, LocalBackend, set_default_backend};
use crate::snapshot::{LoadOpts, SaveOpts, SnapshotReference};

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "cloud")]
#[tokio::test]
async fn cloud_import_keeps_backend_paths_and_unsupported_errors() {
    let backend: Arc<dyn Backend> =
        Arc::new(crate::CloudBackend::new("http://127.0.0.1:1", "test-only-placeholder").unwrap());
    for kind in 0..3 {
        let request = PreparedSnapshotImport::with_backend(
            backend.clone(),
            vec!["".into(), "relative.tar".into()],
            LoadOpts {
                dest: Some("relative-dest".into()),
                base: Some("relative-base".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            request.files,
            vec![std::path::PathBuf::new(), "relative.tar".into()]
        );
        assert_eq!(
            request.options.dest.as_deref(),
            Some(Path::new("relative-dest"))
        );
        assert_eq!(request.options.base.as_deref(), Some("relative-base"));
        let error = match kind {
            0 => request.group("group".into()).await.err().unwrap(),
            1 => request.checkpoints().await.err().unwrap(),
            _ => request.legacy_checkpoint().await.err().unwrap(),
        };
        assert!(matches!(
            error,
            crate::MicrosandboxError::Unsupported { .. }
        ));
    }
    let request = PreparedSnapshotImport::with_backend(
        backend,
        vec!["relative.tar".into()],
        LoadOpts::default(),
    )
    .unwrap();
    assert!(matches!(
        request.legacy_checkpoint().await,
        Err(crate::MicrosandboxError::Unsupported { .. })
    ));
}

#[test]
fn deferred_import_retains_paths_base_kind_and_backend() {
    const CHILD: &str = "MSB_TEST_DEFERRED_IMPORT_CWD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "snapshot::import::tests::deferred_import_retains_paths_base_kind_and_backend",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("deferred imports checked"));
        return;
    }
    // Cwd and the default backend belong to this test's child process, never other tests.
    let root = tempfile::tempdir().unwrap();
    let root = root.path().canonicalize().unwrap();
    let first = root.join("first");
    let second = root.join("second");
    let source = first.join("source");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::create_dir_all(&second).unwrap();
    std::fs::write(source.join("snapshot.json"), br#"{"schema":1,"artifact":"snapshot","scope":"disk","created_at":"2026-05-01T12:00:00Z","parent":null,"image":{"ref":"docker.io/library/alpine:3.20","manifest_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"source_sandbox":null,"state":{"kind":"file","format":"raw","fstype":"ext4","upper":{"file":"upper.ext4","size_bytes":512,"integrity":null}},"labels":{},"extensions":{},"requires":[]}"#).unwrap();
    std::fs::write(source.join("upper.ext4"), [42; 512]).unwrap();
    for name in ["base.tar", "delta.tar", "base-group"] {
        std::fs::write(second.join(name), b"unrelated shadow").unwrap();
    }
    let original = std::env::current_dir().unwrap();
    std::env::set_current_dir(&first).unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let local = LocalBackend::builder()
                .home(root.join("home-a"))
                .config_path(root.join("absent.json"))
                .managed_config_path(root.join("absent-managed.json"))
                .build()
                .await
                .unwrap();
            let backend: Arc<dyn Backend> = Arc::new(local);
            set_default_backend(backend.clone());
            let reference = SnapshotReference::path(source.to_string_lossy());
            backend
                .snapshots()
                .save(
                    reference.clone(),
                    &first.join("base.tar"),
                    SaveOpts {
                        plain_tar: true,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            backend
                .snapshots()
                .save(
                    reference,
                    &first.join("delta.tar"),
                    SaveOpts {
                        plain_tar: true,
                        since: Some("base.tar".into()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            PreparedSnapshotImport::new(vec!["base.tar".into()], LoadOpts::default())
                .unwrap()
                .group("base-group".into())
                .await
                .unwrap();

            let mut requests = Vec::new();
            for (group, base) in [
                ("from-group", "base-group"),
                ("from-archive", "base.tar"),
                ("from-explicit", "./base.tar"),
            ] {
                requests.push((
                    group,
                    PreparedSnapshotImport::new(
                        vec!["delta.tar".into()],
                        LoadOpts {
                            dest: Some("destination".into()),
                            base: Some(base.into()),
                            ..Default::default()
                        },
                    )
                    .unwrap(),
                ));
            }
            let many = PreparedSnapshotImport::new(
                vec!["delta.tar".into()],
                LoadOpts {
                    base: Some("base-group".into()),
                    group: Some("many".into()),
                    ..Default::default()
                },
            )
            .unwrap();
            let single = PreparedSnapshotImport::new(
                vec!["delta.tar".into()],
                LoadOpts {
                    base: Some("base-group".into()),
                    group: Some("single".into()),
                    ..Default::default()
                },
            )
            .unwrap();
            let legacy = PreparedSnapshotImport::new(
                vec!["base.tar".into()],
                LoadOpts {
                    dest: Some("legacy".into()),
                    ..Default::default()
                },
            )
            .unwrap();
            #[cfg(unix)]
            let symlink_parent = {
                std::fs::create_dir(second.join("nested")).unwrap();
                std::os::unix::fs::symlink(second.join("nested"), first.join("alias")).unwrap();
                // The OS resolves alias/.. to second, whose archive is deliberately
                // invalid. Lexically removing .. would wrongly import first/base.tar.
                let request = PreparedSnapshotImport::new(
                    vec!["alias/../base.tar".into()],
                    LoadOpts::default(),
                )
                .unwrap();
                assert_eq!(request.files, vec![first.join("alias/../base.tar")]);
                request
            };
            let missing =
                PreparedSnapshotImport::new(vec!["missing.tar".into()], LoadOpts::default())
                    .unwrap();

            let other: Arc<dyn Backend> = Arc::new(
                LocalBackend::builder()
                    .home(root.join("home-b"))
                    .config_path(root.join("absent.json"))
                    .managed_config_path(root.join("absent-managed.json"))
                    .build()
                    .await
                    .unwrap(),
            );
            set_default_backend(other.clone());
            std::env::set_current_dir(&second).unwrap();
            for (group, request) in requests {
                let imported = request.group(group.into()).await.unwrap();
                assert_eq!(imported.checkpoints.len(), 1);
                let handle = &imported.checkpoints[0];
                assert!(
                    handle
                        .path()
                        .unwrap()
                        .starts_with(first.join("destination"))
                );
                assert!(Arc::ptr_eq(&handle.backend, &backend));
                let opened = handle.open().await.unwrap();
                let crate::snapshot::SnapshotState::File(file) = &opened.manifest().state else {
                    panic!("expected a file snapshot");
                };
                let payload = file.layer_path(&file.layers[0]);
                assert_eq!(
                    std::fs::read(handle.path().unwrap().join(payload)).unwrap(),
                    [42; 512]
                );
            }
            for handle in many
                .checkpoints()
                .await
                .unwrap()
                .into_iter()
                .chain([single.checkpoint().await.unwrap()])
            {
                assert!(Arc::ptr_eq(&handle.backend, &backend));
                assert!(handle.path().unwrap().starts_with(root.join("home-a")));
            }
            assert!(
                legacy
                    .legacy_checkpoint()
                    .await
                    .unwrap()
                    .path()
                    .unwrap()
                    .starts_with(first.join("legacy"))
            );
            assert!(
                other
                    .snapshots()
                    .list(other.clone())
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(!second.join("destination").exists());
            assert_eq!(
                std::fs::read(second.join("base-group")).unwrap(),
                b"unrelated shadow"
            );
            #[cfg(unix)]
            assert!(
                symlink_parent
                    .group("invalid-symlink-parent".into())
                    .await
                    .is_err()
            );
            assert!(missing.group("missing-archive".into()).await.is_err());
            assert!(
                !root
                    .join("home-a/snapshots/invalid-symlink-parent")
                    .exists()
            );
            assert!(!root.join("home-a/snapshots/missing-archive").exists());
            // Empty paths must fail during admission, rather than silently meaning the cwd.
            assert!(
                PreparedSnapshotImport::new(vec![Path::new("").into()], LoadOpts::default())
                    .is_err()
            );
        });
    std::env::set_current_dir(original).unwrap();
    println!("deferred imports checked");
}
