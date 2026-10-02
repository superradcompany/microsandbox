use std::path::{Path, PathBuf};
use std::process::Command;

use microsandbox_types::{
    DiskImageFormat, ExternalMountRestorePolicy, HostPermissions, InterceptCaConfig,
    OciRootfsSource, OwnedVolumeStorage, Patch, RootDisk, RootfsSource, ScopedUpstreamCaCert,
    StatVirtualization, TlsConfig, VolumeMount,
};

use crate::SandboxConfig;

use super::resolve_host_paths;

//--------------------------------------------------------------------------------------------------
// Functions: Fixtures
//--------------------------------------------------------------------------------------------------

fn bind(host: PathBuf, guest: &str) -> VolumeMount {
    VolumeMount::Bind {
        host,
        guest: guest.into(),
        options: Default::default(),
        stat_virtualization: StatVirtualization::Strict,
        host_permissions: HostPermissions::Private,
        follow_root_symlinks: false,
        quota_mib: Some(128),
    }
}

fn config_with_host_inputs(base: Option<&Path>) -> SandboxConfig {
    let path =
        |relative: &str| base.map_or_else(|| PathBuf::from(relative), |base| base.join(relative));
    let mut config = SandboxConfig::default();
    config.spec.image = RootfsSource::Oci(OciRootfsSource {
        reference: "registry.example/team/image:tag".into(),
        root_disk: Some(RootDisk::DiskImage {
            path: path("root.ext4"),
            format: DiskImageFormat::Raw,
            fstype: Some("ext4".into()),
        }),
    });
    config.spec.runtime.workdir = Some("/guest/workdir".into());
    config.spec.mounts = vec![
        bind(path("workspace"), "/workspace"),
        bind(path("input.txt"), "/etc/input.txt"),
        VolumeMount::DiskImage {
            host: path("data.raw"),
            guest: "/data".into(),
            format: DiskImageFormat::Raw,
            fstype: Some("ext4".into()),
            options: Default::default(),
        },
        VolumeMount::Named {
            name: "shared-data".into(),
            guest: "/named".into(),
            create: None,
            options: Default::default(),
            stat_virtualization: StatVirtualization::Strict,
            host_permissions: HostPermissions::Private,
            follow_root_symlinks: false,
        },
        VolumeMount::Owned {
            guest: "/owned".into(),
            storage: OwnedVolumeStorage::Directory {
                quota_mib: Some(256),
            },
            options: Default::default(),
            stat_virtualization: StatVirtualization::Strict,
            host_permissions: HostPermissions::Private,
        },
        VolumeMount::Tmpfs {
            guest: "/scratch".into(),
            size_mib: Some(64),
            options: Default::default(),
        },
    ];
    config.spec.patches = vec![
        Patch::CopyFile {
            src: path("input.txt"),
            dst: "/etc/config".into(),
            mode: Some(0o600),
            replace: false,
        },
        Patch::CopyDir {
            src: path("source"),
            dst: "/app".into(),
            replace: true,
        },
        Patch::Symlink {
            target: "relative-guest-target".into(),
            link: "/app/link".into(),
            replace: false,
        },
    ];
    config.spec.network.tls = Some(TlsConfig {
        enabled: true,
        upstream_ca_cert: vec![path("upstream.pem")],
        scoped_upstream_ca_cert: vec![ScopedUpstreamCaCert {
            pattern: "*.example.com".into(),
            path: path("scoped.pem"),
        }],
        intercept_ca: InterceptCaConfig {
            cert_path: Some(path("intercept.pem")),
            key_path: Some(path("intercept.key")),
        },
        ..Default::default()
    });
    config
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn resolves_host_inputs_and_preserves_guest_paths_and_resource_names() {
    let mut config = config_with_host_inputs(None);
    let expected = config_with_host_inputs(Some(&std::env::current_dir().unwrap()));

    // None of these inputs needs to exist: anchoring must not become a
    // filesystem canonicalization step or change the existing admission rules.
    resolve_host_paths(&mut config).unwrap();

    assert_eq!(
        serde_json::to_value(&config).unwrap(),
        serde_json::to_value(&expected).unwrap()
    );
}

#[test]
fn resolves_bind_and_disk_rootfs_paths() {
    let expected = std::env::current_dir().unwrap().join("rootfs");
    for image in [
        RootfsSource::Bind {
            path: "rootfs".into(),
            follow_root_symlinks: false,
        },
        RootfsSource::DiskImage {
            path: "rootfs".into(),
            format: DiskImageFormat::Raw,
            fstype: Some("ext4".into()),
        },
    ] {
        let mut config = SandboxConfig::default();
        config.spec.image = image;
        resolve_host_paths(&mut config).unwrap();
        match &config.spec.image {
            RootfsSource::Bind { path, .. } | RootfsSource::DiskImage { path, .. } => {
                assert_eq!(path, &expected);
            }
            RootfsSource::Oci(_) => panic!("host rootfs changed kind"),
        }
    }
}

#[test]
fn preserves_absolute_paths_verbatim() {
    let base = std::env::current_dir()
        .unwrap()
        .join("missing")
        .join("..")
        .join(".");
    let mut config = config_with_host_inputs(Some(&base));
    let before = serde_json::to_value(&config).unwrap();

    resolve_host_paths(&mut config).unwrap();

    // Comparing the serialized spelling also detects unwanted removal of
    // dot components that Path's component-based equality would hide.
    assert_eq!(serde_json::to_value(&config).unwrap(), before);
}

#[test]
fn persisted_sources_survive_a_different_restart_directory() {
    const CHILD: &str = "MSB_HOST_PATHS_CWD_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        // Process cwd is global. Only this isolated child runs the cwd changes;
        // the normal test runner and its parallel tests never change directory.
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "backend::local::host_paths::tests::persisted_sources_survive_a_different_restart_directory",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "cwd regression child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("host path cwd regression completed")
        );
        return;
    }

    let original_cwd = std::env::current_dir().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let base = directory.path().canonicalize().unwrap();
    let first = base.join("first");
    let second = base.join("second");
    for (root, marker) in [(&first, "original"), (&second, "unrelated")] {
        std::fs::create_dir_all(root.join("workspace")).unwrap();
        std::fs::write(root.join("workspace/marker"), marker).unwrap();
        std::fs::write(root.join("input.txt"), marker).unwrap();
    }

    std::env::set_current_dir(&first).unwrap();
    let mut builder = crate::Sandbox::builder("early-mapping");
    builder.config = config_with_host_inputs(None).into();
    let backend = crate::backend::LocalBackend::builder()
        .home(base.join("home"))
        .build_lazy()
        .unwrap();
    builder.capture_host_paths(&backend).unwrap();
    let mut config = config_with_host_inputs(None);
    resolve_host_paths(&mut config).unwrap();
    let stored = serde_json::to_string(&config).unwrap();

    // Use the actual persisted-config decoder used by start, rather than only
    // a same-type serde round trip, so stored absolute inputs remain admitted.
    std::env::set_current_dir(&second).unwrap();
    let restored = serde_json::from_str::<SandboxConfig>(&stored).unwrap();
    let expected = config_with_host_inputs(Some(&first));
    // The same boundary is called before restore/branch preparation and before
    // progress tasks are spawned; delayed work must retain its original mappings.
    assert_eq!(
        serde_json::to_value(builder.config.clone().into_config()).unwrap(),
        serde_json::to_value(&expected).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&restored).unwrap(),
        serde_json::to_value(&expected).unwrap()
    );
    for mount in restored.spec.mounts.iter().take(2) {
        let VolumeMount::Bind { host, .. } = mount else {
            panic!("bind mount changed kind");
        };
        let file = if host.is_dir() {
            host.join("marker")
        } else {
            host.clone()
        };
        assert_eq!(std::fs::read_to_string(file).unwrap(), "original");
    }

    // Bare archive filenames have file precedence only at admission. A name
    // admitted as a store lookup must not become a file in the later cwd.
    std::fs::write(first.join("saved.tar"), b"archive fixture").unwrap();
    std::fs::write(first.join("base.tar"), b"base fixture").unwrap();
    std::fs::write(second.join("group"), b"unrelated shadow file").unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            use crate::{backend::SnapshotBackend, snapshot::SnapshotReference};
            let backend = std::sync::Arc::new(
                crate::backend::LocalBackend::builder()
                    .home(base.join("restore-home"))
                    .build_lazy()
                    .unwrap(),
            );
            for selector in ["saved.tar", "group"] {
                std::env::set_current_dir(&first).unwrap();
                let mut restore = SandboxConfig {
                    snapshot_reference: Some(SnapshotReference::auto(selector)),
                    snapshot_base: Some("base.tar".into()),
                    ..Default::default()
                };
                resolve_host_paths(&mut restore).unwrap();
                std::env::set_current_dir(&second).unwrap();
                // The create boundary resolves again after builder preparation.
                // Captured names must keep their original file-vs-store decision.
                resolve_host_paths(&mut restore).unwrap();
                let reference = restore.snapshot_reference.take().unwrap();
                let result = SnapshotBackend::prepare_restore(
                    backend.as_ref(),
                    backend.clone(),
                    &mut restore,
                    reference,
                )
                .await;
                if selector == "saved.tar" {
                    result.unwrap();
                    assert_eq!(
                        restore.snapshot_archive_source,
                        Some(first.join("saved.tar"))
                    );
                } else {
                    assert!(result.is_err());
                    assert!(restore.snapshot_archive_source.is_none());
                }
                assert_eq!(
                    restore.snapshot_base,
                    Some(first.join("base.tar").to_string_lossy().into_owned())
                );
            }

            // Reusing a built config must not skip admission for replacement inputs.
            // Exercise the real builder preparation, including bare-archive selection.
            std::fs::write(second.join("replacement.tar"), b"replacement archive").unwrap();
            let selected_backend: std::sync::Arc<dyn crate::backend::Backend> = backend.clone();
            crate::backend::with_backend(selected_backend, async {
                std::env::set_current_dir(&first).unwrap();
                let resolved = crate::sandbox::SandboxBuilder::new("reused-restore")
                    .override_snapshot("saved.tar")
                    .build()
                    .await
                    .unwrap();
                assert_eq!(
                    resolved.snapshot_archive_source,
                    Some(first.join("saved.tar"))
                );
                std::env::set_current_dir(&second).unwrap();
                for builder in [
                    crate::sandbox::SandboxBuilder::from(resolved.clone())
                        .override_snapshot("replacement.tar"),
                    crate::sandbox::SandboxBuilder::from(resolved.clone())
                        .with_snapshot_reference(SnapshotReference::auto("replacement.tar")),
                ] {
                    let replaced = builder.build().await.unwrap();
                    assert_eq!(
                        replaced.snapshot_archive_source,
                        Some(second.join("replacement.tar"))
                    );
                }
                let mut base_replacement = crate::sandbox::SandboxBuilder::from(resolved.clone())
                    .snapshot_base("replacement.tar");
                base_replacement
                    .capture_host_paths(backend.as_ref())
                    .unwrap();
                assert_eq!(
                    base_replacement.config.snapshot_base,
                    Some(
                        second
                            .join("replacement.tar")
                            .to_string_lossy()
                            .into_owned()
                    )
                );
                let mut source_replacement = crate::sandbox::SandboxBuilder::from(resolved)
                    .snapshot_resolved("sha256:replacement", "./replacement/upper.ext4");
                source_replacement
                    .capture_host_paths(backend.as_ref())
                    .unwrap();
                assert_eq!(
                    source_replacement.config.snapshot_reference,
                    Some(SnapshotReference::path(
                        second.join("replacement").to_string_lossy()
                    ))
                );
            })
            .await;
        });

    // Cover the issue's literal `./` source separately from named descendants.
    std::env::set_current_dir(&first).unwrap();
    let mut dot = SandboxConfig::default();
    dot.spec.mounts.push(bind("./".into(), "/workspace"));
    resolve_host_paths(&mut dot).unwrap();
    std::env::set_current_dir(&second).unwrap();
    let VolumeMount::Bind { host, .. } = &dot.spec.mounts[0] else {
        panic!("bind mount changed kind");
    };
    assert_eq!(host, &first);

    #[cfg(unix)]
    {
        // Collapsing `link/..` lexically would select first/marker instead of
        // actual/marker. Following the link here would bypass the bind policy.
        let actual = base.join("actual");
        std::fs::create_dir_all(actual.join("child")).unwrap();
        std::fs::write(actual.join("marker"), "through-link").unwrap();
        std::os::unix::fs::symlink(actual.join("child"), first.join("link")).unwrap();
        std::env::set_current_dir(&first).unwrap();
        for follow in [false, true] {
            let mut linked = SandboxConfig::default();
            linked.spec.image = RootfsSource::Bind {
                path: "link/../marker".into(),
                follow_root_symlinks: follow,
            };
            resolve_host_paths(&mut linked).unwrap();
            let RootfsSource::Bind {
                path,
                follow_root_symlinks,
            } = linked.spec.image
            else {
                panic!("bind rootfs changed kind");
            };
            assert_eq!(path.as_os_str(), first.join("link/../marker").as_os_str());
            assert_eq!(follow_root_symlinks, follow);
            assert_eq!(std::fs::read_to_string(path).unwrap(), "through-link");
        }
    }
    #[cfg(unix)]
    {
        // A disappeared cwd makes the capture timing observable without starting
        // a VM: progress APIs must fail before their background tasks can poll.
        let gone = base.join("gone");
        std::fs::create_dir(&gone).unwrap();
        let backend: std::sync::Arc<dyn crate::backend::Backend> = std::sync::Arc::new(backend);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(crate::backend::with_backend(backend, async {
                std::env::set_current_dir(&gone).unwrap();
                std::fs::remove_dir(&gone).unwrap();
                for mode in 0..3 {
                    let mut builder = crate::Sandbox::builder("unresolved-progress");
                    builder.config = config_with_host_inputs(None).into();
                    let failed = match mode {
                        0 => builder.create_with_progress().is_err(),
                        1 => builder.create_with_pull_progress().is_err(),
                        _ => builder.create_detached_with_pull_progress().is_err(),
                    };
                    assert!(failed, "progress method {mode} deferred path resolution");
                }
                assert!(
                    crate::Sandbox::restore("./snapshot")
                        .name("unresolved-restore")
                        .restore_with_progress()
                        .is_err()
                );
                let (_, task) =
                    crate::Sandbox::create_with_pull_progress(config_with_host_inputs(None));
                // If resolution waited for the task, this valid cwd would hide the error.
                std::env::set_current_dir(&second).unwrap();
                let error = match task.await.unwrap() {
                    Err(error) => error,
                    Ok(_) => panic!("unresolved progress task started a sandbox"),
                };
                assert!(error.to_string().contains("cannot resolve"), "{error}");
            }));
    }
    std::env::set_current_dir(original_cwd).unwrap();
    println!("host path cwd regression completed");
}

#[test]
fn legacy_saved_paths_round_trip_without_rewriting() {
    // Old saved state contains relative host inputs. The restart decoder and
    // persistence clone must preserve them; only new creation invokes resolution.
    let legacy = config_with_host_inputs(None);
    let stored = serde_json::to_string(&legacy).unwrap();
    let decoded = serde_json::from_str::<SandboxConfig>(&stored).unwrap();
    assert_eq!(serde_json::to_string(&decoded).unwrap(), stored);
    assert_eq!(
        serde_json::to_string(&decoded.clone_for_persistence()).unwrap(),
        stored
    );

    // A new child can capture the same inputs without changing its saved parent.
    let mut child = decoded.clone();
    resolve_host_paths(&mut child).unwrap();
    assert_eq!(serde_json::to_string(&decoded).unwrap(), stored);
    assert_eq!(
        serde_json::to_value(&child).unwrap(),
        serde_json::to_value(config_with_host_inputs(Some(
            &std::env::current_dir().unwrap()
        )))
        .unwrap()
    );
}

#[test]
fn restore_paths_are_captured_but_snapshot_names_and_ids_are_not() {
    use crate::snapshot::SnapshotReference;
    let expected = std::env::current_dir().unwrap();
    let mut config = SandboxConfig {
        snapshot_reference: Some(SnapshotReference::path("saved")),
        snapshot_archive_source: Some("./archive.tar".into()),
        snapshot_base: Some("./base.tar".into()),
        ..Default::default()
    };
    resolve_host_paths(&mut config).unwrap();
    assert_eq!(
        config.snapshot_reference,
        Some(SnapshotReference::path(
            expected.join("saved").to_string_lossy()
        ))
    );
    assert_eq!(
        config.snapshot_archive_source,
        Some(expected.join("archive.tar"))
    );
    assert_eq!(
        config.snapshot_base,
        Some(expected.join("base.tar").to_string_lossy().into_owned())
    );
    for reference in [
        SnapshotReference::auto("group:member"),
        SnapshotReference::id("snap_00000000000000000000000000000001"),
    ] {
        let mut resolved = reference.clone();
        super::resolve_snapshot_reference(&mut resolved).unwrap();
        assert_eq!(resolved, reference);
    }
}

#[test]
fn capturing_sparse_builder_paths_does_not_fill_other_layer_fields() {
    let mut patch = crate::SandboxConfigPatch::new();
    patch.spec.mounts = Some(config_with_host_inputs(None).spec.mounts);
    patch.spec.network.tls = Some(
        microsandbox_types::TlsConfigPatch::new().upstream_ca_cert(vec!["./company.pem".into()]),
    );
    super::resolve_patch_paths(&mut patch).unwrap();
    assert!(patch.spec.image.is_none());
    assert!(patch.spec.resources.cpus.is_none());
    assert!(patch.spec.runtime.workdir.is_none());
    assert!(patch.spec.patches.is_none());
    let tls = patch.spec.network.tls.unwrap();
    assert!(tls.enabled.is_none());
    assert!(tls.intercept_ca.is_none());
    assert_eq!(
        tls.upstream_ca_cert,
        Some(vec![std::path::absolute("./company.pem").unwrap()])
    );
    let mounts = patch.spec.mounts.unwrap();
    let VolumeMount::Bind { host, guest, .. } = &mounts[0] else {
        panic!("bind kind changed");
    };
    assert!(host.is_absolute());
    let original = config_with_host_inputs(None);
    let VolumeMount::Bind {
        guest: expected, ..
    } = &original.spec.mounts[0]
    else {
        unreachable!()
    };
    assert_eq!(guest, expected);
}

#[cfg(unix)]
fn bind_config(host: PathBuf, follow: bool) -> SandboxConfig {
    let mut mount = bind(host, "/data");
    if let VolumeMount::Bind {
        follow_root_symlinks,
        ..
    } = &mut mount
    {
        *follow_root_symlinks = follow;
    }
    let mut config = SandboxConfig::default();
    config.spec.mounts = vec![mount];
    config
}

#[cfg(unix)]
#[test]
fn bind_mount_through_symlink_fails_early_unless_it_opts_out() {
    // The runtime refuses symlinks in a bind mount root unless the mount opts out,
    // so creation must report that instead of persisting a sandbox that cannot boot.
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    let real = base.join("real");
    let link = base.join("link");
    std::fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let check = |host: PathBuf, follow: bool| {
        super::check_bind_roots_do_not_follow_symlinks(&bind_config(host, follow))
    };

    // The final component and an ancestor are both refused, naming the symlink
    // and the way out.
    let message = check(link.clone(), false).unwrap_err().to_string();
    assert!(message.contains("is a symlink"), "{message}");
    std::fs::create_dir(real.join("child")).unwrap();
    let message = check(link.join("child"), false).unwrap_err().to_string();
    assert!(message.contains("goes through symlink"), "{message}");
    for message in [check(link.clone(), false).unwrap_err().to_string(), message] {
        assert!(message.contains(&link.display().to_string()), "{message}");
        assert!(message.contains(&real.display().to_string()), "{message}");
        assert!(message.contains("follow-root-symlinks"), "{message}");
    }
    // Opting out, or naming the resolved path, is accepted.
    check(link, true).unwrap();
    check(real, false).unwrap();
}

#[cfg(unix)]
#[test]
fn bind_root_check_only_applies_to_existing_directories() {
    // A restore marks a vanished mount unavailable instead of failing, so the check
    // must not reject paths that no longer exist (or never were directories).
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    let real = base.join("real");
    let link = base.join("link");
    std::fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let file = real.join("input.txt");
    std::fs::write(&file, "x").unwrap();
    let file_link = base.join("file-link.txt");
    std::os::unix::fs::symlink(&file, &file_link).unwrap();
    let dangling = base.join("dangling");
    std::os::unix::fs::symlink(base.join("gone"), &dangling).unwrap();
    let check = |host: PathBuf| {
        super::check_bind_roots_do_not_follow_symlinks(&bind_config(host, false)).unwrap()
    };

    // A file reached through a symlinked ancestor, before and after it disappears
    // (the `/tmp/input.txt` case on macOS).
    check(link.join("input.txt"));
    std::fs::remove_file(&file).unwrap();
    check(link.join("input.txt"));
    // A missing directory under a symlinked ancestor.
    check(link.join("gone"));
    check(base.join("missing").join("child"));
    // A dangling link root, and a symlinked file.
    check(dangling);
    std::fs::write(&file, "x").unwrap();
    check(file_link);
}

#[cfg(unix)]
#[test]
fn host_path_resolution_accepts_a_vanished_file_under_a_symlinked_ancestor() {
    // Resolution runs before missing-resource admission on restore. It must leave a
    // vanished `/tmp/input.txt`-style mount for `--allow-missing-resources` to mark
    // unavailable rather than rejecting its symlinked ancestor.
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    let real = base.join("real");
    let link = base.join("link");
    std::fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let mut config = bind_config(link.join("input.txt"), false);
    resolve_host_paths(&mut config).unwrap();
    std::fs::write(real.join("input.txt"), "x").unwrap();
    resolve_host_paths(&mut config).unwrap();
    // A directory with the same name is still reported once admission has kept it.
    let mut dir = bind_config(link.join("dir"), false);
    std::fs::create_dir(real.join("dir")).unwrap();
    resolve_host_paths(&mut dir).unwrap();
    assert!(super::check_bind_roots_do_not_follow_symlinks(&dir).is_err());
}

#[cfg(unix)]
#[test]
fn restored_bind_check_retains_captured_transport_and_optional_backing() {
    use microsandbox_runtime::launch::{CheckpointRestoreConfig, ExternalMountRestoreBinding};

    // The runtime keeps a captured file transport, and tolerates an optional backing
    // under a relaxed restore, so the check must not refuse these first.
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    let real = base.join("real");
    let link = base.join("link");
    std::fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let check = |filename: Option<&str>, policy, require_backing| {
        let mut config = bind_config(link.clone(), false);
        config.checkpoint_restore = Some(CheckpointRestoreConfig {
            external_mount_policy: policy,
            external_mounts: vec![ExternalMountRestoreBinding {
                require_backing,
                device_id: "virtio_fs2".into(),
                mount: microsandbox_protocol::bootstrap::BootstrapDirMount {
                    tag: "tag".into(),
                    guest_path: "/data".into(),
                    flags: Default::default(),
                },
                filename: filename.map(Into::into),
                remapped: false,
                unavailable: false,
            }],
            ..Default::default()
        });
        super::check_bind_roots_do_not_follow_symlinks(&config)
    };
    let (strict, relaxed) = (
        ExternalMountRestorePolicy::Strict,
        ExternalMountRestorePolicy::Relaxed,
    );

    check(Some("input.txt"), strict, true).unwrap();
    check(None, relaxed, false).unwrap();
    check(None, relaxed, true).unwrap_err();
    check(None, strict, false).unwrap_err();
}
