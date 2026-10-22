//! Exact backing and adversarial namespace checks, independent of activation.

use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::{self, File},
    os::unix::{
        ffi::OsStrExt,
        fs::{FileExt, MetadataExt, PermissionsExt, symlink},
    },
    path::Path,
    process::Command,
};

use cap_std::fs::Dir;
use tempfile::TempDir;

use crate::{Context, DynFileSystem, FsOptions};

use super::runtime_scripts::{
    CapturedRuntimeScripts, RuntimeBootScript, RuntimeRestoredScript, RuntimeScriptLimits,
    RuntimeScriptMetadata, stage_boot_scripts_with_check, stage_restored_scripts_with_check,
    stage_runtime_boot_scripts, stage_runtime_restored_scripts,
};
use super::{PassthroughConfig, PassthroughFs};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn source() -> (TempDir, File) {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("scripts")).unwrap();
    let dir = Dir::open_ambient_dir(root.path(), cap_std::ambient_authority()).unwrap();
    (root, dir.into_std_file())
}

fn capture_files(
    runtime: &File,
    names: &BTreeSet<String>,
) -> std::io::Result<CapturedRuntimeScripts> {
    CapturedRuntimeScripts::capture(
        runtime,
        names,
        RuntimeScriptLimits {
            max_entries: 256,
            max_script_bytes: 64 * 1024,
            max_total_bytes: 256 * 1024,
        },
    )
}

fn names(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|name| name.to_string()).collect()
}

fn permissions(path: &Path, uid: u32, gid: u32, mode: u16) {
    PassthroughFs::set_runtime_backing_permissions(&File::open(path).unwrap(), uid, gid, mode)
        .unwrap();
}

fn boot_limits() -> RuntimeScriptLimits {
    RuntimeScriptLimits {
        max_entries: 4,
        max_script_bytes: 64,
        max_total_bytes: 128,
    }
}

fn mounted_runtime(root: &Path) -> PassthroughFs {
    let backend = PassthroughFs::new(PassthroughConfig {
        root_dir: root.to_path_buf(),
        inject_init: false,
        ..Default::default()
    })
    .unwrap();
    backend.init(FsOptions::empty()).unwrap();
    backend
}

fn root_context() -> Context {
    Context {
        uid: 0,
        gid: 0,
        pid: 0,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn boot_staging_preserves_exact_bytes_and_guest_modes_without_a_source() {
    let parent = tempfile::tempdir().unwrap();
    let content = "#!/bin/sh\r\nprintf 'λ'\r\n\0";
    let inputs = [
        RuntimeBootScript {
            name: "private",
            content,
            mode: 0,
        },
        RuntimeBootScript {
            name: "task",
            content,
            mode: 0o751,
        },
    ];
    let staged = stage_runtime_boot_scripts(parent.path(), &inputs, boot_limits()).unwrap();
    let path = staged.path().to_owned();
    for input in &inputs {
        let file = path.join("scripts").join(input.name);
        assert_eq!(fs::read(&file).unwrap(), content.as_bytes());
        let guest = PassthroughFs::runtime_backing_stat(&File::open(&file).unwrap()).unwrap();
        assert_eq!((guest.st_uid, guest.st_gid), (0, 0));
        assert_eq!((guest.st_mode & 0o7777) as u16, input.mode);
        assert_eq!(fs::metadata(file).unwrap().permissions().mode() & 0o077, 0);
        assert!(!format!("{input:?}").contains(content));
        assert!(!format!("{input:?}").contains(input.name));
    }
    for relative in ["", "scripts"] {
        let dir = path.join(relative);
        let guest = PassthroughFs::runtime_backing_stat(&File::open(&dir).unwrap()).unwrap();
        assert_eq!(
            (guest.st_uid, guest.st_gid, guest.st_mode & 0o7777),
            (0, 0, 0o755)
        );
        assert_eq!(fs::metadata(dir).unwrap().permissions().mode() & 0o077, 0);
    }
    drop(staged);
    assert!(!path.exists());
}

#[test]
fn boot_staging_refuses_invalid_input_before_creating_files() {
    let parent = tempfile::tempdir().unwrap();
    for name in [
        "../SENSITIVE",
        "nested/SENSITIVE",
        "\\SENSITIVE",
        ".",
        "",
        "bad\0name",
    ] {
        let error = stage_runtime_boot_scripts(
            parent.path(),
            &[RuntimeBootScript {
                name,
                content: "CONTENT_SENTINEL",
                mode: 0o755,
            }],
            boot_limits(),
        )
        .unwrap_err();
        assert!(!error.to_string().contains("SENSITIVE"));
        assert!(!error.to_string().contains("CONTENT_SENTINEL"));
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    }
    for (names, content, mode, limits) in [
        (
            vec!["same", "same"],
            "value".to_owned(),
            0o755,
            boot_limits(),
        ),
        (
            vec!["a", "b", "c", "d", "e"],
            "value".to_owned(),
            0o755,
            boot_limits(),
        ),
        (vec!["large"], "x".repeat(65), 0o755, boot_limits()),
        (vec!["a", "b", "c"], "x".repeat(64), 0o755, boot_limits()),
        (
            vec!["privileged"],
            "value".to_owned(),
            0o4755,
            boot_limits(),
        ),
        (
            vec!["bad-limit"],
            "value".to_owned(),
            0o755,
            RuntimeScriptLimits {
                max_script_bytes: usize::MAX,
                ..boot_limits()
            },
        ),
    ] {
        let inputs: Vec<_> = names
            .iter()
            .map(|name| RuntimeBootScript {
                name,
                content: &content,
                mode,
            })
            .collect();
        assert!(stage_runtime_boot_scripts(parent.path(), &inputs, limits).is_err());
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    }
}

#[test]
fn boot_staging_never_overwrites_existing_paths_or_case_aliases() {
    let parent = tempfile::tempdir().unwrap();
    let protected = parent.path().join("protected");
    fs::write(&protected, "UNCHANGED").unwrap();
    assert!(stage_runtime_boot_scripts(&protected, &[], boot_limits()).is_err());
    assert_eq!(fs::read_to_string(&protected).unwrap(), "UNCHANGED");

    // Respect the actual destination filesystem: macOS volumes need not be case-sensitive.
    let probe = parent.path().join("CaseProbe");
    fs::write(&probe, "probe").unwrap();
    let aliases_case = parent.path().join("caseprobe").exists();
    fs::remove_file(probe).unwrap();
    let inputs = [
        RuntimeBootScript {
            name: "Job",
            content: "FIRST",
            mode: 0o640,
        },
        RuntimeBootScript {
            name: "job",
            content: "SECOND",
            mode: 0o755,
        },
    ];
    let result = stage_runtime_boot_scripts(parent.path(), &inputs, boot_limits());
    if aliases_case {
        assert!(
            result.is_err(),
            "case aliases must not replace the first file"
        );
    } else {
        let staged = result.unwrap();
        for input in inputs {
            assert_eq!(
                fs::read_to_string(staged.path().join("scripts").join(input.name)).unwrap(),
                input.content
            );
        }
    }
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 1);
    assert_eq!(fs::read_to_string(protected).unwrap(), "UNCHANGED");
}

#[test]
fn boot_staging_discards_partial_files_and_detects_namespace_or_metadata_changes() {
    let parent = tempfile::tempdir().unwrap();
    for fault in 0..6 {
        let inputs = [RuntimeBootScript {
            name: "task",
            content: "exact",
            mode: 0o640,
        }];
        let mut reached = false;
        let result = stage_boot_scripts_with_check(parent.path(), &inputs, boot_limits(), |path| {
            reached = true;
            let file = path.join("scripts/task");
            assert_eq!(fs::read(&file).unwrap(), b"exact");
            match fault {
                0 => return Err(std::io::Error::other("SECRET_FAILURE_SENTINEL")),
                1 => fs::write(file, "different").unwrap(),
                2 => permissions(&file, 0, 0, 0o755),
                3 => permissions(&path.join("scripts"), 0, 0, 0o700),
                4 => {
                    fs::rename(path.join("scripts"), path.join("old-scripts")).unwrap();
                    fs::create_dir(path.join("scripts")).unwrap();
                }
                5 => {
                    fs::remove_file(&file).unwrap();
                    symlink("/outside/SENSITIVE", file).unwrap();
                }
                _ => unreachable!(),
            }
            Ok(())
        });
        assert!(reached, "must test failure after files exist");
        let error = result.unwrap_err().to_string();
        assert!(!error.contains("SENSITIVE") && !error.contains("SECRET_FAILURE_SENTINEL"));
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    }
}

#[test]
fn exact_script_staging_preserves_guest_zero_mode_ownership_and_directory_metadata() {
    let (root, dir) = source();
    let content = "#!/bin/sh\r\nprintf 'LITERAL_SENTINEL λ'\r\n";
    fs::write(root.path().join("scripts/task"), content).unwrap();
    permissions(&root.path().join("scripts/task"), 123, 456, 0);
    permissions(root.path(), 7, 8, 0o751);
    permissions(&root.path().join("scripts"), 9, 10, 0o710);
    let capture = capture_files(&dir, &names(&["task"])).unwrap();
    let parent = tempfile::tempdir().unwrap();
    let staged = capture.stage_exact(parent.path()).unwrap();
    let staged_path = staged.path().to_owned();
    assert_eq!(
        fs::read(staged.path().join("scripts/task")).unwrap(),
        content.as_bytes()
    );
    for (relative, uid, gid, mode) in [
        ("", 7, 8, 0o751),
        ("scripts", 9, 10, 0o710),
        ("scripts/task", 123, 456, 0),
    ] {
        let stat =
            PassthroughFs::runtime_backing_stat(&File::open(staged.path().join(relative)).unwrap())
                .unwrap();
        assert_eq!((stat.st_uid, stat.st_gid), (uid, gid));
        assert_eq!(stat.st_mode & 0o7777, mode);
    }
    capture.revalidate().unwrap();
    assert!(!format!("{capture:?}").contains("SENTINEL"));
    assert_eq!(
        fs::read_to_string(root.path().join("scripts/task")).unwrap(),
        content
    );
    drop(staged);
    assert!(!staged_path.exists());
}

#[test]
fn linked_scripts_cannot_claim_independent_portable_backing() {
    for registration in [names(&["task"]), names(&["task", "alias"])] {
        let (root, dir) = source();
        fs::write(root.path().join("scripts/task"), "PRIVATE_BODY").unwrap();
        fs::hard_link(
            root.path().join("scripts/task"),
            root.path().join("scripts/alias"),
        )
        .unwrap();
        let error = capture_files(&dir, &registration).unwrap_err().to_string();
        assert!(!error.contains("PRIVATE") && !error.contains("alias"));
    }

    // An alias outside the registered directory matters too: copying just this name
    // would still change the guest-visible link count and future write relationships.
    let (root, dir) = source();
    fs::write(root.path().join("scripts/task"), "PRIVATE_BODY").unwrap();
    let observed = capture_files(&dir, &names(&["task"])).unwrap();
    fs::hard_link(
        root.path().join("scripts/task"),
        root.path().join("outside-script-directory"),
    )
    .unwrap();
    assert!(capture_files(&dir, &names(&["task"])).is_err());
    assert!(observed.revalidate().is_err());
    let parent = tempfile::tempdir().unwrap();
    assert!(observed.stage_exact(parent.path()).is_err());
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
}

#[test]
fn source_inode_replacement_cannot_reuse_observed_bytes_or_publish_staging() {
    let (root, dir) = source();
    let file = root.path().join("scripts/task");
    fs::write(&file, "same bytes").unwrap();
    let capture = capture_files(&dir, &names(&["task"])).unwrap();
    let replacement = root.path().join("replacement");
    fs::write(&replacement, "same bytes").unwrap();
    fs::rename(replacement, &file).unwrap();
    assert!(capture.revalidate().is_err());
    let parent = tempfile::tempdir().unwrap();
    assert!(capture.stage_exact(parent.path()).is_err());
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
}

#[test]
fn content_and_virtual_permission_changes_invalidate_observations() {
    for mutate_content in [true, false] {
        let (root, dir) = source();
        let file = root.path().join("scripts/task");
        fs::write(&file, "old bytes").unwrap();
        let capture = capture_files(&dir, &names(&["task"])).unwrap();
        if mutate_content {
            fs::write(&file, "new bytes").unwrap();
        } else {
            permissions(&file, 0, 0, 0o640);
        }
        assert!(capture.revalidate().is_err());
    }
}

#[test]
fn linked_script_and_replaced_scripts_directory_never_read_outside_content() {
    let (root, dir) = source();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("SECRET_PATH"), "SECRET_CONTENT").unwrap();
    symlink(
        outside.path().join("SECRET_PATH"),
        root.path().join("scripts/task"),
    )
    .unwrap();
    let error = capture_files(&dir, &names(&["task"]))
        .unwrap_err()
        .to_string();
    assert!(!error.contains("SECRET"));
    fs::remove_file(root.path().join("scripts/task")).unwrap();
    fs::write(root.path().join("scripts/task"), "original").unwrap();
    let capture = capture_files(&dir, &names(&["task"])).unwrap();
    fs::rename(root.path().join("scripts"), root.path().join("previous")).unwrap();
    symlink(outside.path(), root.path().join("scripts")).unwrap();
    assert!(capture.revalidate().is_err());
    assert!(capture_files(&dir, &names(&["SECRET_PATH"])).is_err());
    assert_eq!(
        fs::read_to_string(outside.path().join("SECRET_PATH")).unwrap(),
        "SECRET_CONTENT"
    );
}

#[test]
fn invalid_names_refuse_before_opening_any_candidate() {
    let (_root, dir) = source();
    for name in [
        "",
        ".",
        "..",
        "../SECRET",
        "/SECRET",
        "a/b",
        "a\\b",
        "NUL\0SECRET",
    ] {
        let error = capture_files(&dir, &names(&[name]))
            .unwrap_err()
            .to_string();
        assert!(error.contains("SCFG_BACKING"));
        assert!(!error.contains("SECRET"));
    }
}

#[test]
fn non_files_invalid_utf8_and_size_limits_refuse_without_executing_or_blocking() {
    let (root, dir) = source();
    fs::write(root.path().join("scripts/invalid"), [0xff]).unwrap();
    fs::write(root.path().join("scripts/large"), vec![b'x'; 64 * 1024 + 1]).unwrap();
    fs::create_dir(root.path().join("scripts/directory")).unwrap();
    let fifo = CString::new(root.path().join("scripts/fifo").as_os_str().as_bytes()).unwrap();
    // SAFETY: the CString is terminated and points into our owned temporary directory.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    for name in ["invalid", "large", "directory", "fifo"] {
        assert!(capture_files(&dir, &names(&[name])).is_err(), "{name}");
    }
    let too_many = (0..257).map(|i| format!("script-{i}")).collect();
    assert!(
        capture_files(&dir, &too_many)
            .unwrap_err()
            .to_string()
            .contains("SCFG_LIMIT")
    );
    for i in 0..5 {
        fs::write(
            root.path().join(format!("scripts/script-{i}")),
            vec![b'x'; 64 * 1024],
        )
        .unwrap();
    }
    assert!(
        capture_files(&dir, &(0..5).map(|i| format!("script-{i}")).collect())
            .unwrap_err()
            .to_string()
            .contains("SCFG_LIMIT")
    );
    assert!(
        CapturedRuntimeScripts::capture(
            &dir,
            &BTreeSet::new(),
            RuntimeScriptLimits {
                max_entries: 1,
                max_script_bytes: usize::MAX,
                max_total_bytes: usize::MAX,
            }
        )
        .is_err()
    );
}

#[test]
fn staging_failure_does_not_replace_existing_destination_and_empty_is_known_empty() {
    let (_root, dir) = source();
    let capture = capture_files(&dir, &BTreeSet::new()).unwrap();
    assert_eq!(capture.observations().count(), 0);
    let parent = tempfile::tempdir().unwrap();
    let sentinel = parent.path().join("keep");
    fs::write(&sentinel, "UNCHANGED").unwrap();
    assert!(capture.stage_exact(&sentinel).is_err());
    assert_eq!(fs::read_to_string(&sentinel).unwrap(), "UNCHANGED");
    let staged = capture.stage_exact(parent.path()).unwrap();
    assert_eq!(
        fs::read_dir(staged.path().join("scripts")).unwrap().count(),
        0
    );
}

#[test]
fn late_failure_or_source_change_discards_every_staged_file() {
    for source_change in [false, true] {
        let (root, dir) = source();
        for name in ["first", "second"] {
            fs::write(root.path().join("scripts").join(name), "captured").unwrap();
        }
        let capture = capture_files(&dir, &names(&["first", "second"])).unwrap();
        let parent = tempfile::tempdir().unwrap();
        let mut reached_completion = false;
        let result = capture.stage_with_check(parent.path(), || {
            reached_completion = true;
            let temporary = fs::read_dir(parent.path())
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            assert!(temporary.join("scripts/first").is_file());
            assert!(temporary.join("scripts/second").is_file());
            if source_change {
                fs::write(root.path().join("scripts/second"), "changed").unwrap();
                Ok(())
            } else {
                Err(std::io::Error::other("injected late failure"))
            }
        });
        assert!(reached_completion, "must exercise failure after staging");
        assert!(result.is_err());
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
        assert_eq!(
            fs::read_to_string(root.path().join("scripts/first")).unwrap(),
            "captured"
        );
    }
}

#[test]
fn relative_staging_keeps_symlink_parent_semantics_and_survives_cwd_change() {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "backends::passthroughfs::unix::runtime_scripts_tests::relative_staging_worker",
            "--ignored",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
}

#[test]
#[ignore = "isolated cwd worker invoked by relative_staging_keeps_symlink_parent_semantics_and_survives_cwd_change"]
fn relative_staging_worker() {
    let original_cwd = std::env::current_dir().unwrap();
    let root = tempfile::tempdir().unwrap();
    for directory in ["a/stage", "b/stage", "actual/nested", "actual/stage"] {
        fs::create_dir_all(root.path().join(directory)).unwrap();
    }
    symlink(
        root.path().join("actual/nested"),
        root.path().join("a/alias"),
    )
    .unwrap();
    let sentinel = root.path().join("b/stage/keep");
    fs::write(&sentinel, "untouched").unwrap();
    let (_source_root, source) = source();
    let captured = capture_files(&source, &BTreeSet::new()).unwrap();
    // Only this dedicated subprocess changes cwd; the parallel test harness is unaffected.
    std::env::set_current_dir(root.path().join("a")).unwrap();
    let staged = captured.stage_exact(Path::new("alias/../stage")).unwrap();
    let boot_staged =
        stage_runtime_boot_scripts(Path::new("alias/../stage"), &[], boot_limits()).unwrap();
    assert!(staged.path().is_absolute());
    assert!(boot_staged.path().is_absolute());
    assert_eq!(
        fs::read_dir(root.path().join("actual/stage"))
            .unwrap()
            .count(),
        2
    );
    assert_eq!(
        fs::read_dir(root.path().join("a/stage")).unwrap().count(),
        0
    );
    std::env::set_current_dir(root.path().join("b")).unwrap();
    assert!(staged.path().join("scripts").is_dir());
    assert!(boot_staged.path().join("scripts").is_dir());
    drop(staged);
    drop(boot_staged);
    assert_eq!(
        fs::read_dir(root.path().join("actual/stage"))
            .unwrap()
            .count(),
        0
    );
    assert_eq!(fs::read_to_string(sentinel).unwrap(), "untouched");
    std::env::set_current_dir(original_cwd).unwrap();
}

#[test]
fn exact_staging_restores_registered_open_handles_after_source_removal() {
    let (root, pinned) = source();
    let content = b"#!/bin/sh\nprintf 'captured bytes'\n";
    let path = root.path().join("scripts/task");
    fs::write(&path, content).unwrap();
    permissions(&path, 42, 43, 0o750);
    permissions(&root.path().join("scripts"), 44, 45, 0o711);
    let source_fs = mounted_runtime(root.path());
    let directory = source_fs.lookup(root_context(), 1, c"scripts").unwrap();
    let entry = source_fs
        .lookup(root_context(), directory.inode, c"task")
        .unwrap();
    let handle = source_fs
        .open(root_context(), entry.inode, false, 0)
        .unwrap()
        .0
        .unwrap();
    let state = source_fs.capture_state().unwrap();
    let observed = capture_files(&pinned, &names(&["task"])).unwrap();
    let parent = tempfile::tempdir().unwrap();
    let staged = observed.stage_exact(parent.path()).unwrap();
    let original_inode = fs::metadata(&path).unwrap().ino();
    let staged_inode = fs::metadata(staged.path().join("scripts/task"))
        .unwrap()
        .ino();
    assert_ne!(original_inode, staged_inode);

    // Keep only the serialized FUSE state and separately staged backing. No live source
    // descriptors or paths may service the restored handle.
    drop(observed);
    drop(source_fs);
    drop(pinned);
    root.close().unwrap();
    let restored = mounted_runtime(staged.path());
    restored.validate_state(&state).unwrap();
    restored.restore_state(&state).unwrap();
    let reopened = restored.handles.read().unwrap()[&handle].clone();
    assert_eq!(reopened.inode, entry.inode);
    let file = reopened.file.read().unwrap();
    assert_eq!(file.metadata().unwrap().ino(), staged_inode);
    let mut tail = vec![0; content.len() - 3];
    // FUSE carries the guest offset per request; reopening must serve those exact offsets.
    assert_eq!(file.read_at(&mut tail, 3).unwrap(), tail.len());
    assert_eq!(tail, content[3..]);
    drop(file);
    let again = restored
        .lookup(root_context(), directory.inode, c"task")
        .unwrap();
    assert_eq!(again.inode, entry.inode);
    assert_eq!(
        (
            again.attr.st_uid,
            again.attr.st_gid,
            again.attr.st_mode & 0o7777
        ),
        (42, 43, 0o750)
    );
    let dir = restored.lookup(root_context(), 1, c"scripts").unwrap();
    assert_eq!(
        (dir.attr.st_uid, dir.attr.st_gid, dir.attr.st_mode & 0o7777),
        (44, 45, 0o711)
    );
}

#[test]
fn registered_script_staging_cannot_restore_unaccounted_runtime_handles() {
    let (root, pinned) = source();
    fs::write(root.path().join("scripts/task"), b"registered").unwrap();
    fs::write(root.path().join("unregistered"), b"other captured backing").unwrap();
    let source_fs = mounted_runtime(root.path());
    let entry = source_fs
        .lookup(root_context(), 1, c"unregistered")
        .unwrap();
    source_fs
        .open(root_context(), entry.inode, false, 0)
        .unwrap();
    let state = source_fs.capture_state().unwrap();
    let observed = capture_files(&pinned, &names(&["task"])).unwrap();
    let parent = tempfile::tempdir().unwrap();
    let staged = observed.stage_exact(parent.path()).unwrap();
    let restored = mounted_runtime(staged.path());
    let before = restored.capture_state().unwrap();
    // Script content alone is not a complete runtime-share closure. Validation must
    // fail before installing any of the saved handle table.
    assert!(restored.validate_state(&state).is_err());
    assert!(restored.restore_state(&state).is_err());
    assert_eq!(restored.capture_state().unwrap(), before);
}

#[test]
fn portable_staging_restores_handles_only_after_source_deletion() {
    let (root, pinned) = source();
    let content = b"#!/bin/sh\nprintf 'captured bytes'\n";
    let path = root.path().join("scripts/task");
    fs::write(&path, content).unwrap();
    permissions(&path, 42, 43, 0o750);
    permissions(&root.path().join("scripts"), 44, 45, 0o711);
    let source_fs = mounted_runtime(root.path());
    let directory = source_fs.lookup(root_context(), 1, c"scripts").unwrap();
    let entry = source_fs
        .lookup(root_context(), directory.inode, c"task")
        .unwrap();
    let handle = source_fs
        .open(root_context(), entry.inode, false, 0)
        .unwrap()
        .0
        .unwrap();
    let state = source_fs.capture_state().unwrap();
    let observed = capture_files(&pinned, &names(&["task"])).unwrap();
    let (runtime_metadata, scripts_metadata) = observed.directory_metadata();
    let values: Vec<_> = observed
        .observations()
        .map(|(name, content, metadata)| (name.to_owned(), content.to_owned(), metadata))
        .collect();
    drop(observed);
    drop(source_fs);
    drop(pinned);
    root.close().unwrap();
    // No source descriptors or paths remain when the replacement backing is created.
    let inputs: Vec<_> = values
        .iter()
        .map(|(name, content, metadata)| RuntimeRestoredScript {
            name,
            content,
            metadata: *metadata,
        })
        .collect();
    let parent = tempfile::tempdir().unwrap();
    let staged = stage_runtime_restored_scripts(
        parent.path(),
        &inputs,
        runtime_metadata,
        scripts_metadata,
        boot_limits(),
    )
    .unwrap();
    let staged_inode = fs::metadata(staged.path().join("scripts/task"))
        .unwrap()
        .ino();
    let restored = mounted_runtime(staged.path());
    restored.validate_state(&state).unwrap();
    restored.restore_state(&state).unwrap();
    let reopened = restored.handles.read().unwrap()[&handle].clone();
    assert_eq!(reopened.inode, entry.inode);
    let file = reopened.file.read().unwrap();
    assert_eq!(file.metadata().unwrap().ino(), staged_inode);
    let mut tail = vec![0; content.len() - 3];
    // FUSE carries the guest offset per request; reopening must serve those exact offsets.
    assert_eq!(file.read_at(&mut tail, 3).unwrap(), tail.len());
    assert_eq!(tail, content[3..]);
    drop(file);
    let again = restored
        .lookup(root_context(), directory.inode, c"task")
        .unwrap();
    assert_eq!(again.inode, entry.inode);
    assert_eq!(
        (
            again.attr.st_uid,
            again.attr.st_gid,
            again.attr.st_mode & 0o7777
        ),
        (42, 43, 0o750)
    );
    let dir = restored.lookup(root_context(), 1, c"scripts").unwrap();
    assert_eq!(
        (dir.attr.st_uid, dir.attr.st_gid, dir.attr.st_mode & 0o7777),
        (44, 45, 0o711)
    );
}

#[test]
fn portable_staging_rejects_metadata_and_late_changes_without_partial_output() {
    let valid = RuntimeScriptMetadata {
        uid: 42,
        gid: 43,
        mode: 0,
    };
    let input = [RuntimeRestoredScript {
        name: "task",
        content: "PRIVATE_SCRIPT",
        metadata: valid,
    }];
    let parent = tempfile::tempdir().unwrap();
    for mode in [0o1000, 0o4755, 0xffff] {
        assert!(
            stage_runtime_restored_scripts(
                parent.path(),
                &input,
                RuntimeScriptMetadata { mode, ..valid },
                valid,
                boot_limits()
            )
            .is_err()
        );
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    }
    for mutation in [
        "bytes",
        "mode",
        "replacement",
        "directory",
        "hardlink",
        "failure",
    ] {
        let result = stage_restored_scripts_with_check(
            parent.path(),
            &input,
            valid,
            valid,
            boot_limits(),
            |root| {
                let file = root.join("scripts/task");
                match mutation {
                    "bytes" => fs::write(file, "CHANGED")?,
                    "mode" => permissions(&file, 42, 43, 0o777),
                    "replacement" => {
                        fs::remove_file(&file)?;
                        fs::write(&file, "PRIVATE_SCRIPT")?;
                        permissions(&file, 42, 43, 0);
                    }
                    "directory" => permissions(&root.join("scripts"), 1, 2, 0),
                    "hardlink" => fs::hard_link(file, root.join("PRIVATE_ALIAS"))?,
                    _ => return Err(std::io::Error::other("injected")),
                }
                Ok(())
            },
        );
        assert!(result.is_err(), "{mutation}");
        assert!(!result.err().unwrap().to_string().contains("PRIVATE_SCRIPT"));
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    }
}
