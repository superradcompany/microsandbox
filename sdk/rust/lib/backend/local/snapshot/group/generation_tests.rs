//! Publication, lock identity and crash qualification for the Unix publisher.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, atomic::AtomicU8, mpsc};
use std::time::Duration;

use microsandbox_image::storage_lease::StorageLease;
use microsandbox_utils::process_lock;

use super::super as group;
use super::super::super::lease;
use super::*;
use group::GROUP_FILENAME;
use group::tests::{add, descriptor, id, stage};

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// A sibling subprocess test can inherit any open descriptor between fork and
/// exec. Keep negative ownership checks immediate, but allow bounded release of
/// such copies after the tested owner closes. A leaked owner still fails here.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn assert_released(mut acquire: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !acquire() {
        assert!(
            std::time::Instant::now() < deadline,
            "ownership was not released"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
#[ignore = "live VM test: requires isolated home, runtime and real a/b/c archives from the qualification workload"]
async fn live_archive_import_restore_and_guest_content() {
    use crate::{Checkpoint as Snapshot, Sandbox, backend::LocalBackend, snapshot::LoadOpts};

    let home = std::path::PathBuf::from(
        std::env::var_os("MSB_TEST_LIVE_HOME").expect("MSB_TEST_LIVE_HOME"),
    );
    let archives = std::path::PathBuf::from(
        std::env::var_os("MSB_TEST_LIVE_ARCHIVES").expect("MSB_TEST_LIVE_ARCHIVES"),
    );
    let backend = LocalBackend::builder().home(&home).build().await.unwrap();
    crate::with_backend(backend, async {
        let options = || LoadOpts { group: Some("qualified".into()), ..Default::default() };
        let started = std::time::Instant::now();
        let base = Snapshot::load_many(&[archives.join("a.msb")], options()).await.unwrap();
        assert_eq!(base.len(), 1);
        let base_head = Snapshot::group_head("qualified").await.unwrap().head;
        eprintln!("LIVE_BASE_IMPORTED seconds={:.3}", started.elapsed().as_secs_f64());

        let invalid = home.join("invalid-final.msb");
        fs::write(&invalid, b"not a snapshot archive").unwrap();
        let error = Snapshot::load_many(&[archives.join("b.msb"), invalid], options()).await.unwrap_err();
        let crate::MicrosandboxError::SnapshotImport(error) = error else { panic!("missing structured import failure: {error}") };
        assert_eq!(error.outcome, crate::SnapshotImportOutcome::NotCommitted);
        assert_eq!(Snapshot::group_head("qualified").await.unwrap().head, base_head);
        assert_eq!(Snapshot::list().await.unwrap().len(), 1);
        eprintln!("LIVE_INVALID_FINAL_REJECTED unchanged_members=1");

        let appended = Snapshot::load_many(&[archives.join("c.msb"), archives.join("b.msb")], options()).await.unwrap();
        assert_eq!(appended.len(), 2);
        assert_eq!(Snapshot::group_head("qualified").await.unwrap().head.as_deref(), Some(appended[0].id()));
        assert_eq!(Snapshot::list().await.unwrap().len(), 3);
        let retry = Snapshot::load_many(&[archives.join("b.msb"), archives.join("c.msb")], options()).await.unwrap();
        assert_eq!(retry.len(), 2);
        assert_eq!(Snapshot::list().await.unwrap().len(), 3);
        assert_eq!(Snapshot::group_head("qualified").await.unwrap().head.as_deref(), Some(appended[0].id()));
        eprintln!("LIVE_IMPORT_AND_RETRY_OK publisher=production members=3 seconds={:.3}", started.elapsed().as_secs_f64());

        for state in ['a', 'b', 'c'] {
            let snapshot = Snapshot::open(format!("qualified:{state}")).await.unwrap();
            snapshot.verify().await.unwrap();
            let name = format!("pr01-restored-{state}");
            let boot = std::time::Instant::now();
            let sandbox = Sandbox::restore(format!("qualified:{state}"))
                .name(&name).cpus(2).memory(512u32).max_duration(120).restore().await.unwrap();
            let script = format!(
                "set -eu; test \"$(cat /work/state)\" = {}; test \"$(find /work/files -type f | wc -l | tr -d ' ')\" = 500; test \"$(cat /work/files/file-499)\" = record-499; sha256sum -c /work/payload.sha256; cat /work/state; if [ {} = a ]; then test ! -e /work/b; test ! -e /work/c; elif [ {} = b ]; then test -e /work/b; test ! -e /work/c; else test -e /work/b; test -e /work/c; fi",
                state.to_ascii_uppercase(), state, state,
            );
            let checked = sandbox.exec("sh", ["-c", &script]).await;
            // Clean up even when guest validation fails. The lifetime bound also covers
            // process interruption before cleanup; no source or user sandbox is targeted.
            let stopped = sandbox.stop().await;
            let removed = Sandbox::remove(&name).await;
            let output = checked.unwrap();
            assert!(output.status().success, "guest validation failed: {}", output.stderr().unwrap());
            stopped.unwrap();
            removed.unwrap();
            eprintln!("LIVE_RESTORE_OK state={state} seconds={:.3} output={:?}", boot.elapsed().as_secs_f64(), output.stdout().unwrap());
        }
        eprintln!("LIVE_END_TO_END_OK publisher=production total_seconds={:.3}", started.elapsed().as_secs_f64());
    }).await;
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
#[ignore = "live VM test: requires isolated home and full.msb containing the qualification background counter"]
async fn live_full_archive_import_resumes_captured_process() {
    use crate::{Checkpoint as Snapshot, Sandbox, backend::LocalBackend, snapshot::LoadOpts};

    let home = std::path::PathBuf::from(std::env::var_os("MSB_TEST_LIVE_HOME").unwrap());
    let archives = std::path::PathBuf::from(std::env::var_os("MSB_TEST_LIVE_ARCHIVES").unwrap());
    let backend = LocalBackend::builder().home(&home).build().await.unwrap();
    crate::with_backend(backend, async {
        let started = std::time::Instant::now();
        let loaded = Snapshot::load_many(
            &[archives.join("full.msb")],
            LoadOpts { group: Some("qualified".into()), ..Default::default() },
        ).await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(Snapshot::list().await.unwrap().len(), 1);
        Snapshot::open("qualified:saved").await.unwrap().verify().await.unwrap();
        let sandbox = Sandbox::restore("qualified:saved").name("pr01-full-restored")
            .cpus(2).memory(512u32).max_duration(120).restore().await.unwrap();
        // A cold disk boot cannot advance this counter: only the shell captured in
        // guest RAM knows about it. Also verify that the recorded PID still exists.
        let script = "set -eu; test \"$(cat /work/marker)\" = full-state; pid=$(cat /work/pid); kill -0 \"$pid\"; before=$(cat /work/counter); sleep 2; after=$(cat /work/counter); test \"$after\" -gt \"$before\"; printf 'pid=%s counter=%s->%s\\n' \"$pid\" \"$before\" \"$after\"; tr '\\0' ' ' < /proc/$pid/cmdline";
        let checked = sandbox.exec("sh", ["-c", script]).await;
        let stopped = sandbox.stop().await;
        let removed = Sandbox::remove("pr01-full-restored").await;
        let output = checked.unwrap();
        assert!(output.status().success, "captured-process validation failed: {}", output.stderr().unwrap());
        stopped.unwrap();
        removed.unwrap();
        eprintln!("LIVE_FULL_RESUME_OK publisher=production seconds={:.3} output={:?}", started.elapsed().as_secs_f64(), output.stdout().unwrap());
    }).await;
}

#[cfg(unix)]
#[tokio::test]
async fn staging_a_large_sparse_payload_preserves_inode_and_allocated_blocks() {
    let root = tempfile::tempdir().unwrap();
    let group = group::ensure(root.path(), Some("history")).await.unwrap();
    add(&group, 1, None).await;
    let input = stage(root.path(), &[descriptor(2, Some(1))]);
    let source = group
        .join(id(1).as_str())
        .join("qualification-sparse-payload");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&source)
        .unwrap();
    file.set_len(64 * 1024 * 1024 * 1024).unwrap();
    file.sync_all().unwrap();
    let prepared = Generation::prepare(
        &group,
        input.path(),
        &BTreeMap::new(),
        Some(id(2).to_string()),
    )
    .unwrap();
    let target = prepared
        .path()
        .join(id(1).as_str())
        .join("qualification-sparse-payload");
    assert!(storage_lease::same_file(&source, &target).unwrap());
    assert_eq!(
        fs::metadata(&source).unwrap().len(),
        fs::metadata(&target).unwrap().len()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            fs::metadata(&source).unwrap().blocks(),
            fs::metadata(&target).unwrap().blocks()
        );
        assert!(fs::metadata(&source).unwrap().nlink() >= 2);
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn new_group_publication_never_replaces_an_existing_destination() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("staged");
    let destination = root.path().join("history");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("payload"), b"new").unwrap();
    fs::create_dir(&destination).unwrap();
    assert!(publish_new(&source, &destination).is_err());
    assert!(source.join("payload").exists());
    assert_eq!(fs::read_dir(&destination).unwrap().count(), 0);
}

#[tokio::test]
async fn staging_shares_payloads_but_isolates_mutable_metadata() {
    let root = tempfile::tempdir().unwrap();
    let group = group::ensure(root.path(), Some("history")).await.unwrap();
    add(&group, 1, None).await;
    let member = group.join(id(1).as_str());
    fs::write(member.join(METADATA_FILENAME), b"original labels").unwrap();
    write_member_name(&member, Some("baseline")).unwrap();
    let input = stage(root.path(), &[descriptor(2, Some(1))]);
    let _ownership = group::lock_group(&group).unwrap();
    let prepared = Generation::prepare(
        &group,
        input.path(),
        &BTreeMap::new(),
        Some(id(2).to_string()),
    )
    .unwrap();
    for (source, number) in [(&group, 1), (&input.path().to_path_buf(), 2)] {
        let original = source.join(id(number).as_str());
        let staged = prepared.path().join(id(number).as_str());
        assert!(
            storage_lease::same_file(
                &original.join(group::DESCRIPTOR_FILENAME),
                &staged.join(group::DESCRIPTOR_FILENAME)
            )
            .unwrap()
        );
        let manifest = descriptor(number, (number == 2).then_some(1));
        let microsandbox_image::snapshot::SnapshotState::File(state) = manifest.state else {
            unreachable!()
        };
        let payload = state.layer_path(&state.layers[0]);
        assert!(
            storage_lease::same_file(&original.join(&payload), &staged.join(&payload)).unwrap()
        );
    }
    for name in [MEMBER_FILENAME, METADATA_FILENAME] {
        let staged = prepared.path().join(id(1).as_str()).join(name);
        assert!(!storage_lease::same_file(&member.join(name), &staged).unwrap());
        let original = fs::read(member.join(name)).unwrap();
        fs::write(staged, b"changed staging").unwrap();
        assert_eq!(fs::read(member.join(name)).unwrap(), original);
    }
    assert!(
        !storage_lease::same_file(
            &group.join(GROUP_FILENAME),
            &prepared.path().join(GROUP_FILENAME)
        )
        .unwrap()
    );
    drop(prepared);
    assert!(member.join(group::DESCRIPTOR_FILENAME).exists());
    assert!(input.path().join(id(2).as_str()).exists());
}

#[cfg(unix)]
#[tokio::test]
async fn staging_rejects_symlinks_and_leaves_the_group_unchanged() {
    let root = tempfile::tempdir().unwrap();
    let group = group::ensure(root.path(), Some("history")).await.unwrap();
    add(&group, 1, None).await;
    let before = fs::read(group.join(GROUP_FILENAME)).unwrap();
    let input = stage(root.path(), &[descriptor(2, Some(1))]);
    std::os::unix::fs::symlink(
        root.path(),
        input.path().join(id(2).as_str()).join("escape"),
    )
    .unwrap();
    assert!(
        Generation::prepare(
            &group,
            input.path(),
            &BTreeMap::new(),
            Some(id(2).to_string())
        )
        .is_err()
    );
    assert_eq!(fs::read(group.join(GROUP_FILENAME)).unwrap(), before);
    assert!(!group.join(id(2).as_str()).exists());
    assert!(!fs::read_dir(root.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".group-generation-")
    }));
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn exchange_preserves_existing_group_lock_and_descriptor_reader() {
    let root = tempfile::tempdir().unwrap();
    let group = group::ensure(root.path(), Some("history")).await.unwrap();
    add(&group, 1, None).await;
    let member = group.join(id(1).as_str());
    let descriptor = member.join(group::DESCRIPTOR_FILENAME);
    let pin = StorageLease::descriptor(&descriptor, false)
        .unwrap()
        .unwrap();
    let ownership = group::lock_group(&group).unwrap();
    let input = stage(root.path(), &[self::descriptor(2, Some(1))]);
    let prepared = Generation::prepare(
        &group,
        input.path(),
        &BTreeMap::new(),
        Some(id(2).to_string()),
    )
    .unwrap();
    exchange(&group, prepared.path()).unwrap();
    let lock = process_lock::open_existing_lock_file(&group.join(".group.lock")).unwrap();
    assert!(!process_lock::try_lock_exclusive(&lock).unwrap());
    assert!(
        StorageLease::descriptor(&descriptor, true)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        group::read_group(&group).unwrap().head,
        Some(id(2).to_string())
    );
    drop(ownership);
    assert_released(|| process_lock::try_lock_exclusive(&lock).unwrap());
    drop(pin);
    assert_released(|| {
        StorageLease::descriptor(&descriptor, true)
            .unwrap()
            .is_some()
    });
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn exchange_preserves_reader_namespace_acquired_after_preparation() {
    let root = tempfile::tempdir().unwrap();
    let group = group::ensure(root.path(), Some("history")).await.unwrap();
    add(&group, 1, None).await;
    let input = stage(root.path(), &[descriptor(2, Some(1))]);
    let _admission = group::WriterLease::acquire(&group).await.unwrap();
    let _ownership = group::lock_group(&group).unwrap();
    let prepared = Generation::prepare(
        &group,
        input.path(),
        &BTreeMap::new(),
        Some(id(2).to_string()),
    )
    .unwrap();
    // Model an unchanged old reader without acquiring the new writer gate. Both a
    // current member and an incoming ID have stable lease identity before commit.
    let readers =
        [1, 2].map(|number| StorageLease::shared(&group.join(id(number).as_str())).unwrap());
    exchange(&group, prepared.path()).unwrap();
    drop(prepared);
    for number in [1, 2] {
        assert!(
            StorageLease::try_exclusive(&group.join(id(number).as_str()))
                .unwrap()
                .is_none()
        );
    }
    drop(readers);
    for number in [1, 2] {
        assert_released(|| {
            StorageLease::try_exclusive(&group.join(id(number).as_str()))
                .unwrap()
                .is_some()
        });
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn updated_publisher_waits_before_creating_namespace_leases() {
    let root = tempfile::tempdir().unwrap();
    let group = group::ensure(root.path(), Some("history")).await.unwrap();
    add(&group, 1, None).await;
    let input = stage(root.path(), &[descriptor(2, Some(1))]);
    let admission = group::WriterLease::acquire(&group).await.unwrap();
    let ownership = group::lock_group(&group).unwrap();
    let prepared = Generation::prepare(
        &group,
        input.path(),
        &BTreeMap::new(),
        Some(id(2).to_string()),
    )
    .unwrap();
    let later = stage(root.path(), &[descriptor(3, Some(2))]);
    let destination = group.clone();
    let mut publisher = tokio::spawn(async move {
        group::publish(&destination, later.path(), &BTreeMap::new(), &id(3), false).await
    });
    // Keep the actual publisher queued across preparation and exchange. This goes
    // through production writer admission rather than manufacturing an old lease.
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut publisher)
            .await
            .is_err()
    );
    assert!(
        lease::deletion(&group.join(id(1).as_str()))
            .unwrap()
            .is_none()
    );
    exchange(&group, prepared.path()).unwrap();
    drop(ownership);
    drop(prepared);
    drop(admission);
    let result = tokio::time::timeout(Duration::from_secs(5), publisher)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(result.head, Some(id(3).to_string()));
    assert_eq!(read_members(&group, true).unwrap().len(), 3);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn exchange_preserves_pending_deletion_recovery() {
    let root = tempfile::tempdir().unwrap();
    let group = group::ensure(root.path(), Some("history")).await.unwrap();
    add(&group, 1, None).await;
    let input = stage(root.path(), &[descriptor(2, Some(1))]);
    let _admission = group::WriterLease::acquire(&group).await.unwrap();
    let _ownership = group::lock_group(&group).unwrap();
    let journal = group.join(".snapshot-deletions/delete-interrupted");
    fs::create_dir_all(journal.join("payload")).unwrap();
    fs::write(journal.join("source.json"), b"\"retired\"").unwrap();
    fs::write(journal.join("payload/data"), b"retained payload").unwrap();
    let lock = process_lock::open_lock_file(&journal.join("active.lock")).unwrap();
    process_lock::lock_exclusive(&lock).unwrap();

    let prepared = Generation::prepare(
        &group,
        input.path(),
        &BTreeMap::new(),
        Some(id(2).to_string()),
    )
    .unwrap();
    exchange(&group, prepared.path()).unwrap();
    drop(prepared);
    assert_eq!(
        fs::read(journal.join("source.json")).unwrap(),
        b"\"retired\""
    );
    assert_eq!(
        fs::read(journal.join("payload/data")).unwrap(),
        b"retained payload"
    );
    let current = process_lock::open_existing_lock_file(&journal.join("active.lock")).unwrap();
    assert!(!process_lock::try_lock_exclusive(&current).unwrap());
    drop(lock);
    assert_released(|| process_lock::try_lock_exclusive(&current).unwrap());
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn sibling_capture_staging_survives_group_exchange() {
    let root = tempfile::tempdir().unwrap();
    let group = group::ensure(root.path(), Some("history")).await.unwrap();
    add(&group, 1, None).await;
    let input = stage(root.path(), &[descriptor(2, Some(1))]);
    let _admission = group::WriterLease::acquire(&group).await.unwrap();
    let _ownership = group::lock_group(&group).unwrap();
    let capture = tempfile::Builder::new()
        .prefix(".capture-")
        .tempdir_in(root.path())
        .unwrap();
    fs::write(capture.path().join("pending"), b"capture started").unwrap();
    let prepared = Generation::prepare(
        &group,
        input.path(),
        &BTreeMap::new(),
        Some(id(2).to_string()),
    )
    .unwrap();
    exchange(&group, prepared.path()).unwrap();
    drop(prepared);
    fs::write(capture.path().join("next-payload"), b"capture continues").unwrap();
    assert_eq!(
        fs::read(capture.path().join("pending")).unwrap(),
        b"capture started"
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
#[ignore = "diagnostic of unsupported concurrent older writers bypassing admission; maintenance must drain them"]
async fn exchange_preserves_lease_created_after_staging() {
    let root = tempfile::tempdir().unwrap();
    let group = group::ensure(root.path(), Some("history")).await.unwrap();
    add(&group, 1, None).await;
    let input = stage(root.path(), &[descriptor(2, Some(1))]);
    let _ownership = group::lock_group(&group).unwrap();
    let prepared = Generation::prepare(
        &group,
        input.path(),
        &BTreeMap::new(),
        Some(id(2).to_string()),
    )
    .unwrap();
    // An older publisher pins its incoming ID BEFORE waiting for the group lock. The
    // group lock therefore cannot prevent this new lease from appearing after staging.
    let late_pin = StorageLease::shared(&group.join(id(3).as_str())).unwrap();
    exchange(&group, prepared.path()).unwrap();
    let deletion = StorageLease::try_exclusive(&group.join(id(3).as_str())).unwrap();
    assert!(
        deletion.is_none(),
        "directory exchange admitted deletion while an older publisher still held the same member's namespace lease"
    );
    drop((late_pin, deletion));
    // This reproduces why the approved maintenance interval excludes older writers.
    // Updated writers use stable external admission before creating namespace leases.
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
#[ignore = "diagnostic of unsupported older captures inside the group; maintenance must drain them"]
async fn exchange_preserves_inflight_capture_path() {
    let root = tempfile::tempdir().unwrap();
    let group = group::ensure(root.path(), Some("history")).await.unwrap();
    add(&group, 1, None).await;
    let input = stage(root.path(), &[descriptor(2, Some(1))]);
    let _ownership = group::lock_group(&group).unwrap();
    let prepared = Generation::prepare(
        &group,
        input.path(),
        &BTreeMap::new(),
        Some(id(2).to_string()),
    )
    .unwrap();
    // Older capture implementations staged inside the group without external writer
    // admission. Updated capture uses sibling staging and the stable admission gate.
    let capture = tempfile::Builder::new()
        .prefix(".capture-")
        .tempdir_in(&group)
        .unwrap();
    fs::write(capture.path().join("pending"), b"capture started").unwrap();
    exchange(&group, prepared.path()).unwrap();
    let resumed = fs::write(capture.path().join("next-payload"), b"capture continues");
    assert!(
        resumed.is_ok(),
        "directory exchange stranded the ongoing capture: {resumed:?}"
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn killed_generation_publisher_leaves_old_or_complete_directory() {
    crash_cases(None).await;
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
#[ignore = "requires MSB_TEST_LEGACY_CLI pointing to an actual pre-change executable"]
async fn legacy_cli_observes_complete_generation_after_publisher_crash() {
    let executable = std::env::var_os("MSB_TEST_LEGACY_CLI").expect("MSB_TEST_LEGACY_CLI");
    crash_cases(Some(Path::new(&executable))).await;
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
async fn crash_cases(legacy_cli: Option<&Path>) {
    for fresh in [false, true] {
        for committed in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let source = group::ensure(root.path(), Some(if fresh { "seed" } else { "history" }))
                .await
                .unwrap();
            if !fresh {
                add(&source, 1, None).await;
            }
            let destination = root.path().join("history");
            let input = stage(
                root.path(),
                &[descriptor(2, (!fresh).then_some(1)), descriptor(3, Some(2))],
            );
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "backend::local::snapshot::group::generation::tests::generation_crash_worker",
                    "--ignored",
                    "--nocapture",
                ])
                .env("MSB_GENERATION_SOURCE", &source)
                .env("MSB_GENERATION_INPUT", input.path())
                .env("MSB_GENERATION_DESTINATION", &destination)
                .env(
                    "MSB_GENERATION_COMMITTED",
                    if committed { "1" } else { "0" },
                )
                .env("MSB_GENERATION_FRESH", if fresh { "1" } else { "0" })
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let output = child.stdout.take().unwrap();
            let (sender, receiver) = mpsc::channel();
            let reader = std::thread::spawn(move || {
                for line in BufReader::new(output).lines() {
                    if line.unwrap().contains("GENERATION_BOUNDARY_READY") {
                        let _ = sender.send(());
                        break;
                    }
                }
            });
            let reached = receiver.recv_timeout(Duration::from_secs(20));
            let _ = child.kill();
            child.wait().unwrap();
            reader.join().unwrap();
            reached.expect("generation publisher did not reach the requested boundary");
            if fresh && !committed {
                assert!(!destination.exists());
            } else {
                let members = read_members(&destination, true).unwrap();
                assert_eq!(
                    members.len(),
                    if committed {
                        if fresh { 2 } else { 3 }
                    } else {
                        1
                    }
                );
                assert_eq!(
                    group::read_group(&destination).unwrap().head,
                    Some(id(if committed { 3 } else { 1 }).to_string())
                );
            }
            if let Some(executable) = legacy_cli {
                for number in [2, 3] {
                    let output = Command::new(executable)
                        .env("MSB_HOME", root.path().join("isolated-legacy-home"))
                        .args(["snapshot", "inspect"])
                        .arg(destination.join(id(number).as_str()))
                        .output()
                        .unwrap();
                    assert_eq!(
                        output.status.success(),
                        committed,
                        "fresh={fresh}, committed={committed}, member={number}: {} {}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                if !fresh {
                    let output = Command::new(executable)
                        .env("MSB_HOME", root.path().join("isolated-legacy-home"))
                        .args(["snapshot", "inspect"])
                        .arg(destination.join(id(1).as_str()))
                        .output()
                        .unwrap();
                    assert!(
                        output.status.success(),
                        "old member must remain readable: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
#[ignore = "subprocess worker exercised by generation crash tests"]
fn generation_crash_worker() {
    let source = std::path::PathBuf::from(std::env::var_os("MSB_GENERATION_SOURCE").unwrap());
    let input = std::path::PathBuf::from(std::env::var_os("MSB_GENERATION_INPUT").unwrap());
    let destination =
        std::path::PathBuf::from(std::env::var_os("MSB_GENERATION_DESTINATION").unwrap());
    let _ownership = group::lock_group(&source).unwrap();
    let prepared =
        Generation::prepare(&source, &input, &BTreeMap::new(), Some(id(3).to_string())).unwrap();
    if std::env::var("MSB_GENERATION_COMMITTED").unwrap() == "1" {
        if std::env::var("MSB_GENERATION_FRESH").unwrap() == "1" {
            publish_new(prepared.path(), &destination).unwrap();
        } else {
            exchange(&source, prepared.path()).unwrap();
        }
    }
    println!("GENERATION_BOUNDARY_READY");
    std::io::stdout().flush().unwrap();
    loop {
        std::thread::park();
    }
}

#[test]
fn capability_probe_refuses_missing_operations_without_touching_group() {
    let root = tempfile::tempdir().unwrap();
    let group = root.path().join("existing");
    fs::create_dir(&group).unwrap();
    fs::write(group.join("untouched"), b"original").unwrap();
    for fail_links in [true, false] {
        let error = check_with(
            root.path(),
            |from, to| {
                if fail_links {
                    Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
                } else {
                    fs::hard_link(from, to)
                }
            },
            |_, _| Err(io::Error::from_raw_os_error(libc::ENOSYS)),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("atomic snapshot import is unavailable")
        );
        assert!(
            error
                .to_string()
                .contains("no group members or head were changed")
        );
        assert_eq!(fs::read(group.join("untouched")).unwrap(), b"original");
        assert_eq!(
            fs::read_dir(root.path()).unwrap().count(),
            1,
            "probe leaked files"
        );
    }
    check(&root.path().join("missing/child")).unwrap();
    assert!(!root.path().join("missing").exists());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
}

#[tokio::test]
async fn failed_durability_flush_keeps_complete_view_and_previous_generation() {
    use std::sync::{Arc, atomic::AtomicU8};

    let root = tempfile::tempdir().unwrap();
    let group = group::ensure(root.path(), Some("history")).await.unwrap();
    add(&group, 1, None).await;
    let input = stage(
        root.path(),
        &[descriptor(2, Some(1)), descriptor(3, Some(2))],
    );
    let outcome = Arc::new(AtomicU8::new(SnapshotImportOutcome::NotCommitted as u8));
    let operation = group::IndexedPublication {
        operation: "00000000000000000000000000000042".into(),
        outcome: outcome.clone(),
    };
    let owner = group::lock_group(&group).unwrap();
    let incoming = read_members(input.path(), false).unwrap();
    let error = publish_with_flush(
        &group,
        input.path(),
        &incoming,
        &BTreeMap::new(),
        Some(id(3).to_string()),
        &operation,
        |_| Err(io::Error::from_raw_os_error(libc::EIO)),
    )
    .unwrap_err();
    assert!(error.to_string().contains("durability is unconfirmed"));
    assert_eq!(
        outcome.load(Ordering::Acquire),
        SnapshotImportOutcome::Unknown as u8
    );
    assert_eq!(read_members(&group, true).unwrap().len(), 3);
    assert_eq!(
        group::read_group(&group).unwrap().head,
        Some(id(3).to_string())
    );
    let retired = fs::read_dir(root.path())
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.unwrap();
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".group-generation-")
                .then(|| entry.path())
        })
        .collect::<Vec<_>>();
    assert_eq!(retired.len(), 1);
    assert_eq!(read_members(&retired[0], true).unwrap().len(), 1);
    assert_eq!(
        group::read_group(&retired[0]).unwrap().head,
        Some(id(1).to_string())
    );
    drop(owner);
    let pending = group::pending_index(&group).await.unwrap().unwrap();
    assert_eq!(pending.snapshots.len(), 2);
    pending.finish().await.unwrap();
    assert!(!group.join(".group-transaction").exists());
}

#[tokio::test]
async fn production_publisher_crash_never_exposes_a_batch_prefix() {
    production_crash_cases(None).await;
}

#[tokio::test]
#[ignore = "requires MSB_TEST_LEGACY_CLI pointing to a released executable"]
async fn released_reader_sees_atomic_production_publication_after_crash() {
    let executable = std::env::var_os("MSB_TEST_LEGACY_CLI").expect("MSB_TEST_LEGACY_CLI");
    production_crash_cases(Some(Path::new(&executable))).await;
}

async fn production_crash_cases(legacy_cli: Option<&Path>) {
    for fresh in [true, false] {
        for boundary in ["linking", "prepared", "exchanged", "committed"] {
            let root = tempfile::tempdir().unwrap();
            let destination = if fresh {
                group::ensure_import(root.path(), Some("history"))
                    .await
                    .unwrap()
                    .directory
            } else {
                let group = group::ensure(root.path(), Some("history")).await.unwrap();
                add(&group, 1, None).await;
                group
            };
            let input = stage(
                root.path(),
                &[descriptor(2, (!fresh).then_some(1)), descriptor(3, Some(2))],
            );
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "backend::local::snapshot::group::generation::tests::production_crash_worker",
                    "--ignored",
                    "--nocapture",
                ])
                .env("MSB_TEST_ATOMIC_GROUP", &destination)
                .env("MSB_TEST_ATOMIC_BOUNDARY", boundary)
                .env("MSB_TEST_ATOMIC_INPUT", input.path())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let output = child.stdout.take().unwrap();
            let (sender, receiver) = mpsc::channel();
            let reader = std::thread::spawn(move || {
                for line in BufReader::new(output).lines() {
                    if line.unwrap().contains("ATOMIC_IMPORT_BOUNDARY_READY") {
                        let _ = sender.send(());
                        break;
                    }
                }
            });
            let reached = receiver.recv_timeout(Duration::from_secs(20));
            let _ = child.kill();
            child.wait().unwrap();
            reader.join().unwrap();
            reached.expect("production publisher did not reach crash boundary");
            let published = matches!(boundary, "exchanged" | "committed");
            let expected = usize::from(!fresh) + if published { 2 } else { 0 };
            assert_eq!(read_members(&destination, true).unwrap().len(), expected);
            if let Some(executable) = legacy_cli {
                for number in [2, 3] {
                    let output = Command::new(executable)
                        .env("MSB_HOME", root.path().join("legacy-home"))
                        .args(["snapshot", "inspect"])
                        .arg(destination.join(id(number).as_str()))
                        .output()
                        .unwrap();
                    assert_eq!(
                        output.status.success(),
                        published,
                        "fresh={fresh}, boundary={boundary}, member={number}: {} {}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
            if published {
                let pending = group::pending_index(&destination).await.unwrap().unwrap();
                assert_eq!(pending.snapshots.len(), 2);
                pending.finish().await.unwrap();
            }
            {
                let _admission = group::WriterLease::acquire(&destination).await.unwrap();
                recover_retired(&destination).unwrap();
                recover_retired(&destination).unwrap();
                assert!(
                    fs::read_dir(root.path()).unwrap().all(|entry| {
                        !entry
                            .unwrap()
                            .file_name()
                            .to_string_lossy()
                            .starts_with(".group-generation-")
                    }),
                    "fresh={fresh}, boundary={boundary}: recovery left an abandoned generation"
                );
            }
            // Retry the same batch after recovery; existing members are never duplicated.
            let operation = group::IndexedPublication {
                operation: "00000000000000000000000000000043".into(),
                outcome: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(
                    SnapshotImportOutcome::NotCommitted as u8,
                )),
            };
            group::publish_batch_indexed(
                &destination,
                input.path(),
                &BTreeMap::new(),
                &[id(3)],
                false,
                operation,
            )
            .await
            .unwrap();
            group::pending_index(&destination)
                .await
                .unwrap()
                .unwrap()
                .finish()
                .await
                .unwrap();
            assert_eq!(
                read_members(&destination, true).unwrap().len(),
                if fresh { 2 } else { 3 }
            );
        }
    }
}

#[tokio::test]
#[ignore = "subprocess worker for production publication crash tests"]
async fn production_crash_worker() {
    let group = std::path::PathBuf::from(std::env::var_os("MSB_TEST_ATOMIC_GROUP").unwrap());
    let input = std::path::PathBuf::from(std::env::var_os("MSB_TEST_ATOMIC_INPUT").unwrap());
    let operation = group::IndexedPublication {
        operation: "00000000000000000000000000000044".into(),
        outcome: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(
            SnapshotImportOutcome::NotCommitted as u8,
        )),
    };
    group::publish_batch_indexed(&group, &input, &BTreeMap::new(), &[id(3)], false, operation)
        .await
        .unwrap();
    panic!("publisher missed requested crash boundary");
}

#[tokio::test]
async fn confirmed_publication_returns_cleanup_warning_without_losing_members() {
    let root = tempfile::tempdir().unwrap();
    let group = group::ensure(root.path(), Some("history")).await.unwrap();
    add(&group, 1, None).await;
    let input = stage(root.path(), &[descriptor(2, Some(1))]);
    let outcome = Arc::new(AtomicU8::new(SnapshotImportOutcome::NotCommitted as u8));
    let operation = group::IndexedPublication {
        operation: "00000000000000000000000000000043".into(),
        outcome: outcome.clone(),
    };
    let _owner = group::lock_group(&group).unwrap();
    let incoming = read_members(input.path(), false).unwrap();
    let warnings = publish_with_flush(
        &group,
        input.path(),
        &incoming,
        &BTreeMap::new(),
        Some(id(2).to_string()),
        &operation,
        |parent| {
            sync_directory(parent)?;
            // Force only retired-generation cleanup to fail, after publication and
            // durability have succeeded. All paths belong to this disposable fixture.
            let retired = fs::read_dir(parent)?
                .map(|entry| entry.unwrap())
                .find(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".group-generation-")
                })
                .unwrap()
                .path();
            fs::remove_dir_all(&retired)?;
            fs::write(retired, b"cleanup fault")?;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        outcome.load(Ordering::Acquire),
        SnapshotImportOutcome::Committed as u8
    );
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("cleanup remains"));
    assert_eq!(read_members(&group, true).unwrap().len(), 2);
    assert_eq!(
        group::read_group(&group).unwrap().head,
        Some(id(2).to_string())
    );
}

#[tokio::test]
async fn removal_flush_failure_retains_complete_view_and_old_generation() {
    let root = tempfile::tempdir().unwrap();
    let directory = group::ensure(root.path(), Some("history")).await.unwrap();
    add(&directory, 1, None).await;
    add(&directory, 2, Some(1)).await;
    let path = directory.join(id(2).as_str());
    let _pin = lease::deletion(&path).unwrap().unwrap();
    let _lock = group::lock_group(&directory).unwrap();
    let error = remove_with_flush(&directory, id(2).as_str(), Some(id(1).to_string()), |_| {
        Err(io::Error::other("injected durability failure"))
    })
    .unwrap_err();
    assert!(
        error.to_string().contains("durability is unconfirmed"),
        "{error}"
    );
    assert_eq!(
        group::read_group(&directory).unwrap().head.as_deref(),
        Some(id(1).as_str())
    );
    assert!(!path.exists());
    let retired = fs::read_dir(root.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".group-generation-")
        })
        .unwrap();
    assert_eq!(
        group::read_group(&retired).unwrap().head.as_deref(),
        Some(id(2).as_str())
    );
    assert!(
        retired
            .join(id(2).as_str())
            .join(group::DESCRIPTOR_FILENAME)
            .exists()
    );
    assert!(directory.join(".snapshot-deletions").exists());
    // Older recovery may consume the catalog receipt; generation reclamation
    // remains independently recoverable, including after a durability failure.
    fs::remove_dir_all(directory.join(".snapshot-deletions")).unwrap();
    recover_retired(&directory).unwrap();
    recover_retired(&directory).unwrap();
    assert!(!retired.exists());
    assert!(directory.join(id(1).as_str()).is_dir());
}
