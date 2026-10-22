//! Recoverable filesystem publication under the existing group ownership lock.
//!
//! The journal is local coordination metadata, never part of a portable descriptor or archive.
//! A durable commit marker selects the complete new state; without it recovery restores the old
//! namespace. Catalog publication is coordinated by the caller and must not infer success from
//! the presence of an individual member directory.

use super::*;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const DIRECTORY: &str = ".group-transaction";
const SCHEMA: &str = "microsandbox.group-transaction/1";
const MAX_JOURNAL_BYTES: usize = 16 * 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema: String,
    operation: String,
    /// Indexed batch publication keeps this journal until the ready rows commit together.
    #[serde(default)]
    index_pending: bool,
    #[serde(default)]
    new_group: bool,
    #[serde(default)]
    incoming: BTreeMap<String, String>,
    previous_head: Option<String>,
    next_head: Option<String>,
    /// Only previously absent members belong to this transaction's rollback set.
    added: BTreeMap<String, String>,
    /// Changes to a reused member's local alias must also roll back on failed publication.
    aliases: BTreeMap<String, AliasChange>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AliasChange {
    digest: String,
    previous: Option<String>,
    next: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Prepare catalog recovery metadata inside an unpublished complete generation. The
/// publisher selects this committed view only by exchanging the containing directory.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) fn stage_generation_index(
    directory: &Path,
    incoming: &BTreeMap<String, Member>,
    operation: &IndexedPublication,
) -> MicrosandboxResult<()> {
    let members = read_members(directory, true)?;
    let head = read_group(directory)?.head;
    let aliases = BTreeMap::new();
    let mut intent = prepare(directory, incoming, &members, &aliases, head.clone(), head)?;
    // Every incoming member already exists in this private complete view. Its journal
    // must never describe a partially installed batch or move the source staging files.
    if !intent.added.is_empty() {
        return Err(integrity("generation is missing an incoming member".into()));
    }
    intent.operation = operation.operation.clone();
    intent.index_pending = true;
    validate(&intent)?;
    write_json(&directory.join(DIRECTORY), "intent.json", &intent)?;
    install(directory, incoming, &members, &aliases, &intent, |_| Ok(()))
}

/// Publish a preflighted batch. The caller retains group ownership throughout this call.
/// Errors before the commit marker leave a recoverable, unpublished intent, never a claim that
/// some prefix was successfully imported. Existing members are never in the rollback set.
pub(super) fn publish(
    directory: &Path,
    incoming: &BTreeMap<String, Member>,
    members: &BTreeMap<String, Member>,
    aliases: &BTreeMap<String, String>,
    previous_head: Option<String>,
    next_head: Option<String>,
    operation: Option<&IndexedPublication>,
) -> MicrosandboxResult<()> {
    #[cfg(windows)]
    if operation.is_some() {
        // Recheck the final destination under writer ownership in case the filesystem
        // changed after archive preflight. No group journal or payload is changed yet.
        super::txf::check(directory)?;
    }
    let mut intent = prepare(
        directory,
        incoming,
        members,
        aliases,
        previous_head,
        next_head,
    )?;
    if let Some(operation) = operation {
        intent.index_pending = true;
        intent.operation = operation.operation.clone();
        validate(&intent)?;
        write_json(&directory.join(DIRECTORY), "intent.json", &intent)?;
    }
    // Preflight and durable intent creation have not installed any member. From this
    // point a failed write (including the commit-marker flush) can leave an uncertain
    // outcome, so the caller must recover the journal rather than infer a rollback.
    if let Some(operation) = operation {
        operation
            .outcome
            .store(SnapshotImportOutcome::Unknown as u8, Ordering::Release);
    }
    #[cfg(windows)]
    let result = if operation.is_some() {
        install_windows(directory, incoming, members, &intent, |_| Ok(()))
    } else {
        install(directory, incoming, members, aliases, &intent, |_| Ok(()))
    };
    #[cfg(not(windows))]
    let result = install(directory, incoming, members, aliases, &intent, |_| Ok(()));
    if let Err(error) = result {
        return Err(MicrosandboxError::SnapshotIntegrity(format!(
            "snapshot batch {} was not confirmed committed: {error}; recovery journal retained at {}; retry through the same group before inspecting the outcome",
            intent.operation,
            directory.join(DIRECTORY).display()
        )));
    }
    if let Some(operation) = operation {
        operation
            .outcome
            .store(SnapshotImportOutcome::Committed as u8, Ordering::Release);
    }
    // Publication has committed. Retiring coordination files cannot turn success into an
    // apparent failed import that callers might blindly retry with a different identity.
    if operation.is_none()
        && let Err(error) = finish_creation(directory).and_then(|()| retire(directory))
    {
        tracing::warn!(operation = %intent.operation, %error, "snapshot batch committed; journal cleanup will retry on the next group access");
    }
    Ok(())
}

/// Recover with exclusive group ownership, before admitting new group operations.
pub(super) fn recover(directory: &Path) -> MicrosandboxResult<()> {
    let journal = directory.join(DIRECTORY);
    if !path_exists(&journal)? {
        return Ok(());
    }
    require_directory(&journal)?;
    let intent: Intent = serde_json::from_slice(&read_regular(
        &journal.join("intent.json"),
        MAX_JOURNAL_BYTES,
    )?)?;
    validate(&intent)?;
    let committed = journal.join("committed");
    if path_exists(&committed)? {
        let operation = read_regular(&committed, 64)?;
        if operation != intent.operation.as_bytes() {
            return Err(integrity(
                "snapshot batch commit marker does not match its intent".into(),
            ));
        }
        // A generation's marker is prepared before its directory exchange. Recovery
        // must confirm the containing name is durable before exposing work to SQLite;
        // the original publisher may have failed its post-exchange parent flush.
        if intent.index_pending {
            sync_directory(
                directory
                    .parent()
                    .ok_or_else(|| integrity("group has no parent".into()))?,
            )?;
        }
        // Do not roll the complete filesystem view back because catalog completion or
        // later cleanup was interrupted.
        if intent.index_pending && !index_acknowledged(&journal, &intent)? {
            return Ok(());
        }
        finish_creation(directory)?;
        return retire(directory);
    }
    rollback(directory, &intent)?;
    retire(directory)
}

/// Read the complete committed index work while the caller owns the group lock. This
/// works even while the original publisher retains namespace pins: no payload is deleted.
pub(super) fn pending_index(
    directory: &Path,
) -> MicrosandboxResult<Option<Vec<(PathBuf, String, Manifest)>>> {
    let journal = directory.join(DIRECTORY);
    if !path_exists(&journal)? || !path_exists(&journal.join("committed"))? {
        return Ok(None);
    }
    let intent: Intent = serde_json::from_slice(&read_regular(
        &journal.join("intent.json"),
        MAX_JOURNAL_BYTES,
    )?)?;
    validate(&intent)?;
    if !intent.index_pending || index_acknowledged(&journal, &intent)? {
        return Ok(None);
    }
    let mut snapshots = Vec::with_capacity(intent.incoming.len());
    for (id, digest) in intent.incoming {
        let path = directory.join(&id);
        require_directory(&path)?;
        let manifest = Manifest::from_bytes(&read_regular(
            &path.join(DESCRIPTOR_FILENAME),
            MAX_DESCRIPTOR_BYTES,
        )?)
        .map_err(|error| integrity(error.to_string()))?;
        if manifest.snapshot_id.as_str() != id
            || manifest
                .digest()
                .map_err(|error| integrity(error.to_string()))?
                != digest
        {
            return Err(integrity(format!(
                "committed snapshot {id} changed before index completion"
            )));
        }
        snapshots.push((path, digest, manifest));
    }
    Ok(Some(snapshots))
}

/// Persist the index acknowledgement before retiring the journal. If recursive cleanup
/// fails, subsequent accesses can retry it without repeating or undoing the committed batch.
pub(super) fn finish_index(directory: &Path) -> MicrosandboxResult<Vec<String>> {
    let journal = directory.join(DIRECTORY);
    let intent: Intent = serde_json::from_slice(&read_regular(
        &journal.join("intent.json"),
        MAX_JOURNAL_BYTES,
    )?)?;
    write_json(&journal, "indexed", &intent.operation)?;
    finish_creation(directory)?;
    if let Err(error) = retire(directory) {
        let warning = format!(
            "snapshot batch committed and indexed; journal cleanup will retry at {}: {error}",
            directory.display()
        );
        tracing::warn!(%warning);
        return Ok(vec![warning]);
    }
    Ok(Vec::new())
}

fn index_acknowledged(journal: &Path, intent: &Intent) -> MicrosandboxResult<bool> {
    let marker = journal.join("indexed");
    if !path_exists(&marker)? {
        return Ok(false);
    }
    let operation: String = serde_json::from_slice(&read_regular(&marker, 64)?)?;
    if operation != intent.operation {
        return Err(integrity(
            "snapshot index acknowledgement does not match its batch".into(),
        ));
    }
    Ok(true)
}

fn prepare(
    directory: &Path,
    incoming: &BTreeMap<String, Member>,
    members: &BTreeMap<String, Member>,
    aliases: &BTreeMap<String, String>,
    previous_head: Option<String>,
    next_head: Option<String>,
) -> MicrosandboxResult<Intent> {
    let mut added = BTreeMap::new();
    for (id, member) in incoming {
        if !path_exists(&directory.join(id))? {
            added.insert(id.clone(), member.digest.clone());
        }
    }
    let mut changes = BTreeMap::new();
    for id in aliases.keys().filter(|id| !added.contains_key(*id)) {
        let previous = member_name(&directory.join(id))?;
        let next = members[id].name.clone();
        if previous != next {
            changes.insert(
                id.clone(),
                AliasChange {
                    digest: members[id].digest.clone(),
                    previous,
                    next,
                },
            );
        }
    }
    let intent = Intent {
        schema: SCHEMA.into(),
        operation: format!("{:032x}", rand::random::<u128>()),
        index_pending: false,
        new_group: !path_exists(&directory.join(GROUP_FILENAME))? && is_creating(directory)?,
        incoming: incoming
            .iter()
            .map(|(id, member)| (id.clone(), member.digest.clone()))
            .collect(),
        previous_head,
        next_head,
        added,
        aliases: changes,
    };
    validate(&intent)?;
    let bytes = serde_json::to_vec(&intent)?;
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(integrity(
            "snapshot batch journal exceeds its size limit".into(),
        ));
    }
    let stage = tempfile::Builder::new()
        .prefix(".group-intent-")
        .tempdir_in(directory)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(stage.path().join("intent.json"))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    fs::create_dir(stage.path().join("retired"))?;
    sync_directory(stage.path())?;
    // An old journal is never overwritten, including an unexpectedly empty directory.
    if path_exists(&directory.join(DIRECTORY))? {
        return Err(integrity(
            "snapshot group has an unfinished transaction".into(),
        ));
    }
    fs::rename(stage.path(), directory.join(DIRECTORY))?;
    sync_directory(directory)?;
    Ok(intent)
}

fn install(
    directory: &Path,
    incoming: &BTreeMap<String, Member>,
    members: &BTreeMap<String, Member>,
    aliases: &BTreeMap<String, String>,
    intent: &Intent,
    mut after_move: impl FnMut(usize) -> MicrosandboxResult<()>,
) -> MicrosandboxResult<()> {
    let mut moved = 0;
    for (id, member) in incoming {
        if intent.added.contains_key(id) {
            write_member_name(&member.path, members[id].name.as_deref())?;
            sync_directory(&member.path)?;
            fs::rename(&member.path, directory.join(id))?;
            // The destination and the source of a cross-directory rename must both be durable.
            sync_directory(
                member
                    .path
                    .parent()
                    .ok_or_else(|| integrity("snapshot staging has no parent".into()))?,
            )?;
            moved += 1;
            after_move(moved)?;
        }
    }
    for id in aliases.keys() {
        write_member_name(&directory.join(id), members[id].name.as_deref())?;
    }
    sync_directory(directory)?;
    if intent.new_group || intent.previous_head != intent.next_head {
        write_group(directory, intent.next_head.clone())?;
    }
    after_move(usize::MAX)?;
    let journal = directory.join(DIRECTORY);
    let mut marker = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(journal.join("committed.part"))?;
    marker.write_all(intent.operation.as_bytes())?;
    marker.sync_all()?;
    drop(marker);
    fs::rename(journal.join("committed.part"), journal.join("committed"))?;
    sync_directory(&journal)?;
    Ok(())
}

/// TxF keeps the namespace/lock directory stable while atomically publishing membership,
/// aliases, head and the commit marker. A killed publisher therefore needs no new reader
/// code to hide a partial prefix. SQLite completion remains recoverable from the journal.
#[cfg(windows)]
fn install_windows(
    directory: &Path,
    incoming: &BTreeMap<String, Member>,
    members: &BTreeMap<String, Member>,
    intent: &Intent,
    mut after_move: impl FnMut(usize) -> MicrosandboxResult<()>,
) -> MicrosandboxResult<()> {
    let stage = tempfile::Builder::new()
        .prefix(".group-commit-")
        .tempdir_in(directory.join(DIRECTORY))?;
    write_group(stage.path(), intent.next_head.clone())?;
    let marker = stage.path().join("committed");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&marker)?;
    file.write_all(intent.operation.as_bytes())?;
    file.sync_all()?;
    drop(file);
    // Prepare all metadata before enlisting paths: ordinary writes to a transacted path
    // can conflict with its transaction, even within this process.
    for id in intent.added.keys() {
        write_member_name(&incoming[id].path, members[id].name.as_deref())?;
    }
    for (id, change) in &intent.aliases {
        let alias_stage = stage.path().join(id);
        fs::create_dir(&alias_stage)?;
        write_member_name(&alias_stage, change.next.as_deref())?;
    }
    let mut transaction = super::txf::Transaction::new()?;
    for (index, id) in intent.added.keys().enumerate() {
        transaction.rename(&incoming[id].path, &directory.join(id), false)?;
        after_move(index + 1)?;
    }
    for (id, change) in &intent.aliases {
        let destination = directory.join(id).join(MEMBER_FILENAME);
        if change.next.is_some() {
            transaction.rename(
                &stage.path().join(id).join(MEMBER_FILENAME),
                &destination,
                true,
            )?;
        } else if path_exists(&destination)? {
            transaction.remove_file(&destination)?;
        }
    }
    if intent.new_group || intent.previous_head != intent.next_head {
        transaction.rename(
            &stage.path().join(GROUP_FILENAME),
            &directory.join(GROUP_FILENAME),
            true,
        )?;
    }
    transaction.rename(&marker, &directory.join(DIRECTORY).join("committed"), false)?;
    after_move(usize::MAX)?;
    #[cfg(test)]
    pause_import_for_test("before");
    transaction.commit()?;
    #[cfg(test)]
    pause_import_for_test("after");
    Ok(())
}

/// Subprocess-only live qualification hook; no environment-controlled pause is compiled
/// into the CLI or SDK shipped to users.
#[cfg(all(test, windows))]
fn pause_import_for_test(boundary: &str) {
    if std::env::var("MSB_TEST_TXF_IMPORT_BOUNDARY").as_deref() == Ok(boundary) {
        eprintln!("TXF_IMPORT_BOUNDARY_READY {boundary}");
        loop {
            std::thread::park();
        }
    }
}

fn rollback(directory: &Path, intent: &Intent) -> MicrosandboxResult<()> {
    let state = publication_state(directory)?;
    if state.head != intent.previous_head && state.head != intent.next_head {
        return Err(integrity(
            "snapshot head changed outside the pending batch; journal retained for recovery".into(),
        ));
    }
    // Preflight every identity and acquire all deletion pins before changing anything. A
    // historical reader may still hold one of these descriptors; never delete its live payload.
    // Acquire the lifetime gate once for the batch; its clones retain the same
    // lock, avoiding self-conflict while pinning several rollback members.
    let group_lease = super::super::lease::group_deletion(directory)?.ok_or_else(|| {
        integrity(
            "snapshot batch recovery is waiting for group verification; retry after it finishes"
                .into(),
        )
    })?;
    let mut leases = Vec::new();
    for (id, digest) in &intent.added {
        let path = directory.join(id);
        if path_exists(&path)? {
            let lease = super::super::lease::deletion_under_group_lock(&path, &group_lease)?.ok_or_else(|| integrity(format!(
                "snapshot batch recovery is waiting for an active reader of {id}; retry after it finishes"
            )))?;
            if read_member(&path, true)?.1.digest != *digest {
                return Err(integrity(format!(
                    "snapshot {id} changed outside the pending batch; refusing rollback"
                )));
            }
            leases.push(lease);
        }
    }
    for (id, change) in &intent.aliases {
        let (_, member) = read_member(&directory.join(id), true)?;
        if member.digest != change.digest
            || (member.name != change.previous && member.name != change.next)
        {
            return Err(integrity(format!(
                "snapshot {id} metadata changed outside the pending batch; refusing rollback"
            )));
        }
    }
    if intent.new_group {
        // No empty group existed before this operation. Retain only its invisible creation
        // reservation, so retry can reuse the name and indexed roots can be retired safely.
        if path_exists(&directory.join(GROUP_FILENAME))? {
            fs::remove_file(directory.join(GROUP_FILENAME))?;
            sync_directory(directory)?;
        }
    } else {
        write_group(directory, intent.previous_head.clone())?;
    }
    for (id, change) in &intent.aliases {
        write_member_name(&directory.join(id), change.previous.as_deref())?;
    }
    let retired = directory.join(DIRECTORY).join("retired");
    require_directory(&retired)?;
    for id in intent.added.keys() {
        let path = directory.join(id);
        if path_exists(&path)? {
            let destination = retired.join(id);
            if path_exists(&destination)? {
                return Err(integrity(format!(
                    "snapshot batch has both live and retired copies of {id}"
                )));
            }
            fs::rename(path, destination)?;
        }
    }
    sync_directory(directory)?;
    sync_directory(&retired)?;
    drop(leases);
    Ok(())
}

fn validate(intent: &Intent) -> MicrosandboxResult<()> {
    if intent.schema != SCHEMA
        || intent.operation.len() != 32
        || !intent
            .operation
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(integrity(
            "unsupported or malformed snapshot batch journal".into(),
        ));
    }
    for id in intent
        .added
        .keys()
        .chain(intent.incoming.keys())
        .chain(intent.aliases.keys())
        .chain(intent.previous_head.iter())
        .chain(intent.next_head.iter())
    {
        SnapshotId::new(id).map_err(|error| integrity(error.to_string()))?;
    }
    for digest in intent
        .added
        .values()
        .chain(intent.incoming.values())
        .chain(intent.aliases.values().map(|change| &change.digest))
    {
        let Some(hex) = digest.strip_prefix("sha256:") else {
            return Err(integrity("invalid snapshot digest in batch journal".into()));
        };
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(integrity("invalid snapshot digest in batch journal".into()));
        }
    }
    // Rollback may retire only entries the same intent declared as incoming.
    // A damaged journal must never expand its deletion set to preexisting members.
    if intent
        .added
        .iter()
        .any(|(id, digest)| intent.incoming.get(id) != Some(digest))
    {
        return Err(integrity(
            "batch rollback entries do not match incoming identities".into(),
        ));
    }
    if intent.index_pending && intent.incoming.is_empty() {
        return Err(integrity(
            "indexed batch journal has no incoming members".into(),
        ));
    }
    for change in intent.aliases.values() {
        for name in change.previous.iter().chain(change.next.iter()) {
            validate_alias(name)?;
        }
    }
    if intent
        .added
        .keys()
        .any(|id| intent.aliases.contains_key(id))
    {
        return Err(integrity(
            "batch journal cannot reuse and add the same member".into(),
        ));
    }
    Ok(())
}

fn retire(directory: &Path) -> MicrosandboxResult<()> {
    let journal = directory.join(DIRECTORY);
    // Rename first: interruption during recursive cleanup must not turn a partially deleted
    // journal back into a live transaction. Orphaned hidden garbage is safe to reclaim later.
    let garbage = directory.join(format!(".group-retired-{:032x}", rand::random::<u128>()));
    fs::rename(&journal, &garbage)?;
    sync_directory(directory)?;
    fs::remove_dir_all(garbage)?;
    sync_directory(directory)?;
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use super::super::tests::{add, descriptor, id, stage};
    use super::*;

    #[cfg(windows)]
    #[tokio::test]
    #[ignore = "live subprocess worker; requires isolated home, archives and explicit crash boundary"]
    async fn live_windows_import_worker() {
        use crate::{Checkpoint as Snapshot, backend::LocalBackend, snapshot::LoadOpts};
        let home = PathBuf::from(std::env::var_os("MSB_TEST_IMPORT_HOME").unwrap());
        let archives: Vec<PathBuf> =
            serde_json::from_str(&std::env::var("MSB_TEST_IMPORT_ARCHIVES").unwrap()).unwrap();
        let group = std::env::var("MSB_TEST_IMPORT_GROUP").unwrap();
        let backend = LocalBackend::builder().home(&home).build().await.unwrap();
        crate::with_backend(backend, async {
            Snapshot::load_many(
                &archives,
                LoadOpts {
                    group: Some(group),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        })
        .await;
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn txf_killed_publisher_needs_no_reader_recovery_to_hide_partial_batch() {
        for new_group in [false, true] {
            for boundary in 0..=4 {
                let root = tempfile::tempdir().unwrap();
                super::super::txf::check(root.path()).unwrap();
                let group = if new_group {
                    ensure_import(root.path(), Some("history"))
                        .await
                        .unwrap()
                        .directory
                } else {
                    let group = ensure(root.path(), Some("history")).await.unwrap();
                    add(&group, 1, None).await;
                    group
                };
                let staged = stage(
                    root.path(),
                    &[
                        descriptor(2, (!new_group).then_some(1)),
                        descriptor(3, Some(2)),
                    ],
                );
                let mut child = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "backend::local::snapshot::group::transaction::tests::crash_worker",
                        "--ignored",
                        "--nocapture",
                    ])
                    .env("MSB_TEST_GROUP_TRANSACTION", &group)
                    .env("MSB_TEST_GROUP_STAGING", staged.path())
                    .env("MSB_TEST_GROUP_BOUNDARY", boundary.to_string())
                    .env("MSB_TEST_GROUP_TXF", "1")
                    .stdout(Stdio::piped())
                    .spawn()
                    .unwrap();
                let output = child.stdout.take().unwrap();
                let (sender, receiver) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    for line in BufReader::new(output).lines() {
                        if line.unwrap().contains("TRANSACTION_BOUNDARY_READY") {
                            let _ = sender.send(());
                            break;
                        }
                    }
                });
                let reached = receiver.recv_timeout(Duration::from_secs(20));
                let _ = child.kill();
                child.wait().unwrap();
                reached
                    .unwrap_or_else(|error| panic!("new={new_group} boundary={boundary}: {error}"));
                let committed = boundary == 4;
                // These are raw filesystem reads, deliberately BEFORE lock_recovery or
                // any SDK access. Old readers cannot understand our intent journal.
                let raw = read_members(&group, true).unwrap();
                assert_eq!(
                    raw.len(),
                    if committed {
                        if new_group { 2 } else { 3 }
                    } else {
                        usize::from(!new_group)
                    }
                );
                if new_group && !committed {
                    assert!(!group.join(GROUP_FILENAME).exists());
                } else {
                    assert_eq!(
                        read_group(&group).unwrap().head,
                        Some(id(if committed { 3 } else { 1 }).to_string())
                    );
                }
                assert_eq!(
                    member_name(&group.join(id(if new_group { 2 } else { 1 }).as_str())).unwrap(),
                    committed.then(|| "baseline".into())
                );
                assert_eq!(group.join(DIRECTORY).join("committed").exists(), committed);
                recover(&group).unwrap();
                assert_eq!(read_members(&group, true).unwrap().len(), raw.len());
            }
        }
    }

    #[tokio::test]
    async fn killed_publisher_recovers_old_or_complete_state_and_can_retry() {
        for (new_group, boundary) in [false, true]
            .into_iter()
            .flat_map(|new| (0..=4).map(move |boundary| (new, boundary)))
        {
            let root = tempfile::tempdir().unwrap();
            let group = if new_group {
                let destination = ensure_import(root.path(), Some("history")).await.unwrap();
                destination.directory.clone()
            } else {
                let group = ensure(root.path(), Some("history")).await.unwrap();
                add(&group, 1, None).await;
                group
            };
            let original = (!new_group)
                .then(|| fs::read(group.join(id(1).as_str()).join(DESCRIPTOR_FILENAME)).unwrap());
            let baseline = if new_group { 2 } else { 1 };
            let staged = stage(
                root.path(),
                &[
                    descriptor(2, (!new_group).then_some(1)),
                    descriptor(3, Some(2)),
                ],
            );
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "backend::local::snapshot::group::transaction::tests::crash_worker",
                    "--ignored",
                    "--nocapture",
                ])
                .env("MSB_TEST_GROUP_TRANSACTION", &group)
                .env("MSB_TEST_GROUP_STAGING", staged.path())
                .env("MSB_TEST_GROUP_BOUNDARY", boundary.to_string())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let output = child.stdout.take().unwrap();
            let (sender, receiver) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                for line in BufReader::new(output).lines() {
                    if line.unwrap().contains("TRANSACTION_BOUNDARY_READY") {
                        let _ = sender.send(());
                        break;
                    }
                }
            });
            let reached = receiver.recv_timeout(Duration::from_secs(15));
            let reader_group = group.clone();
            let mut reader = tokio::spawn(async move { member_paths(&reader_group).await });
            let reader_blocked = tokio::time::timeout(Duration::from_millis(30), &mut reader)
                .await
                .is_err();
            // Terminate the process, rather than unwinding an injected error: its leases and
            // temporary directories must survive until the OS closes handles on process exit.
            let _ = child.kill();
            child.wait().unwrap();
            reached.unwrap_or_else(|error| panic!("boundary {boundary}: {error}"));
            assert!(reader_blocked, "reader bypassed active group ownership");

            let committed = boundary == 4;
            let paths = tokio::time::timeout(Duration::from_secs(15), reader)
                .await
                .expect("reader remained blocked after publisher exit")
                .unwrap();
            // The waiting reader can acquire the group lock while the OS is still
            // closing the killed publisher's member pins. Refusing rollback then is
            // correct. Retry that specific busy result after child.wait(), when the
            // terminated process no longer owns handles; all other errors still fail.
            let paths = match paths {
                Err(MicrosandboxError::SnapshotIntegrity(message))
                    if message.starts_with(
                        "snapshot batch recovery is waiting for an active reader of ",
                    ) =>
                {
                    member_paths(&group).await.unwrap()
                }
                result => result.unwrap(),
            };
            assert_eq!(
                paths.len(),
                if committed {
                    if new_group { 2 } else { 3 }
                } else {
                    usize::from(!new_group)
                }
            );
            if new_group && !committed {
                assert!(!group.join(GROUP_FILENAME).exists());
                assert!(resolve(root.path(), "history").await.is_err());
                assert!(recover_member(&group.join(id(2).as_str())).await.is_err());
                // The reserved name remains reusable after a process dies mid-publication.
                let retry = ensure_import(root.path(), Some("history")).await.unwrap();
                assert_eq!(retry.directory, group);
            } else {
                assert_eq!(
                    read_group(&group).unwrap().head,
                    Some(id(if committed { 3 } else { 1 }).to_string())
                );
            }
            assert_eq!(
                member_name(&group.join(id(baseline).as_str())).unwrap(),
                committed.then(|| "baseline".to_owned())
            );
            if let Some(original) = original {
                assert_eq!(
                    fs::read(group.join(id(1).as_str()).join(DESCRIPTOR_FILENAME)).unwrap(),
                    original
                );
            }
            assert!(!group.join(DIRECTORY).exists());

            // Re-unpack the same immutable batch after losing the previous reply. Both an
            // aborted publication and an already committed one must have the same final view.
            let retry = stage(
                root.path(),
                &[
                    descriptor(2, (!new_group).then_some(1)),
                    descriptor(3, Some(2)),
                ],
            );
            publish_batch(
                &group,
                retry.path(),
                &BTreeMap::from([
                    (id(baseline).to_string(), "baseline".into()),
                    (id(3).to_string(), "latest".into()),
                ]),
                &[id(2), id(3)],
                false,
            )
            .await
            .unwrap();
            assert_eq!(
                member_paths(&group).await.unwrap().len(),
                if new_group { 2 } else { 3 }
            );
            assert_eq!(read_group(&group).unwrap().head, Some(id(3).to_string()));
        }
    }

    #[tokio::test]
    #[ignore = "requires MSB_TEST_LEGACY_CLI pointing to a pre-journal CLI"]
    async fn old_cli_refuses_uncommitted_member_after_publisher_crash() {
        let executable = std::env::var_os("MSB_TEST_LEGACY_CLI").expect("legacy CLI path");
        let root = tempfile::tempdir().unwrap();
        let group = ensure(root.path(), Some("history")).await.unwrap();
        add(&group, 1, None).await;
        let staged = stage(
            root.path(),
            &[descriptor(2, Some(1)), descriptor(3, Some(2))],
        );
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "backend::local::snapshot::group::transaction::tests::crash_worker",
                "--ignored",
                "--nocapture",
            ])
            .env("MSB_TEST_GROUP_TRANSACTION", &group)
            .env("MSB_TEST_GROUP_STAGING", staged.path())
            .env("MSB_TEST_GROUP_BOUNDARY", "1")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let output = child.stdout.take().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                if line.unwrap().contains("TRANSACTION_BOUNDARY_READY") {
                    let _ = sender.send(());
                    break;
                }
            }
        });
        let reached = receiver.recv_timeout(Duration::from_secs(15));
        let _ = child.kill();
        child.wait().unwrap();
        reached.unwrap();
        assert!(group.join(id(2).as_str()).exists());
        assert!(!group.join(id(3).as_str()).exists());
        assert!(!group.join(DIRECTORY).join("committed").exists());
        // Exercise a real old executable before any new reader repairs the journal.
        // Use an isolated home: this probe must never open the user's normal catalog.
        let result = Command::new(executable)
            .env("MSB_HOME", root.path().join("legacy-home"))
            .args(["snapshot", "inspect"])
            .arg(group.join(id(2).as_str()))
            .output()
            .unwrap();
        assert!(
            !result.status.success(),
            "old CLI admitted an uncommitted member:\n{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        // Refusal alone is not enough: ensure the old reader did not hide a damaged
        // fixture behind an unrelated startup error. A new reader must recover it.
        assert_eq!(member_paths(&group).await.unwrap().len(), 1);
    }

    #[test]
    #[ignore = "subprocess helper, exercised by killed_publisher_recovers_old_or_complete_state_and_can_retry"]
    fn crash_worker() {
        let group = PathBuf::from(std::env::var_os("MSB_TEST_GROUP_TRANSACTION").unwrap());
        let staged = PathBuf::from(std::env::var_os("MSB_TEST_GROUP_STAGING").unwrap());
        let boundary: usize = std::env::var("MSB_TEST_GROUP_BOUNDARY")
            .unwrap()
            .parse()
            .unwrap();
        let new_group = is_creating(&group).unwrap();
        let _creation = new_group.then(|| {
            let lock = process_lock::open_existing_lock_file(
                &group.parent().unwrap().join(".groups.lock"),
            )
            .unwrap();
            process_lock::lock_exclusive(&lock).unwrap();
            lock
        });
        let incoming = read_members(&staged, false).unwrap();
        let _pins = incoming
            .keys()
            .map(|id| {
                microsandbox_image::storage_lease::StorageLease::shared(&group.join(id)).unwrap()
            })
            .collect::<Vec<_>>();
        let _lock = lock_publication(&group).unwrap();
        let mut members = read_members(&group, true).unwrap();
        members.extend(read_members(&staged, false).unwrap());
        let aliases = BTreeMap::from([
            (
                id(if new_group { 2 } else { 1 }).to_string(),
                "baseline".into(),
            ),
            (id(3).to_string(), "latest".into()),
        ]);
        apply_aliases(&mut members, &aliases).unwrap();
        let intent = prepare(
            &group,
            &incoming,
            &members,
            &aliases,
            (!new_group).then(|| id(1).to_string()),
            Some(id(3).to_string()),
        )
        .unwrap();
        let wait = |reached| {
            if boundary == reached {
                println!("TRANSACTION_BOUNDARY_READY");
                std::io::stdout().flush().unwrap();
                loop {
                    std::thread::park();
                }
            }
        };
        wait(0);
        #[cfg(windows)]
        if std::env::var_os("MSB_TEST_GROUP_TXF").is_some() {
            install_windows(&group, &incoming, &members, &intent, |moved| {
                wait(if moved == usize::MAX { 3 } else { moved });
                Ok(())
            })
            .unwrap();
            wait(4);
            panic!("unknown TxF test boundary");
        }
        install(&group, &incoming, &members, &aliases, &intent, |moved| {
            wait(if moved == usize::MAX { 3 } else { moved });
            Ok(())
        })
        .unwrap();
        wait(4);
        panic!("unknown transaction test boundary");
    }

    #[tokio::test]
    async fn interrupted_batch_restores_members_head_and_reused_alias() {
        for fail_after in [1, 2, usize::MAX] {
            let root = tempfile::tempdir().unwrap();
            let group = ensure(root.path(), Some("history")).await.unwrap();
            add(&group, 1, None).await;
            let original = fs::read(group.join(id(1).as_str()).join(DESCRIPTOR_FILENAME)).unwrap();
            let staged = stage(
                root.path(),
                &[descriptor(2, Some(1)), descriptor(3, Some(2))],
            );
            let incoming = read_members(staged.path(), false).unwrap();
            let mut members = read_members(&group, true).unwrap();
            for (key, member) in &incoming {
                members.insert(
                    key.clone(),
                    Member {
                        path: member.path.clone(),
                        digest: member.digest.clone(),
                        parent: member.parent.clone(),
                        name: None,
                    },
                );
            }
            let aliases = BTreeMap::from([
                (id(1).to_string(), "baseline".into()),
                (id(3).to_string(), "latest".into()),
            ]);
            apply_aliases(&mut members, &aliases).unwrap();
            let intent = prepare(
                &group,
                &incoming,
                &members,
                &aliases,
                Some(id(1).to_string()),
                Some(id(3).to_string()),
            )
            .unwrap();
            let error = install(&group, &incoming, &members, &aliases, &intent, |count| {
                if count == fail_after {
                    return Err(integrity("injected publication failure".into()));
                }
                Ok(())
            })
            .unwrap_err();
            assert!(error.to_string().contains("injected"));
            recover(&group).unwrap();
            assert_eq!(
                read_group(&group).unwrap().head.as_deref(),
                Some(id(1).as_str())
            );
            assert_eq!(read_members(&group, true).unwrap().len(), 1);
            assert_eq!(member_name(&group.join(id(1).as_str())).unwrap(), None);
            assert_eq!(
                fs::read(group.join(id(1).as_str()).join(DESCRIPTOR_FILENAME)).unwrap(),
                original
            );
            assert!(!group.join(DIRECTORY).exists());
            recover(&group).unwrap(); // A lost recovery acknowledgement is safe to retry.
        }
    }

    #[tokio::test]
    async fn committed_batch_survives_journal_cleanup_retry() {
        let root = tempfile::tempdir().unwrap();
        let group = ensure(root.path(), Some("history")).await.unwrap();
        let staged = stage(root.path(), &[descriptor(1, None), descriptor(2, Some(1))]);
        let incoming = read_members(staged.path(), false).unwrap();
        let intent = prepare(
            &group,
            &incoming,
            &incoming,
            &BTreeMap::new(),
            None,
            Some(id(2).to_string()),
        )
        .unwrap();
        install(
            &group,
            &incoming,
            &incoming,
            &BTreeMap::new(),
            &intent,
            |_| Ok(()),
        )
        .unwrap();
        recover(&group).unwrap();
        assert_eq!(read_members(&group, true).unwrap().len(), 2);
        assert_eq!(
            read_group(&group).unwrap().head.as_deref(),
            Some(id(2).as_str())
        );
    }

    #[tokio::test]
    async fn recovery_refuses_changed_identity_without_partial_rollback() {
        let root = tempfile::tempdir().unwrap();
        let group = ensure(root.path(), Some("history")).await.unwrap();
        let staged = stage(root.path(), &[descriptor(1, None), descriptor(2, Some(1))]);
        let incoming = read_members(staged.path(), false).unwrap();
        let intent = prepare(
            &group,
            &incoming,
            &incoming,
            &BTreeMap::new(),
            None,
            Some(id(2).to_string()),
        )
        .unwrap();
        install(
            &group,
            &incoming,
            &incoming,
            &BTreeMap::new(),
            &intent,
            |count| {
                if count == 2 {
                    Err(integrity("injected failure".into()))
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
        let mut changed = descriptor(2, Some(1));
        changed.capture.source_lineage = Some("different".into());
        fs::write(
            group.join(id(2).as_str()).join(DESCRIPTOR_FILENAME),
            changed.to_canonical_bytes().unwrap(),
        )
        .unwrap();
        assert!(
            recover(&group)
                .unwrap_err()
                .to_string()
                .contains("changed outside")
        );
        assert!(group.join(id(1).as_str()).exists());
        assert!(group.join(DIRECTORY).exists());
        assert_eq!(read_group(&group).unwrap().head, None);
    }

    #[tokio::test]
    async fn explicit_open_barrier_recovers_uncommitted_members() {
        let root = tempfile::tempdir().unwrap();
        let group = ensure(root.path(), Some("history")).await.unwrap();
        let staged = stage(root.path(), &[descriptor(1, None)]);
        let incoming = read_members(staged.path(), false).unwrap();
        let intent = prepare(
            &group,
            &incoming,
            &incoming,
            &BTreeMap::new(),
            None,
            Some(id(1).to_string()),
        )
        .unwrap();
        install(
            &group,
            &incoming,
            &incoming,
            &BTreeMap::new(),
            &intent,
            |_| Err(integrity("injected failure".into())),
        )
        .unwrap_err();
        recover_member(&group.join(id(1).as_str())).await.unwrap();
        assert!(member_paths(&group).await.unwrap().is_empty());
        assert!(!group.join(id(1).as_str()).exists());
    }
}
