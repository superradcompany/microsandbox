//! Immutable boot-selection evidence, kept separate from the strict retention journal.

use std::{io, path::Path};

use microsandbox_protocol::init_observation::InitObservation;
use serde::{Deserialize, Serialize};

use super::{RetainedConfiguration, RetentionOwner, invalid, read_private_json};

#[cfg(any(feature = "runner", test))]
use super::{RetentionJournal, RetentionTransition, write_private_json};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const RECORD: &str = "init.json";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedInit {
    schema: u32,
    owner: RetentionOwner,
    start_generation: u64,
    observation: Option<InitObservation>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[cfg(any(feature = "runner", test))]
impl RetentionJournal {
    /// Persist immutable boot evidence before confirming activation. A later live modification
    /// changes configuration generation, but cannot change which executable booted this run.
    pub(crate) fn confirm_start(
        &mut self,
        source: Option<serde_json::Value>,
        observation: Option<InitObservation>,
    ) -> io::Result<()> {
        if self.record.pending != Some(RetentionTransition::Start) {
            return Err(invalid("no activation to confirm"));
        }
        let init = RetainedInit {
            schema: 1,
            owner: self.record.owner.clone(),
            start_generation: self.record.generation,
            observation,
        };
        // Publish first: a crash between these writes leaves the main journal pending, so
        // neither live nor stopped selection can turn this sidecar into confirmed evidence.
        write_private_json(&self.directory, RECORD, &init)?;
        self.confirm(source)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Read init selection only for an independently selected, confirmed configuration owner.
/// The caller must retain its live mutation/lifecycle guard and revalidate that selection.
/// Missing evidence from an older runtime/guest is unknown; it never implies builtin init.
pub fn read_retained_init(
    sandbox_directory: &Path,
    confirmed: &RetainedConfiguration,
) -> io::Result<Option<InitObservation>> {
    let Some(init) = read_private_json::<RetainedInit>(sandbox_directory, RECORD)? else {
        return Ok(None);
    };
    if init.schema != 1 || init.start_generation == 0 {
        return Err(invalid("unsupported retained init record"));
    }
    if init.owner != confirmed.owner
        || init.start_generation > confirmed.generation
        || confirmed.source.is_none()
    {
        return Ok(None);
    }
    Ok(init.observation)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    fn owner(boot: &str) -> RetentionOwner {
        RetentionOwner {
            catalog_file: [1, 2],
            sandbox_id: 3,
            sandbox_created_at: Some("created".into()),
            run_id: 4,
            run_started_at: "started".into(),
            runtime_boot_id: boot.into(),
        }
    }

    fn handoff() -> Option<InitObservation> {
        Some(InitObservation::Handoff {
            path: "/sbin/init".into(),
        })
    }

    #[test]
    fn selection_survives_live_generations_but_not_runtime_replacement() {
        let home = tempfile::tempdir().unwrap();
        let first = owner("first");
        let mut journal = RetentionJournal::begin_start(home.path(), first.clone()).unwrap();
        journal.confirm_start(Some(json!({})), handoff()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(journal.directory.join(RECORD))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        journal.begin_modify().unwrap();
        journal
            .confirm(Some(json!({"resources":{"cpus":2}})))
            .unwrap();
        let selected = journal.record().current(&first).unwrap();
        assert_eq!(
            read_retained_init(home.path(), selected).unwrap(),
            handoff()
        );

        // An older writer can still read the unchanged strict journal and confirm a new run.
        // It never writes init.json; the previous boot's file must not become its evidence.
        let mut next = RetentionJournal::begin_start(home.path(), owner("second")).unwrap();
        next.confirm(Some(json!({}))).unwrap();
        assert!(
            read_retained_init(home.path(), next.record().confirmed.as_ref().unwrap())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn init_write_failure_keeps_activation_pending() {
        let home = tempfile::tempdir().unwrap();
        let first = owner("first");
        let mut journal = RetentionJournal::begin_start(home.path(), first.clone()).unwrap();
        std::fs::create_dir(journal.directory.join(RECORD)).unwrap();
        assert!(journal.confirm_start(Some(json!({})), handoff()).is_err());
        assert!(journal.record().current(&first).is_none());
        assert!(
            RetentionJournal::read(home.path())
                .unwrap()
                .unwrap()
                .current(&first)
                .is_none()
        );
    }

    #[test]
    fn journal_confirmation_failure_does_not_certify_the_sidecar() {
        let home = tempfile::tempdir().unwrap();
        let first = owner("first");
        let mut journal = RetentionJournal::begin_start(home.path(), first.clone()).unwrap();
        let state = journal.directory.join(super::super::RECORD);
        std::fs::remove_file(&state).unwrap();
        std::fs::create_dir(&state).unwrap();
        assert!(journal.confirm_start(Some(json!({})), handoff()).is_err());
        assert!(journal.directory.join(RECORD).is_file());
        assert!(journal.record().current(&first).is_none());
    }

    #[test]
    fn older_or_unknown_sources_do_not_gain_init_defaults() {
        let home = tempfile::tempdir().unwrap();
        let first = owner("first");
        let mut journal = RetentionJournal::begin_start(home.path(), first.clone()).unwrap();
        journal.confirm(Some(json!({}))).unwrap();
        assert!(
            read_retained_init(home.path(), journal.record().current(&first).unwrap())
                .unwrap()
                .is_none()
        );

        let second = owner("second");
        let mut next = RetentionJournal::begin_start(home.path(), second).unwrap();
        next.confirm_start(None, Some(InitObservation::Builtin))
            .unwrap();
        assert!(
            read_retained_init(home.path(), next.record().confirmed.as_ref().unwrap())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn owner_and_generation_mismatch_never_reuse_init_selection() {
        let home = tempfile::tempdir().unwrap();
        let first = owner("first");
        let mut journal = RetentionJournal::begin_start(home.path(), first.clone()).unwrap();
        journal.confirm_start(Some(json!({})), handoff()).unwrap();
        let selected = journal.record().current(&first).unwrap().clone();
        for field in ["catalog", "sandbox", "run", "boot", "generation"] {
            let mut wrong = selected.clone();
            match field {
                "catalog" => wrong.owner.catalog_file[1] += 1,
                "sandbox" => wrong.owner.sandbox_id += 1,
                "run" => wrong.owner.run_id += 1,
                "boot" => wrong.owner.runtime_boot_id.push('x'),
                _ => wrong.generation = 0,
            }
            assert!(
                read_retained_init(home.path(), &wrong).unwrap().is_none(),
                "{field}"
            );
        }
        assert!(
            journal
                .confirm_start(Some(json!({})), Some(InitObservation::Builtin))
                .is_err()
        );
        assert_eq!(
            read_retained_init(home.path(), &selected).unwrap(),
            handoff()
        );
    }
}
