//! Small, reviewable support reports. Never copy raw storage errors or configuration into them.

use std::collections::BTreeSet;

use microsandbox::MicrosandboxError;
use microsandbox::setup::{
    self, StorageDiagnosticReason, StorageDiagnosticStatus, StorageSandboxDiagnosis,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

pub(super) const ISSUES_URL: &str = "https://github.com/superradcompany/microsandbox/issues";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Presentation classifications only: none of these authorize a repair or a fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Failure {
    SelectionUnknown,
    SourcesUnavailable,
    Configuration,
    NotFound,
    IncompleteCreation,
    UnfinishedOperation,
    StaleOperation,
    WriterProtection,
    UnsafeStop,
    Permissions,
    RuntimeRequired,
    ResourceLimit,
    UnsupportedLayout,
    Unclassified,
}

/// The caller records actions before awaiting them, since an error can follow a partial action.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Actions {
    pub stop_attempted: bool,
    pub stopped: usize,
    pub repair_attempted: bool,
    pub repaired: bool,
    /// Another target may share this catalog or backing storage; do not claim a global no-op.
    pub other_actions_attempted: bool,
}

/// A configured executable's embedded version, not the version of an already-running VM.
#[derive(Debug)]
pub(super) enum RuntimeVersion {
    Known(setup::Version),
    NoVersionMetadata,
    Unavailable,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Failure {
    pub(super) fn from_diagnosis(item: &StorageSandboxDiagnosis) -> Self {
        match item.reason {
            Some(StorageDiagnosticReason::NotFound) => return Self::NotFound,
            Some(StorageDiagnosticReason::InvalidConfiguration) => return Self::Configuration,
            Some(StorageDiagnosticReason::IncompleteCreation) => return Self::IncompleteCreation,
            Some(StorageDiagnosticReason::StorageUnavailable) => return Self::SourcesUnavailable,
            None => {}
        }
        if let Some(inspection) = &item.inspection {
            for reason in &inspection.reasons {
                let failure = Self::from_message(reason);
                if failure != Self::Unclassified {
                    return failure;
                }
            }
        }
        Self::Unclassified
    }

    pub(super) fn from_error(error: &MicrosandboxError) -> Self {
        match error {
            MicrosandboxError::SandboxNotFound(_) => Self::NotFound,
            MicrosandboxError::SandboxStillRunning(_)
            | MicrosandboxError::SandboxStopTimedOut { .. }
            | MicrosandboxError::StopTimeout { .. } => Self::WriterProtection,
            MicrosandboxError::SandboxReplaced { .. } => Self::StaleOperation,
            MicrosandboxError::RuntimeNotInstalled(_)
            | MicrosandboxError::RuntimeIncomplete(_)
            | MicrosandboxError::LibkrunfwNotFound(_) => Self::RuntimeRequired,
            MicrosandboxError::Io(error) => match error.kind() {
                std::io::ErrorKind::PermissionDenied => Self::Permissions,
                std::io::ErrorKind::NotFound => Self::SourcesUnavailable,
                _ => Self::Unclassified,
            },
            MicrosandboxError::Runtime(message)
            | MicrosandboxError::InvalidConfig(message)
            | MicrosandboxError::Custom(message) => Self::from_message(message),
            _ => Self::Unclassified,
        }
    }

    pub(super) fn code(self) -> &'static str {
        match self {
            Self::SelectionUnknown => "active_state_unresolved",
            Self::SourcesUnavailable => "required_storage_unavailable",
            Self::Configuration => "configuration_unavailable",
            Self::NotFound => "sandbox_not_found",
            Self::IncompleteCreation => "creation_incomplete",
            Self::UnfinishedOperation => "operation_incomplete",
            Self::StaleOperation => "operation_changed",
            Self::WriterProtection => "writer_exclusion_unavailable",
            Self::UnsafeStop => "stop_requires_data_preservation",
            Self::Permissions => "storage_authority_unavailable",
            Self::RuntimeRequired => "supporting_runtime_required",
            Self::ResourceLimit => "inspection_limit_reached",
            Self::UnsupportedLayout => "layout_not_supported",
            Self::Unclassified => "safe_repair_not_established",
        }
    }

    pub(super) fn message(self) -> &'static str {
        match self {
            Self::SelectionUnknown => "We couldn't establish which saved disk state is active.",
            Self::SourcesUnavailable => {
                "A required file or dependency could not be opened safely. It may be missing or inaccessible."
            }
            Self::Configuration => "The saved sandbox configuration could not be read safely.",
            Self::NotFound => "The requested sandbox was not found in the selected home.",
            Self::IncompleteCreation => "Sandbox creation or restore has not finished.",
            Self::UnfinishedOperation => {
                "An earlier disk operation needs recovery before this repair can proceed."
            }
            Self::StaleOperation => {
                "The sandbox, selected storage, or saved repair operation changed. It needs investigation before retrying."
            }
            Self::WriterProtection => {
                "We couldn't establish that the selected disks are protected from other writers."
            }
            Self::UnsafeStop => {
                "Stopping this ephemeral sandbox could remove its storage. Preserve its data before stopping it separately."
            }
            Self::Permissions => {
                "The storage permissions or file links do not establish safe host ownership."
            }
            Self::RuntimeRequired => {
                "A supporting runtime installation is required for this operation."
            }
            Self::ResourceLimit => "The storage inspection reached a safety or resource limit.",
            Self::UnsupportedLayout => {
                "This storage layout or dependency arrangement is not supported by automatic repair."
            }
            Self::Unclassified => "We couldn't establish a safe repair for this storage.",
        }
    }

    fn from_message(message: &str) -> Self {
        // Existing engine failures are strings. Match only known classifications and emit
        // fixed text; never redact-and-print arbitrary errors, which can contain host paths.
        if message.contains("stopping this ephemeral sandbox") {
            Self::UnsafeStop
        } else if message.contains("active-head record")
            || message.contains("invalid legacy root journal")
            || message.contains("invalid legacy owned-disk journal")
        {
            Self::SelectionUnknown
        } else if message.contains("pending root growth") {
            Self::UnfinishedOperation
        } else if message.contains("recorded migration source changed")
            || message.contains("migration source changed")
            || message.contains("legacy selection changed")
            || message.contains("frozen operation")
            || message.contains("saved configuration changed")
            || message.contains("selected blocker changed")
            || message.contains("selected storage home changed")
            || message.contains("stale")
        {
            Self::StaleOperation
        } else if message.contains("open writer")
            || message.contains("writer protection")
            || message.contains("read leases")
            || message.contains("still has a recorded runtime process")
        {
            Self::WriterProtection
        } else if message.contains("upgrade required") {
            Self::RuntimeRequired
        } else if message.contains("incomplete creation") {
            Self::IncompleteCreation
        } else if message.contains("unavailable or linked")
            || message.contains("missing or linked directory")
        {
            Self::SourcesUnavailable
        } else if message.contains("permission")
            || message.contains("host controlled")
            || message.contains("hardlink aliases")
            || message.contains("host authority")
        {
            Self::Permissions
        } else if message.contains("exceeds") && message.contains("bound") {
            Self::ResourceLimit
        } else if message.contains("unsupported")
            || message.contains("outside its disk producer roles")
            || message.contains("separately authorized dependencies")
            || message.contains("disagrees with")
        {
            Self::UnsupportedLayout
        } else {
            Self::Unclassified
        }
    }
}

impl RuntimeVersion {
    pub(super) fn inspect() -> Self {
        // This uses the same layered path resolution as setup, without constructing a
        // backend, executing a runtime, installing files, or opening the catalog.
        let version = setup::binding_runtime_config("{}")
            .and_then(|config| setup::resolve_runtime(&config))
            .and_then(|runtime| setup::resolve_runtime_version(runtime.msb_path));
        match version {
            Ok(Some(version)) => Self::Known(version),
            Ok(None) => Self::NoVersionMetadata,
            Err(_) => Self::Unavailable,
        }
    }

    fn description(&self) -> String {
        match self {
            Self::Known(version) => version.to_string(),
            Self::NoVersionMetadata => "unavailable (executable has no embedded version)".into(),
            Self::Unavailable => "unavailable (configured runtime could not be inspected)".into(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn preservation(actions: Actions, failure: Failure) -> &'static str {
    if actions.repaired {
        "Protected storage is ready. Original disk files were retained."
    } else if actions.repair_attempted {
        "Repair was attempted and may have recorded migration or catalog progress. Keep the remaining original files and recovery records."
    } else if actions.stop_attempted || actions.stopped > 0 {
        "No storage repair was applied. A stop was attempted; normal shutdown may write guest state or update the catalog. Keep the remaining original files and recovery records."
    } else if actions.other_actions_attempted {
        "No repair was applied to this sandbox. Other selected operations may have updated shared storage or the catalog. Keep the remaining original files and recovery records."
    } else if failure == Failure::SourcesUnavailable {
        "No repair was performed. The remaining original disk files were left unchanged. Keep this sandbox until the problem is resolved."
    } else {
        "No repair was performed. Original disk files were left unchanged. Keep this sandbox until the problem is resolved."
    }
}

pub(super) fn render(
    diagnosis: Option<&StorageSandboxDiagnosis>,
    failure: Failure,
    actions: Actions,
    runtime: &RuntimeVersion,
) -> String {
    let mut report = format!(
        "microsandbox storage repair report\nCLI: {}\nConfigured runtime: {}\nPlatform: {} / {}\nOperation: legacy storage repair\nReason: {}\n{}\n",
        env!("CARGO_PKG_VERSION"),
        runtime.description(),
        std::env::consts::OS,
        std::env::consts::ARCH,
        failure.code(),
        failure.message(),
    );
    if let Some(item) = diagnosis {
        report.push_str(&format!(
            "Inspection: {} (provisional)\nRunning or transitioning: {}\nProtection registered: {}\n",
            status(item.status), item.running, item.protection_registered,
        ));
        if item.running {
            report.push_str("Running VM runtime: not queried\n");
        }
        if let Some(inspection) = &item.inspection {
            let root_views = inspection
                .candidates
                .iter()
                .filter(|view| view.disk_id == "root")
                .count();
            let owned: BTreeSet<_> = inspection
                .candidates
                .iter()
                .filter(|view| view.disk_id != "root")
                .map(|view| &view.disk_id)
                .collect();
            let layers = inspection
                .candidates
                .iter()
                .map(|view| view.layers)
                .max()
                .unwrap_or(0);
            report.push_str(&format!(
                "Storage: {root_views} root views; {} owned-disk roles; {} total views; up to {layers} layers per view\nEstimated staging bytes: {}\n",
                owned.len(), inspection.candidates.len(), inspection.estimated_bytes,
            ));
        }
    } else {
        report.push_str("Inspection: unavailable\n");
    }
    report.push_str(&format!(
        "Stop attempted: {}\nConfirmed stops: {}\nRepair attempted: {}\nRepair completed: {}\nOther batch actions attempted: {}\n{}\n\nGuest contents, sandbox names, credentials and host paths are excluded.\nReview and copy this report before posting at {ISSUES_URL}\nNothing is submitted automatically.\n",
        actions.stop_attempted, actions.stopped, actions.repair_attempted, actions.repaired,
        actions.other_actions_attempted,
        preservation(actions, failure),
    ));
    report
}

fn status(status: StorageDiagnosticStatus) -> &'static str {
    match status {
        StorageDiagnosticStatus::Ready => "ready",
        StorageDiagnosticStatus::Eligible => "eligible",
        StorageDiagnosticStatus::MaintenanceRequired => "maintenance required",
        StorageDiagnosticStatus::RecoveryRequired => "needs investigation",
        StorageDiagnosticStatus::InProgress => "upgrade in progress",
        StorageDiagnosticStatus::Unavailable => "unavailable",
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use microsandbox_runtime::checkpoint::migration::{
        CandidateSummary, Inspection, MigrationStatus,
    };

    use super::*;

    #[test]
    fn report_never_copies_names_paths_guest_mounts_or_raw_failures() {
        let secret = "private-token-123";
        let item = StorageSandboxDiagnosis {
            name: secret.into(),
            guest_mounts: BTreeMap::from([(secret.into(), format!("/{secret}"))]),
            status: StorageDiagnosticStatus::RecoveryRequired,
            running: false,
            protection_registered: true,
            reason: None,
            inspection: Some(Inspection {
                status: MigrationStatus::RecoveryRequired,
                preview_available: false,
                reasons: vec![format!(
                    "advanced disk storage has no usable active-head record: /home/{secret}"
                )],
                candidates: vec![CandidateSummary {
                    id: secret.into(),
                    disk_id: secret.into(),
                    layers: 2,
                    virtual_size: 1024,
                    estimated_bytes: 512,
                }],
                estimated_bytes: 512,
            }),
        };
        let failure = Failure::from_diagnosis(&item);
        let report = render(
            Some(&item),
            failure,
            Actions::default(),
            &RuntimeVersion::Unavailable,
        );
        assert_eq!(failure, Failure::SelectionUnknown);
        assert!(report.contains("1 owned-disk roles; 1 total views"));
        assert!(!report.contains(secret));
        assert!(!report.contains("/home/"));

        let error = MicrosandboxError::Runtime(format!("unexpected {secret} /private/data"));
        let report = render(
            None,
            Failure::from_error(&error),
            Actions::default(),
            &RuntimeVersion::Unavailable,
        );
        assert!(!report.contains(secret));
        assert!(!report.contains("/private/data"));
    }

    #[test]
    fn preservation_does_not_undo_or_hide_earlier_actions() {
        let failure = Failure::SourcesUnavailable;
        assert!(preservation(Actions::default(), failure).contains("remaining original"));
        let stopped = Actions {
            stop_attempted: true,
            stopped: 1,
            ..Default::default()
        };
        assert!(!preservation(stopped, failure).contains("left unchanged"));
        assert!(preservation(stopped, failure).contains("shutdown may write"));
        let attempted = Actions {
            repair_attempted: true,
            ..stopped
        };
        assert!(!preservation(attempted, failure).contains("No repair was performed"));
        assert!(preservation(attempted, failure).contains("may have recorded"));
    }

    #[test]
    fn source_error_does_not_claim_missing_data_or_damage() {
        let failure = Failure::from_error(&MicrosandboxError::Runtime(
            "storage source is unavailable or linked".into(),
        ));
        assert_eq!(failure, Failure::SourcesUnavailable);
        assert!(failure.message().contains("may be missing"));
        assert!(!failure.message().contains("damaged"));
        assert_eq!(
            Failure::from_message("pending root growth needs operation-aware recovery"),
            Failure::UnfinishedOperation
        );
        assert_eq!(
            Failure::from_message("source has an open writer or writable mapping"),
            Failure::WriterProtection
        );
        assert_eq!(
            Failure::from_error(&MicrosandboxError::Custom(
                "the selected blocker changed; inspect storage again".into()
            )),
            Failure::StaleOperation
        );
    }
}
