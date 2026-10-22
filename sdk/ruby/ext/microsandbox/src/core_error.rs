//! Preserve structured snapshot outcomes when translating SDK errors to Ruby.

use magnus::{Error, RHash, RObject, Ruby, prelude::*};
use microsandbox_core::{
    MicrosandboxError, PublishedSnapshotArtifact, SnapshotArtifactKind, SnapshotSourceRecoveryError,
};

use super::{
    core_error_class_name, exception_class, ruby_api_name, ruby_hint, snapshot_group,
    unsupported_error,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Convert a core error into the matching typed Ruby exception. The message is
/// always the core error's `Display` rendering, except for `Unsupported`,
/// which names the Ruby API instead of the Rust path.
pub(super) fn core_error(ruby: &Ruby, error: MicrosandboxError) -> Error {
    if let MicrosandboxError::SnapshotRemovalRecovery { result, source } = &error {
        let class = exception_class(ruby, "SnapshotRemovalRecoveryError");
        let message = error.to_string();
        let exception = match class.new_instance((message.as_str(),)) {
            Ok(exception) => exception,
            Err(_) => return Error::new(class, message),
        };
        if let Some(object) = RObject::from_value(exception.as_value()) {
            let result = snapshot_group::RubyCheckpointRemoveResult {
                inner: (**result).clone(),
            };
            if let Err(error) = object
                .ivar_set("@result", result)
                .and_then(|()| object.ivar_set("@detail", source.to_string()))
            {
                return error;
            }
        }
        return Error::from(exception);
    }
    if let MicrosandboxError::SnapshotGroupRemovalRecovery { result, source } = &error {
        let class = exception_class(ruby, "SnapshotGroupRemovalRecoveryError");
        let message = error.to_string();
        let exception = match class.new_instance((message.as_str(),)) {
            Ok(exception) => exception,
            Err(_) => return Error::new(class, message),
        };
        if let Some(object) = RObject::from_value(exception.as_value()) {
            let result = snapshot_group::RubySnapshotRemoveResult {
                inner: (**result).clone(),
            };
            if let Err(error) = object
                .ivar_set("@result", result)
                .and_then(|()| object.ivar_set("@detail", source.to_string()))
            {
                return error;
            }
        }
        return Error::from(exception);
    }
    if let MicrosandboxError::SnapshotVerification(report) = &error {
        let class = exception_class(ruby, "SnapshotVerificationError");
        let message = error.to_string();
        let exception = match class.new_instance((message.as_str(),)) {
            Ok(exception) => exception,
            Err(_) => return Error::new(class, message),
        };
        if let Some(object) = RObject::from_value(exception.as_value()) {
            match snapshot_group::verification_report(ruby, report)
                .and_then(|report| object.ivar_set("@report", report))
            {
                Ok(()) => {}
                Err(error) => return error,
            }
        }
        return Error::from(exception);
    }
    if let MicrosandboxError::Unsupported { op, reason } = &error {
        return unsupported_error(ruby, &ruby_api_name(*op), &ruby_hint(reason));
    }
    if let MicrosandboxError::SnapshotImport(details) = &error {
        let class = exception_class(ruby, "SnapshotImportError");
        let message = error.to_string();
        let exception = match class.new_instance((message.as_str(),)) {
            Ok(exception) => exception,
            Err(_) => return Error::new(class, message),
        };
        if let Some(object) = RObject::from_value(exception.as_value()) {
            let outcome = match details.outcome {
                microsandbox_core::SnapshotImportOutcome::NotCommitted => "not_committed",
                microsandbox_core::SnapshotImportOutcome::Committed => "committed",
                microsandbox_core::SnapshotImportOutcome::Unknown => "unknown",
            };
            let paths = ruby.ary_from_iter(
                details
                    .archives
                    .iter()
                    .map(|path| path.to_string_lossy().into_owned()),
            );
            let _ = object.ivar_set("@operation_id", details.operation_id.as_str());
            let _ = object.ivar_set("@archives", paths);
            let _ = object.ivar_set(
                "@group_path",
                details
                    .group_path
                    .as_ref()
                    .map(|path| path.to_string_lossy().into_owned()),
            );
            let _ = object.ivar_set("@outcome", outcome);
            let _ = object.ivar_set("@detail", details.detail.as_str());
        }
        return exception.into();
    }
    if let MicrosandboxError::SnapshotSourceRecovery(recovery) = &error {
        return snapshot_source_recovery_error(ruby, error.to_string(), recovery);
    }
    Error::new(
        exception_class(ruby, core_error_class_name(&error)),
        error.to_string(),
    )
}

/// Build a `Microsandbox::SnapshotSourceRecoveryError` carrying the recovery
/// locator as the attributes read by its `attr_reader`s, mirroring the Python
/// SDK's `SnapshotSourceRecoveryError`, so callers never parse the message.
fn snapshot_source_recovery_error(
    ruby: &Ruby,
    message: String,
    recovery: &SnapshotSourceRecoveryError,
) -> Error {
    let class = exception_class(ruby, "SnapshotSourceRecoveryError");
    let exception = match class.new_instance((message.as_str(),)) {
        Ok(exception) => exception,
        Err(_) => return Error::new(class, message),
    };
    // Best-effort extras; the message already carries the locator.
    if let Some(object) = RObject::from_value(exception.as_value()) {
        let checkpoint_path = recovery.checkpoint_path.to_string_lossy().into_owned();
        let _ = object.ivar_set("@source_sandbox", recovery.source_sandbox.as_str());
        let _ = object.ivar_set("@checkpoint_id", recovery.checkpoint_id.as_str());
        let _ = object.ivar_set("@checkpoint_root", recovery.checkpoint_root.as_str());
        let _ = object.ivar_set("@checkpoint_path", checkpoint_path);
        let _ = object.ivar_set("@detail", recovery.detail.as_str());
        let _ = object.ivar_set("@publication_error", recovery.publication_error.as_deref());
        let artifact = recovery.artifact.as_ref();
        if let Some(Ok(hash)) = artifact.map(|artifact| published_artifact_hash(ruby, artifact)) {
            let _ = object.ivar_set("@artifact", hash);
        }
    }
    exception.into()
}

/// The snapshot that was published despite the source failing to recover, as
/// a Hash with the same keys as the Python SDK's `PublishedSnapshotArtifact`.
fn published_artifact_hash(
    ruby: &Ruby,
    artifact: &PublishedSnapshotArtifact,
) -> Result<RHash, Error> {
    let kind = match artifact.kind {
        SnapshotArtifactKind::Installed => "installed",
        SnapshotArtifactKind::Archive => "archive",
    };
    let hash = ruby.hash_new();
    hash.aset("kind", kind)?;
    hash.aset("path", artifact.path.to_string_lossy().into_owned())?;
    hash.aset("snapshot_id", artifact.snapshot_id.as_str())?;
    hash.aset("digest", artifact.digest.as_str())?;
    if let Some(update) = &artifact.head_update {
        hash.aset("head_update", snapshot_group::head_update(update)?)?;
    }
    Ok(hash)
}
