//! Source-bound group histories and operation-owned capture results for Ruby.

use std::sync::Arc;

use magnus::{
    Error, RArray, RHash, RModule, Ruby, Value, function, method, prelude::*, scan_args::scan_args,
    typed_data,
};
use microsandbox_core::snapshot::{SnapshotVerifyCoverage, UpperVerifyStatus};
use microsandbox_core::{
    CheckpointCaptureResult, Snapshot, SnapshotCaptureOptions, SnapshotCreateResult,
};

use super::{
    RubySandbox, RubySandboxHandle, RubySnapshot, RubySnapshotHandle, argument_error, current_ruby,
    keyword, reject_unknown_keywords, run, string_map, symbol,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[magnus::wrap(class = "Microsandbox::Snapshot", free_immediately, size)]
pub(super) struct RubyGroup {
    pub(super) inner: Snapshot,
}

#[magnus::wrap(class = "Microsandbox::SnapshotCreateResult", free_immediately, size)]
pub(super) struct RubySnapshotCreateResult {
    pub(super) inner: SnapshotCreateResult,
}

#[magnus::wrap(
    class = "Microsandbox::CheckpointCaptureResult",
    free_immediately,
    size
)]
struct RubyCheckpointCaptureResult {
    inner: CheckpointCaptureResult,
}

#[magnus::wrap(class = "Microsandbox::SnapshotImportResult", free_immediately, size)]
struct RubySnapshotImportResult {
    inner: microsandbox_core::SnapshotImportResult,
}

#[magnus::wrap(class = "Microsandbox::CheckpointRemoveResult", free_immediately, size)]
pub(super) struct RubyCheckpointRemoveResult {
    pub(super) inner: microsandbox_core::CheckpointRemoveResult,
}

#[magnus::wrap(class = "Microsandbox::SnapshotRemoveResult", free_immediately, size)]
pub(super) struct RubySnapshotRemoveResult {
    pub(super) inner: microsandbox_core::SnapshotRemoveResult,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RubySandboxHandle {
    pub(super) fn snapshot(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        args: &[Value],
    ) -> Result<RubySnapshotCreateResult, Error> {
        let parsed = scan_args::<(String,), (), (), (), RHash, ()>(args)?;
        let name = parsed.required.0;
        let options = capture_options(ruby, parsed.keywords, true)?;
        let handle = Arc::clone(&this.inner);
        Ok(RubySnapshotCreateResult {
            inner: run(ruby, async move {
                handle.snapshot_with(&name, |_| options).await
            })?,
        })
    }
}

impl RubyCheckpointRemoveResult {
    fn id(&self) -> String {
        self.inner.id.to_string()
    }
    fn head_update(&self) -> Result<Option<RHash>, Error> {
        self.inner.head_update.as_ref().map(head_update).transpose()
    }
    fn warnings(&self) -> Vec<String> {
        self.inner.warnings.clone()
    }
}

impl RubySnapshotRemoveResult {
    fn group(&self) -> String {
        self.inner.group.clone()
    }
    fn removed(&self) -> Vec<String> {
        self.inner.removed.iter().map(ToString::to_string).collect()
    }
    fn head_update(&self) -> Result<RHash, Error> {
        head_update(&self.inner.head_update)
    }
    fn warnings(&self) -> Vec<String> {
        self.inner.warnings.clone()
    }
}

impl RubyGroup {
    fn inspect_info(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RHash, Error> {
        let group = this.inner.clone();
        let info = run(ruby, async move { group.inspect().await })?;
        ruby.require("json")?;
        let json: RModule = ruby.class_object().const_get("JSON")?;
        let payload = serde_json::to_string(&info)
            .map_err(|error| argument_error(ruby, error.to_string()))?;
        json.funcall("parse", (payload,))
    }

    fn remove(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RubySnapshotRemoveResult, Error> {
        let group = this.inner.clone();
        Ok(RubySnapshotRemoveResult {
            inner: run(ruby, async move { group.remove().await })?,
        })
    }

    fn verify(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RHash, Error> {
        let group = this.inner.clone();
        let report = run(ruby, async move { group.verify().await })?;
        verification_report(ruby, &report)
    }

    fn load(ruby: &Ruby, args: &[Value]) -> Result<RubySnapshotImportResult, Error> {
        let parsed = scan_args::<(String, Vec<String>), (), (), (), RHash, ()>(args)?;
        let (group, files) = parsed.required;
        let keywords = parsed.keywords;
        reject_unknown_keywords(ruby, keywords, &["dest", "base", "set_head"])?;
        let options = microsandbox_core::SnapshotImportOptions {
            dest: keyword::<String>(keywords, "dest")?.map(Into::into),
            base: keyword(keywords, "base")?,
            set_head: keyword::<bool>(keywords, "set_head")?.unwrap_or(false),
        };
        let files = files
            .into_iter()
            .map(std::path::PathBuf::from)
            .collect::<Vec<_>>();
        Ok(RubySnapshotImportResult {
            inner: run(ruby, async move {
                Snapshot::load_with(group, &files, |_| options).await
            })?,
        })
    }

    fn get(ruby: &Ruby, name: String) -> Result<Self, Error> {
        Ok(Self {
            inner: run(ruby, async move { Snapshot::get(name).await })?,
        })
    }

    fn list(ruby: &Ruby) -> Result<RArray, Error> {
        let groups = run(ruby, Snapshot::list())?;
        let result = ruby.ary_new();
        for inner in groups {
            result.push(Self { inner })?;
        }
        Ok(result)
    }

    fn name(&self) -> String {
        self.inner.name().into()
    }

    fn head(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<Option<RubySnapshot>, Error> {
        let group = this.inner.clone();
        Ok(run(ruby, async move { group.head().await })?.map(|inner| RubySnapshot { inner }))
    }

    fn checkpoints(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RArray, Error> {
        let group = this.inner.clone();
        let members = run(ruby, async move { group.checkpoints().await })?;
        let result = ruby.ary_new();
        for inner in members {
            result.push(RubySnapshotHandle { inner })?;
        }
        Ok(result)
    }

    fn get_checkpoint(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        member: String,
    ) -> Result<RubySnapshot, Error> {
        let group = this.inner.clone();
        Ok(RubySnapshot {
            inner: run(ruby, async move { group.get_checkpoint(member).await })?,
        })
    }

    fn set_head(ruby: &Ruby, this: typed_data::Obj<Self>, member: String) -> Result<RHash, Error> {
        let group = this.inner.clone();
        head_update(&run(ruby, async move { group.set_head(member).await })?)
    }

    fn clear_head(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RHash, Error> {
        let group = this.inner.clone();
        head_update(&run(ruby, async move { group.clear_head().await })?)
    }

    fn checkpoint(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        args: &[Value],
    ) -> Result<RubyCheckpointCaptureResult, Error> {
        let parsed = scan_args::<(), (), (), (), RHash, ()>(args)?;
        let options = capture_options(ruby, parsed.keywords, false)?;
        let group = this.inner.clone();
        Ok(RubyCheckpointCaptureResult {
            inner: run(
                ruby,
                async move { group.checkpoint_with(|_| options).await },
            )?,
        })
    }
}

impl RubySnapshot {
    pub(super) fn id(&self) -> String {
        self.inner.id().to_string()
    }

    pub(super) fn verify(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RHash, Error> {
        let checkpoint = this.inner.clone();
        let report = run(ruby, async move { checkpoint.verify().await })?;
        let result = ruby.hash_new();
        result.aset("digest", report.digest)?;
        result.aset("path", report.path.display().to_string())?;
        let upper = ruby.hash_new();
        match report.upper {
            UpperVerifyStatus::NotRecorded => upper.aset("kind", "not_recorded")?,
            UpperVerifyStatus::Verified { algorithm, digest } => {
                upper.aset("kind", "verified")?;
                upper.aset("algorithm", algorithm)?;
                upper.aset("digest", digest)?;
            }
        }
        result.aset("upper", upper)?;
        if let Some(checkpoint) = report.checkpoint {
            let state = ruby.hash_new();
            state.aset("kind", "verified")?;
            state.aset("root", checkpoint.root)?;
            result.aset("checkpoint", state)?;
        } else {
            result.aset("checkpoint", ruby.qnil())?;
        }
        let coverage = ruby.hash_new();
        match report.coverage {
            SnapshotVerifyCoverage::Complete => coverage.aset("kind", "complete")?,
            SnapshotVerifyCoverage::Incomplete { unrecorded } => {
                coverage.aset("kind", "incomplete")?;
                let paths = ruby.ary_new();
                for path in unrecorded {
                    paths.push(path.display().to_string())?;
                }
                coverage.aset("unrecorded", paths)?;
            }
        }
        result.aset("coverage", coverage)?;
        Ok(result)
    }
}

impl RubySnapshotHandle {
    pub(super) fn id(&self) -> String {
        self.inner.id().to_string()
    }
}

impl RubySandbox {
    pub(super) fn snapshot(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        args: &[Value],
    ) -> Result<RubySnapshotCreateResult, Error> {
        let parsed = scan_args::<(String,), (), (), (), RHash, ()>(args)?;
        let (name,) = parsed.required;
        let options = capture_options(ruby, parsed.keywords, true)?;
        let sandbox = this.inner_clone()?;
        Ok(RubySnapshotCreateResult {
            inner: run(ruby, async move {
                sandbox.snapshot_with(&name, |_| options).await
            })?,
        })
    }
}

impl RubySnapshotImportResult {
    fn operation_id(&self) -> String {
        self.inner.operation_id.clone()
    }
    fn snapshot(&self) -> RubyGroup {
        RubyGroup {
            inner: self.inner.snapshot.clone(),
        }
    }
    fn checkpoints(&self) -> Result<RArray, Error> {
        let result = current_ruby().ary_new();
        for inner in &self.inner.checkpoints {
            result.push(RubySnapshotHandle {
                inner: inner.clone(),
            })?;
        }
        Ok(result)
    }
    fn added(&self) -> Vec<String> {
        self.inner.added.iter().map(ToString::to_string).collect()
    }
    fn reused(&self) -> Vec<String> {
        self.inner.reused.iter().map(ToString::to_string).collect()
    }
    fn head_update(&self) -> Result<RHash, Error> {
        head_update(&self.inner.head_update)
    }
    fn warnings(&self) -> Vec<String> {
        self.inner.warnings.clone()
    }
}

impl RubySnapshotCreateResult {
    fn snapshot(&self) -> RubyGroup {
        RubyGroup {
            inner: self.inner.snapshot.clone(),
        }
    }
    fn checkpoint(&self) -> RubySnapshot {
        RubySnapshot {
            inner: self.inner.checkpoint.clone(),
        }
    }
    fn head_update(&self) -> Result<RHash, Error> {
        head_update(&self.inner.head_update)
    }
}

impl RubyCheckpointCaptureResult {
    fn checkpoint(&self) -> RubySnapshot {
        RubySnapshot {
            inner: self.inner.checkpoint.clone(),
        }
    }
    fn head_update(&self) -> Result<RHash, Error> {
        head_update(&self.inner.head_update)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn capture_options(
    ruby: &Ruby,
    keywords: RHash,
    initial: bool,
) -> Result<SnapshotCaptureOptions, Error> {
    let allowed = if initial {
        &[
            "initial_checkpoint",
            "dest_dir",
            "labels",
            "full",
            "record_integrity",
            "guest_flush",
        ][..]
    } else {
        &["name", "labels", "full", "record_integrity", "guest_flush"][..]
    };
    reject_unknown_keywords(ruby, keywords, allowed)?;
    let mut options = SnapshotCaptureOptions::default();
    if let Some(name) = keyword::<String>(
        keywords,
        if initial {
            "initial_checkpoint"
        } else {
            "name"
        },
    )? {
        options = options.name(name);
    }
    if let Some(dest) = keyword::<String>(keywords, "dest_dir")? {
        options = options.dest_dir(dest);
    }
    if keyword::<bool>(keywords, "full")?.unwrap_or(false) {
        options = options.full();
    }
    if keyword::<bool>(keywords, "record_integrity")?.unwrap_or(false) {
        options = options.record_integrity();
    }
    if let Some(policy) = keyword::<String>(keywords, "guest_flush")? {
        options = options.guest_flush(match policy.as_str() {
            "auto" => microsandbox_core::snapshot::GuestFlush::Auto,
            "required" => microsandbox_core::snapshot::GuestFlush::Required,
            "skip" => microsandbox_core::snapshot::GuestFlush::Skip,
            _ => {
                return Err(argument_error(
                    ruby,
                    "guest_flush must be auto, required, or skip",
                ));
            }
        });
    }
    if let Some(labels) = keywords.get(symbol("labels")) {
        for (key, value) in string_map(labels, "labels")? {
            options = options.label(key, value);
        }
    }
    Ok(options)
}

pub(super) fn head_update(update: &microsandbox_core::HeadUpdate) -> Result<RHash, Error> {
    let hash = current_ruby().hash_new();
    hash.aset("group", update.group.as_str())?;
    hash.aset("head", update.head.as_deref())?;
    hash.aset("previous", update.previous.as_deref())?;
    hash.aset("changed", update.changed)?;
    let reason = serde_json::to_value(update.reason)
        .map_err(|error| argument_error(&current_ruby(), error.to_string()))?;
    hash.aset("reason", reason.as_str())?;
    Ok(hash)
}

/// Success and failure use the same report projection, retaining all per-member findings.
pub(super) fn verification_report(
    ruby: &Ruby,
    report: &microsandbox_core::snapshot::SnapshotGroupVerifyReport,
) -> Result<RHash, Error> {
    ruby.require("json")?;
    let json: RModule = ruby.class_object().const_get("JSON")?;
    let payload =
        serde_json::to_string(report).map_err(|error| argument_error(ruby, error.to_string()))?;
    json.funcall("parse", (payload,))
}

pub(super) fn register(ruby: &Ruby, module: RModule) -> Result<(), Error> {
    let removed = module.define_class("CheckpointRemoveResult", ruby.class_object())?;
    removed.define_method("id", method!(RubyCheckpointRemoveResult::id, 0))?;
    removed.define_method(
        "head_update",
        method!(RubyCheckpointRemoveResult::head_update, 0),
    )?;
    removed.define_method("warnings", method!(RubyCheckpointRemoveResult::warnings, 0))?;
    let removed_group = module.define_class("SnapshotRemoveResult", ruby.class_object())?;
    removed_group.define_method("group", method!(RubySnapshotRemoveResult::group, 0))?;
    removed_group.define_method("removed", method!(RubySnapshotRemoveResult::removed, 0))?;
    removed_group.define_method(
        "head_update",
        method!(RubySnapshotRemoveResult::head_update, 0),
    )?;
    removed_group.define_method("warnings", method!(RubySnapshotRemoveResult::warnings, 0))?;
    let group = module.define_class("Snapshot", ruby.class_object())?;
    group.define_method("remove", method!(RubyGroup::remove, 0))?;
    group.define_singleton_method("load", function!(RubyGroup::load, -1))?;
    group.define_singleton_method("get", function!(RubyGroup::get, 1))?;
    group.define_singleton_method("list", function!(RubyGroup::list, 0))?;
    group.define_method("name", method!(RubyGroup::name, 0))?;
    group.define_method("head", method!(RubyGroup::head, 0))?;
    group.define_method("verify", method!(RubyGroup::verify, 0))?;
    group.define_method("info", method!(RubyGroup::inspect_info, 0))?;
    group.define_method("checkpoints", method!(RubyGroup::checkpoints, 0))?;
    group.define_method("get_checkpoint", method!(RubyGroup::get_checkpoint, 1))?;
    group.define_method("set_head", method!(RubyGroup::set_head, 1))?;
    group.define_method("clear_head", method!(RubyGroup::clear_head, 0))?;
    group.define_method("checkpoint", method!(RubyGroup::checkpoint, -1))?;
    let imported = module.define_class("SnapshotImportResult", ruby.class_object())?;
    imported.define_method(
        "operation_id",
        method!(RubySnapshotImportResult::operation_id, 0),
    )?;
    imported.define_method("snapshot", method!(RubySnapshotImportResult::snapshot, 0))?;
    imported.define_method(
        "checkpoints",
        method!(RubySnapshotImportResult::checkpoints, 0),
    )?;
    imported.define_method("added", method!(RubySnapshotImportResult::added, 0))?;
    imported.define_method("reused", method!(RubySnapshotImportResult::reused, 0))?;
    imported.define_method(
        "head_update",
        method!(RubySnapshotImportResult::head_update, 0),
    )?;
    imported.define_method("warnings", method!(RubySnapshotImportResult::warnings, 0))?;
    let initial = module.define_class("SnapshotCreateResult", ruby.class_object())?;
    initial.define_method("snapshot", method!(RubySnapshotCreateResult::snapshot, 0))?;
    initial.define_method(
        "checkpoint",
        method!(RubySnapshotCreateResult::checkpoint, 0),
    )?;
    initial.define_method(
        "head_update",
        method!(RubySnapshotCreateResult::head_update, 0),
    )?;
    let captured = module.define_class("CheckpointCaptureResult", ruby.class_object())?;
    captured.define_method(
        "checkpoint",
        method!(RubyCheckpointCaptureResult::checkpoint, 0),
    )?;
    captured.define_method(
        "head_update",
        method!(RubyCheckpointCaptureResult::head_update, 0),
    )?;
    Ok(())
}
