//! Explicit destinations retained by Ruby collections, builders and resources.

use std::{cell::RefCell, sync::Arc};

use magnus::{Error, RModule, Ruby, Value, function, method, prelude::*, typed_data};
use microsandbox_core::snapshot::HeadUpdateReason;
use microsandbox_core::{Context, SnapshotBuilder};

use crate::{RubySandbox, RubySandboxBuilder, RubySnapshot, RubyVolume, RubyVolumeBuilder};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[magnus::wrap(class = "Microsandbox::Context", size)]
pub(crate) struct RubyContext {
    inner: Arc<dyn Context>,
}

#[magnus::wrap(class = "Microsandbox::Sandboxes", size)]
struct RubySandboxes {
    inner: Arc<dyn Context>,
}

#[magnus::wrap(class = "Microsandbox::Volumes", size)]
struct RubyVolumes {
    inner: Arc<dyn Context>,
}

#[magnus::wrap(class = "Microsandbox::Snapshots", size)]
struct RubySnapshots {
    inner: Arc<dyn Context>,
}

#[magnus::wrap(class = "Microsandbox::Checkpoints", size)]
struct RubyCheckpoints {
    inner: Arc<dyn Context>,
}

#[magnus::wrap(class = "Microsandbox::SnapshotBuilder", size)]
struct RubySnapshotBuilder {
    inner: RefCell<Option<SnapshotBuilder>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RubyContext {
    fn from_json(
        ruby: &Ruby,
        class: magnus::RClass,
        json: String,
    ) -> Result<typed_data::Obj<Self>, Error> {
        Ok(ruby.obj_wrap_as(
            Self {
                inner: microsandbox_core::context::from_options_json(&json)
                    .map_err(|e| crate::core_error(ruby, e))?,
            },
            class,
        ))
    }
    fn derive_from_json(
        ruby: &Ruby,
        class: magnus::RClass,
        base: &Self,
        json: String,
    ) -> Result<typed_data::Obj<Self>, Error> {
        let inner =
            microsandbox_core::context::derive_remote_from_options_json(base.inner.as_ref(), &json)
                .map_err(|e| crate::core_error(ruby, e))?;
        Ok(ruby.obj_wrap_as(Self { inner }, class))
    }

    fn info_json(ruby: &Ruby, this: &Self) -> Result<String, Error> {
        let info = this.inner.info().map_err(|e| crate::core_error(ruby, e))?;
        serde_json::to_string(&info)
            .map_err(|e| Error::new(ruby.exception_runtime_error(), e.to_string()))
    }

    fn kind(&self) -> magnus::Symbol {
        crate::symbol(match self.inner.kind() {
            microsandbox_core::ContextKind::Local => "local",
            microsandbox_core::ContextKind::Remote => "remote",
        })
    }
    fn sandboxes(&self) -> RubySandboxes {
        RubySandboxes {
            inner: self.inner.clone(),
        }
    }
    fn volumes(&self) -> RubyVolumes {
        RubyVolumes {
            inner: self.inner.clone(),
        }
    }
    fn snapshots(&self) -> RubySnapshots {
        RubySnapshots {
            inner: self.inner.clone(),
        }
    }
    fn checkpoints(&self) -> RubyCheckpoints {
        RubyCheckpoints {
            inner: self.inner.clone(),
        }
    }
}

impl RubySandboxes {
    fn context(&self) -> RubyContext {
        RubyContext {
            inner: self.inner.clone(),
        }
    }
    fn create(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        args: &[Value],
    ) -> Result<RubySandbox, Error> {
        crate::sandbox_create_in(this.inner.clone(), ruby, args)
    }
    fn connect_or_create(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        args: &[Value],
    ) -> Result<RubySandbox, Error> {
        crate::sandbox_connect_or_create_in(this.inner.clone(), ruby, args)
    }
    fn start(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        args: &[Value],
    ) -> Result<RubySandbox, Error> {
        crate::sandbox_start_in(this.inner.clone(), ruby, args)
    }
    fn get(ruby: &Ruby, this: typed_data::Obj<Self>, args: &[Value]) -> Result<RubySandbox, Error> {
        crate::sandbox_get_in(this.inner.clone(), ruby, args)
    }
    fn get_running(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        args: &[Value],
    ) -> Result<RubySandbox, Error> {
        crate::sandbox_get_running_in(this.inner.clone(), ruby, args)
    }
    fn remove(ruby: &Ruby, this: typed_data::Obj<Self>, args: &[Value]) -> Result<(), Error> {
        crate::sandbox_remove_in(this.inner.clone(), ruby, args)
    }
    fn list(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        args: &[Value],
    ) -> Result<magnus::RHash, Error> {
        crate::sandbox_list_in(this.inner.clone(), ruby, args)
    }
    fn builder(&self, name: String) -> RubySandboxBuilder {
        RubySandboxBuilder {
            inner: RefCell::new(Some(self.inner.sandboxes().builder(name))),
        }
    }
}

impl RubyVolumes {
    fn context(&self) -> RubyContext {
        RubyContext {
            inner: self.inner.clone(),
        }
    }
    fn get(ruby: &Ruby, this: typed_data::Obj<Self>, args: &[Value]) -> Result<RubyVolume, Error> {
        crate::volume_get_in(this.inner.clone(), ruby, args)
    }
    fn list(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        args: &[Value],
    ) -> Result<magnus::RArray, Error> {
        crate::volume_list_in(this.inner.clone(), ruby, args)
    }
    fn remove(ruby: &Ruby, this: typed_data::Obj<Self>, args: &[Value]) -> Result<(), Error> {
        crate::volume_remove_in(this.inner.clone(), ruby, args)
    }
    fn builder(&self, name: String) -> RubyVolumeBuilder {
        RubyVolumeBuilder {
            inner: RefCell::new(Some(self.inner.volumes().builder(name))),
        }
    }
}

impl RubySnapshots {
    fn load(
        ruby: &Ruby,
        this: &Self,
        args: &[Value],
    ) -> Result<crate::snapshot_group::RubySnapshotImportResult, Error> {
        crate::snapshot_group::load_in(ruby, this.inner.snapshots(), args)
    }

    fn get(
        ruby: &Ruby,
        this: &Self,
        name: String,
    ) -> Result<crate::snapshot_group::RubyGroup, Error> {
        let groups = this.inner.snapshots();
        Ok(crate::snapshot_group::RubyGroup {
            inner: crate::run(ruby, async move { groups.get(&name).await })?,
        })
    }

    fn list(ruby: &Ruby, this: &Self) -> Result<magnus::RArray, Error> {
        let groups = this.inner.snapshots();
        let values = crate::run(ruby, async move { groups.list().await })?;
        let result = ruby.ary_new_capa(values.len());
        for inner in values {
            result.push(crate::snapshot_group::RubyGroup { inner })?;
        }
        Ok(result)
    }

    fn open(
        ruby: &Ruby,
        this: &Self,
        path: String,
    ) -> Result<crate::snapshot_group::RubyGroup, Error> {
        let future = this.inner.snapshots().open(path);
        Ok(crate::snapshot_group::RubyGroup {
            inner: crate::run(ruby, future)?,
        })
    }
}

impl RubyCheckpoints {
    fn group_head(ruby: &Ruby, this: &Self, group: String) -> Result<Option<String>, Error> {
        let collection = this.inner.checkpoints();
        Ok(
            crate::run(ruby, async move { collection.group_head(&group).await })?
                .map(|id| id.to_string()),
        )
    }

    fn set_group_head(
        ruby: &Ruby,
        this: &Self,
        group: String,
        id: String,
    ) -> Result<magnus::RHash, Error> {
        let collection = this.inner.checkpoints();
        let id = microsandbox_core::snapshot::SnapshotId::new(id)
            .map_err(|e| crate::argument_error(ruby, e.to_string()))?;
        let update = crate::run(
            ruby,
            async move { collection.set_group_head(&group, &id).await },
        )?;
        let result = ruby.hash_new();
        result.aset("group", update.group)?;
        result.aset("previous", update.previous)?;
        result.aset("head", update.head)?;
        let reason = match update.reason {
            HeadUpdateReason::Initialized => "initialized",
            HeadUpdateReason::FastForwarded => "fast_forwarded",
            HeadUpdateReason::Cleared => "cleared",
            HeadUpdateReason::ParentSelected => "parent_selected",
            HeadUpdateReason::Selected => "selected",
            HeadUpdateReason::Unchanged => "unchanged",
            HeadUpdateReason::Diverged => "diverged",
            HeadUpdateReason::UnknownAncestry => "unknown_ancestry",
            HeadUpdateReason::AmbiguousCandidates => "ambiguous_candidates",
        };
        result.aset("reason", ruby.to_symbol(reason))?;
        result.aset("changed", update.changed)?;
        Ok(result)
    }

    fn context(&self) -> RubyContext {
        RubyContext {
            inner: self.inner.clone(),
        }
    }
    fn open(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        args: &[Value],
    ) -> Result<RubySnapshot, Error> {
        crate::snapshot_open_in(this.inner.clone(), ruby, args)
    }
    fn get(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        args: &[Value],
    ) -> Result<RubySnapshot, Error> {
        crate::snapshot_get_in(this.inner.clone(), ruby, args)
    }
    fn list(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        args: &[Value],
    ) -> Result<magnus::RArray, Error> {
        crate::snapshot_list_in(this.inner.clone(), ruby, args)
    }
    fn remove(ruby: &Ruby, this: typed_data::Obj<Self>, args: &[Value]) -> Result<(), Error> {
        crate::snapshot_remove_in(this.inner.clone(), ruby, args)
    }
    fn builder(&self, name: String) -> RubySnapshotBuilder {
        RubySnapshotBuilder {
            inner: RefCell::new(Some(self.inner.checkpoints().builder(name))),
        }
    }
}

impl RubySnapshotBuilder {
    fn update(
        this: typed_data::Obj<Self>,
        f: impl FnOnce(SnapshotBuilder) -> SnapshotBuilder,
    ) -> Result<typed_data::Obj<Self>, Error> {
        let builder = this.inner.borrow_mut().take().ok_or_else(|| {
            crate::argument_error(&crate::current_ruby(), "snapshot builder has been consumed")
        })?;
        *this.inner.borrow_mut() = Some(f(builder));
        Ok(this)
    }
    fn from_sandbox(
        this: typed_data::Obj<Self>,
        source: String,
    ) -> Result<typed_data::Obj<Self>, Error> {
        Self::update(this, |b| b.from_sandbox(source))
    }
    fn dest_dir(this: typed_data::Obj<Self>, path: String) -> Result<typed_data::Obj<Self>, Error> {
        Self::update(this, |b| b.dest_dir(path))
    }
    fn group(this: typed_data::Obj<Self>, group: String) -> Result<typed_data::Obj<Self>, Error> {
        Self::update(this, |b| b.group(group))
    }
    fn label(
        this: typed_data::Obj<Self>,
        key: String,
        value: String,
    ) -> Result<typed_data::Obj<Self>, Error> {
        Self::update(this, |b| b.label(key, value))
    }
    fn force(this: typed_data::Obj<Self>) -> Result<typed_data::Obj<Self>, Error> {
        Self::update(this, |b| b.force())
    }
    fn full(this: typed_data::Obj<Self>) -> Result<typed_data::Obj<Self>, Error> {
        Self::update(this, |b| b.full())
    }
    fn record_integrity(this: typed_data::Obj<Self>) -> Result<typed_data::Obj<Self>, Error> {
        Self::update(this, |b| b.record_integrity())
    }
    fn create(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RubySnapshot, Error> {
        let builder = this
            .inner
            .borrow_mut()
            .take()
            .ok_or_else(|| crate::argument_error(ruby, "snapshot builder has been consumed"))?;
        Ok(RubySnapshot {
            inner: crate::run(ruby, builder.create())?,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn sandbox_context(this: &RubySandbox) -> Result<RubyContext, Error> {
    Ok(RubyContext {
        inner: this.inner_clone()?.context().clone_shared(),
    })
}
fn volume_context(this: &RubyVolume) -> RubyContext {
    RubyContext {
        inner: this.inner.context().clone_shared(),
    }
}
fn snapshot_context(this: &RubySnapshot) -> RubyContext {
    RubyContext {
        inner: this.inner.context().clone_shared(),
    }
}
fn snapshot_builder(name: String) -> RubySnapshotBuilder {
    RubySnapshotBuilder {
        inner: RefCell::new(Some(microsandbox_core::Checkpoint::builder(name))),
    }
}
fn sandbox_ctx(context: &RubyContext) -> RubySandboxes {
    context.sandboxes()
}
fn volume_ctx(context: &RubyContext) -> RubyVolumes {
    context.volumes()
}
fn group_ctx(context: &RubyContext) -> RubySnapshots {
    context.snapshots()
}
fn group_context(this: &crate::snapshot_group::RubyGroup) -> RubyContext {
    RubyContext {
        inner: this.inner.context().clone_shared(),
    }
}
fn snapshot_ctx(context: &RubyContext) -> RubyCheckpoints {
    context.checkpoints()
}

fn configured_context(ruby: &Ruby) -> Result<typed_data::Obj<RubyContext>, Error> {
    let inner = microsandbox_core::resolve_context().map_err(|e| crate::core_error(ruby, e))?;
    let module: RModule = ruby.class_object().const_get("Microsandbox")?;
    let class: magnus::RClass = module.const_get(match inner.kind() {
        microsandbox_core::ContextKind::Local => "LocalContext",
        microsandbox_core::ContextKind::Remote => "RemoteContext",
    })?;
    Ok(ruby.obj_wrap_as(RubyContext { inner }, class))
}

pub(crate) fn register(ruby: &Ruby, module: RModule) -> Result<(), Error> {
    module.define_singleton_method("configured_context", function!(configured_context, 0))?;
    let context = module.define_class("Context", ruby.class_object())?;
    context.define_singleton_method("__from_json", method!(RubyContext::from_json, 1))?;
    context.define_singleton_method(
        "__derive_from_json",
        method!(RubyContext::derive_from_json, 2),
    )?;
    context.define_singleton_method(
        "inherited",
        function!(magnus::RClass::undef_default_alloc_func, 1),
    )?;
    context.define_method("__info_json", method!(RubyContext::info_json, 0))?;
    context.define_method("kind", method!(RubyContext::kind, 0))?;
    context.define_method("sandboxes", method!(RubyContext::sandboxes, 0))?;
    context.define_method("volumes", method!(RubyContext::volumes, 0))?;
    context.define_method("snapshots", method!(RubyContext::snapshots, 0))?;
    let groups = module.define_class("Snapshots", ruby.class_object())?;
    groups.define_method("get", method!(RubySnapshots::get, 1))?;
    groups.define_method("list", method!(RubySnapshots::list, 0))?;
    groups.define_method("load", method!(RubySnapshots::load, -1))?;
    let group_class: magnus::RClass = module.const_get("Snapshot")?;
    group_class.define_singleton_method("ctx", function!(group_ctx, 1))?;
    group_class.define_method("context", method!(group_context, 0))?;
    groups.define_method("open", method!(RubySnapshots::open, 1))?;
    context.define_method("checkpoints", method!(RubyContext::checkpoints, 0))?;
    let collection = module.define_class("Sandboxes", ruby.class_object())?;
    collection.define_method("context", method!(RubySandboxes::context, 0))?;
    collection.define_method("builder", method!(RubySandboxes::builder, 1))?;
    collection.define_method("create", method!(RubySandboxes::create, -1))?;
    collection.define_method(
        "connect_or_create",
        method!(RubySandboxes::connect_or_create, -1),
    )?;
    collection.define_method("start", method!(RubySandboxes::start, -1))?;
    collection.define_method("get", method!(RubySandboxes::get, -1))?;
    collection.define_method("get_running", method!(RubySandboxes::get_running, -1))?;
    collection.define_method("remove", method!(RubySandboxes::remove, -1))?;
    collection.define_method("list", method!(RubySandboxes::list, -1))?;
    let resource: magnus::RClass = module.const_get("Sandbox")?;
    resource.define_singleton_method("ctx", function!(sandbox_ctx, 1))?;
    resource.define_method("context", method!(sandbox_context, 0))?;
    let collection = module.define_class("Volumes", ruby.class_object())?;
    collection.define_method("context", method!(RubyVolumes::context, 0))?;
    collection.define_method("builder", method!(RubyVolumes::builder, 1))?;
    collection.define_method("get", method!(RubyVolumes::get, -1))?;
    collection.define_method("list", method!(RubyVolumes::list, -1))?;
    collection.define_method("remove", method!(RubyVolumes::remove, -1))?;
    let resource: magnus::RClass = module.const_get("Volume")?;
    resource.define_singleton_method("ctx", function!(volume_ctx, 1))?;
    resource.define_method("context", method!(volume_context, 0))?;
    let collection = module.define_class("Checkpoints", ruby.class_object())?;
    collection.define_method("context", method!(RubyCheckpoints::context, 0))?;
    collection.define_method("builder", method!(RubyCheckpoints::builder, 1))?;
    collection.define_method("open", method!(RubyCheckpoints::open, -1))?;
    collection.define_method("group_head", method!(RubyCheckpoints::group_head, 1))?;
    collection.define_method(
        "set_group_head",
        method!(RubyCheckpoints::set_group_head, 2),
    )?;
    collection.define_method("get", method!(RubyCheckpoints::get, -1))?;
    collection.define_method("list", method!(RubyCheckpoints::list, -1))?;
    collection.define_method("remove", method!(RubyCheckpoints::remove, -1))?;
    let resource: magnus::RClass = module.const_get("Checkpoint")?;
    resource.define_singleton_method("ctx", function!(snapshot_ctx, 1))?;
    resource.define_method("context", method!(snapshot_context, 0))?;
    resource.define_singleton_method("builder", function!(snapshot_builder, 1))?;
    let builder = module.define_class("SnapshotBuilder", ruby.class_object())?;
    builder.define_method(
        "from_sandbox",
        method!(RubySnapshotBuilder::from_sandbox, 1),
    )?;
    builder.define_method("dest_dir", method!(RubySnapshotBuilder::dest_dir, 1))?;
    builder.define_method("group", method!(RubySnapshotBuilder::group, 1))?;
    builder.define_method("label", method!(RubySnapshotBuilder::label, 2))?;
    builder.define_method("force", method!(RubySnapshotBuilder::force, 0))?;
    builder.define_method("full", method!(RubySnapshotBuilder::full, 0))?;
    builder.define_method(
        "record_integrity",
        method!(RubySnapshotBuilder::record_integrity, 0),
    )?;
    builder.define_method("create", method!(RubySnapshotBuilder::create, 0))?;
    Ok(())
}
