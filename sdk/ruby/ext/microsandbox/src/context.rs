//! Explicit destinations retained by Ruby collections, builders and resources.

use std::{cell::RefCell, sync::Arc};

use magnus::{Error, RModule, Ruby, Value, function, method, prelude::*, typed_data};
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
    fn kind(&self) -> &'static str {
        match self.inner.kind() {
            microsandbox_core::ContextKind::Local => "local",
            microsandbox_core::ContextKind::Remote => "remote",
        }
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
            inner: RefCell::new(Some(self.inner.snapshots().builder(name))),
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
        inner: RefCell::new(Some(microsandbox_core::Snapshot::builder(name))),
    }
}
fn sandbox_ctx(context: &RubyContext) -> RubySandboxes {
    context.sandboxes()
}
fn volume_ctx(context: &RubyContext) -> RubyVolumes {
    context.volumes()
}
fn snapshot_ctx(context: &RubyContext) -> RubySnapshots {
    context.snapshots()
}

pub(crate) fn register(ruby: &Ruby, module: RModule) -> Result<(), Error> {
    let context = module.define_class("Context", ruby.class_object())?;
    context.define_singleton_method("__from_json", method!(RubyContext::from_json, 1))?;
    context.define_singleton_method(
        "inherited",
        function!(magnus::RClass::undef_default_alloc_func, 1),
    )?;
    context.define_method("kind", method!(RubyContext::kind, 0))?;
    context.define_method("sandboxes", method!(RubyContext::sandboxes, 0))?;
    context.define_method("volumes", method!(RubyContext::volumes, 0))?;
    context.define_method("snapshots", method!(RubyContext::snapshots, 0))?;
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
    let collection = module.define_class("Snapshots", ruby.class_object())?;
    collection.define_method("context", method!(RubySnapshots::context, 0))?;
    collection.define_method("builder", method!(RubySnapshots::builder, 1))?;
    collection.define_method("open", method!(RubySnapshots::open, -1))?;
    collection.define_method("get", method!(RubySnapshots::get, -1))?;
    collection.define_method("list", method!(RubySnapshots::list, -1))?;
    collection.define_method("remove", method!(RubySnapshots::remove, -1))?;
    let resource: magnus::RClass = module.const_get("Snapshot")?;
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
