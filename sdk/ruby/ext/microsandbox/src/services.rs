//! Ruby bindings for the cloud Service resource.

use std::cell::RefCell;

use magnus::{
    Error, RHash, Ruby, Value, function, method, prelude::*, scan_args::scan_args, typed_data,
};
use microsandbox_core::{Service, ServiceBuilder, ServicePage, ServiceStatus, ServiceTarget};

use crate::{
    current_ruby, keyword, reject_unknown_keywords, required_keyword, run, run_service_change,
    symbol,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[magnus::wrap(class = "Microsandbox::Service", free_immediately, size)]
struct RubyService {
    inner: Service,
}

#[magnus::wrap(class = "Microsandbox::ServiceBuilder", free_immediately, size)]
struct RubyServiceBuilder {
    inner: RefCell<Option<ServiceBuilder>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RubyService {
    fn slug(&self) -> String {
        self.inner.slug().to_owned()
    }

    fn url(&self) -> String {
        self.inner.url().to_owned()
    }

    fn status(&self) -> &'static str {
        match self.inner.status() {
            ServiceStatus::Enabled => "enabled",
            ServiceStatus::Disabled => "disabled",
            ServiceStatus::Detached => "detached",
            ServiceStatus::Unknown => "unknown",
        }
    }

    fn target(ruby: &Ruby, this: &Self) -> Result<Option<RHash>, Error> {
        this.inner
            .target()
            .map(|target| {
                let value = ruby.hash_new();
                value.aset("sandbox", target.sandbox)?;
                value.aset("port", target.port)?;
                Ok(value)
            })
            .transpose()
    }

    fn created_at(&self) -> String {
        self.inner.created_at().to_rfc3339()
    }

    fn updated_at(&self) -> String {
        self.inner.updated_at().to_rfc3339()
    }

    fn update(
        ruby: &Ruby,
        this: typed_data::Obj<Self>,
        args: &[Value],
    ) -> Result<RubyService, Error> {
        let parsed = scan_args::<(), (), (), (), RHash, ()>(args)?;
        reject_unknown_keywords(ruby, parsed.keywords, &["target"])?;
        let target = required_target(ruby, parsed.keywords)?;
        let service = this.inner.clone();
        let inner = run_service_change(ruby, async move {
            service
                .update(|mut update| {
                    if let Some(target) = target {
                        update = update.target(target.sandbox, target.port);
                    }
                    update
                })
                .await
        })?;
        Ok(RubyService { inner })
    }

    fn enable(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RubyService, Error> {
        let service = this.inner.clone();
        let inner = run_service_change(ruby, async move { service.enable().await })?;
        Ok(RubyService { inner })
    }

    fn disable(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RubyService, Error> {
        let service = this.inner.clone();
        let inner = run_service_change(ruby, async move { service.disable().await })?;
        Ok(RubyService { inner })
    }

    fn remove(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<(), Error> {
        let service = this.inner.clone();
        run_service_change(ruby, async move { service.remove().await })
    }

    fn refresh(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RubyService, Error> {
        let service = this.inner.clone();
        let inner = run(ruby, async move { service.refresh().await })?;
        Ok(RubyService { inner })
    }
}

impl RubyServiceBuilder {
    fn target(
        this: typed_data::Obj<Self>,
        sandbox: String,
        port: u16,
    ) -> Result<typed_data::Obj<Self>, Error> {
        let builder = take_builder(&this)?;
        *this.inner.borrow_mut() = Some(builder.target(sandbox, port));
        Ok(this)
    }

    fn create(ruby: &Ruby, this: typed_data::Obj<Self>) -> Result<RubyService, Error> {
        let builder = take_builder(&this)?;
        let inner = run_service_change(ruby, builder.create())?;
        Ok(RubyService { inner })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn take_builder(this: &RubyServiceBuilder) -> Result<ServiceBuilder, Error> {
    this.inner.borrow_mut().take().ok_or_else(|| {
        Error::new(
            current_ruby().exception_runtime_error(),
            "builder has been consumed",
        )
    })
}

fn service_builder(slug: String) -> RubyServiceBuilder {
    RubyServiceBuilder {
        inner: RefCell::new(Some(Service::builder(slug))),
    }
}

fn required_target(ruby: &Ruby, keywords: RHash) -> Result<Option<ServiceTarget>, Error> {
    if keywords.get(symbol("target")).is_none() {
        let _: Value = required_keyword(keywords, "target", ruby)?;
    }
    keyword::<Value>(keywords, "target")?
        .map(|target| {
            Ok(ServiceTarget {
                sandbox: target.funcall("sandbox", ())?,
                port: target.funcall("port", ())?,
            })
        })
        .transpose()
}

fn service_create(ruby: &Ruby, args: &[Value]) -> Result<RubyService, Error> {
    let parsed = scan_args::<(String,), (), (), (), RHash, ()>(args)?;
    reject_unknown_keywords(ruby, parsed.keywords, &["target"])?;
    let target = required_target(ruby, parsed.keywords)?;
    let mut builder = Service::builder(parsed.required.0);
    if let Some(target) = target {
        builder = builder.target(target.sandbox, target.port);
    }
    let inner = run_service_change(ruby, builder.create())?;
    Ok(RubyService { inner })
}

fn service_get(ruby: &Ruby, args: &[Value]) -> Result<RubyService, Error> {
    let parsed = scan_args::<(String,), (), (), (), RHash, ()>(args)?;
    reject_unknown_keywords(ruby, parsed.keywords, &[])?;
    let slug = parsed.required.0;
    let inner = run(ruby, async move { Service::get(&slug).await })?;
    Ok(RubyService { inner })
}

fn service_list(ruby: &Ruby, args: &[Value]) -> Result<RHash, Error> {
    let parsed = scan_args::<(), (), (), (), RHash, ()>(args)?;
    reject_unknown_keywords(ruby, parsed.keywords, &["sandbox", "cursor", "limit"])?;
    let sandbox = keyword::<String>(parsed.keywords, "sandbox")?;
    let cursor = keyword::<String>(parsed.keywords, "cursor")?;
    let limit = keyword::<u32>(parsed.keywords, "limit")?;
    let page = run(
        ruby,
        Service::list_with(move |mut list| {
            if let Some(sandbox) = sandbox {
                list = list.sandbox(sandbox);
            }
            if let Some(cursor) = cursor {
                list = list.cursor(cursor);
            }
            if let Some(limit) = limit {
                list = list.limit(limit);
            }
            list
        }),
    )?;
    page_hash(ruby, page)
}

fn page_hash(ruby: &Ruby, page: ServicePage) -> Result<RHash, Error> {
    let services = ruby.ary_new_capa(page.services.len());
    for inner in page.services {
        services.push(RubyService { inner })?;
    }
    let hash = ruby.hash_new();
    hash.aset("services", services)?;
    hash.aset("next_cursor", page.next_cursor)?;
    Ok(hash)
}

pub(crate) fn init(ruby: &Ruby, module: magnus::RModule) -> Result<(), Error> {
    let service = module.define_class("Service", ruby.class_object())?;
    service.define_singleton_method("builder", function!(service_builder, 1))?;
    service.define_singleton_method("create", function!(service_create, -1))?;
    service.define_singleton_method("get", function!(service_get, -1))?;
    service.define_singleton_method("list", function!(service_list, -1))?;
    service.define_method("slug", method!(RubyService::slug, 0))?;
    service.define_method("url", method!(RubyService::url, 0))?;
    service.define_method("status", method!(RubyService::status, 0))?;
    service.define_method("_target", method!(RubyService::target, 0))?;
    service.define_method("created_at", method!(RubyService::created_at, 0))?;
    service.define_method("updated_at", method!(RubyService::updated_at, 0))?;
    service.define_method("update", method!(RubyService::update, -1))?;
    service.define_method("enable", method!(RubyService::enable, 0))?;
    service.define_method("disable", method!(RubyService::disable, 0))?;
    service.define_method("remove", method!(RubyService::remove, 0))?;
    service.define_method("refresh", method!(RubyService::refresh, 0))?;

    let builder = module.define_class("ServiceBuilder", ruby.class_object())?;
    builder.define_method("target", method!(RubyServiceBuilder::target, 2))?;
    builder.define_method("create", method!(RubyServiceBuilder::create, 0))?;

    Ok(())
}
