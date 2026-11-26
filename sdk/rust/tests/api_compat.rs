#[test]
fn creation_futures_remain_small_for_concurrent_callers() {
    let future = microsandbox::Sandbox::builder("stack-probe").create();
    let detached = microsandbox::Sandbox::builder("stack-probe").create_detached();
    for bytes in [
        std::mem::size_of_val(&future),
        std::mem::size_of_val(&detached),
    ] {
        assert!(
            bytes < 16 * 1024,
            "create state must not inflate every caller's async stack: {bytes} bytes"
        );
    }
}

#[test]
#[cfg(feature = "local")]
fn rust_root_compat_exports_stay_available() {
    // Compile-time tripwire for public root exports restored after the
    // backend-routing refactor. The function items are not invoked.
    let _ = microsandbox::Image::get;
    let _ = microsandbox::Image::list;
    let _ = microsandbox::Image::inspect;
    let _ = microsandbox::Image::remove;
    let _ = microsandbox::Image::prune;
    let _ = microsandbox::all_sandbox_metrics;

    let _: Option<microsandbox::ImagePruneReport> = None;
    let _: Option<microsandbox::SandboxMetrics> = None;
}

#[test]
#[cfg(feature = "local")]
fn rust_config_and_runtime_setup_surface_stays_available() {
    let _ = microsandbox::setup::resolve_runtime;
    let _ = microsandbox::setup::install_runtime;
    let _ = microsandbox::setup::ensure_runtime;
    let _: Option<microsandbox::setup::ResolvedRuntime> = None;
    let _: Option<microsandbox::setup::InstallOptions> = None;
    let _ = microsandbox::config::config;
    let _ = microsandbox::config::resolve_msb_path;
    let _ = microsandbox::config::resolve_libkrunfw_path;
    let _ = microsandbox::config::GlobalConfig::resolve_msb_path;
    let _ = microsandbox::config::GlobalConfig::resolve_libkrunfw_path;

    #[allow(deprecated)]
    let _: Option<microsandbox::config::LocalConfig> = None;
}

#[cfg(feature = "ssh")]
#[test]
fn rust_ssh_compat_export_stays_available() {
    let _: Option<microsandbox::SandboxSshOps> = None;
}

#[test]
fn rust_identity_and_generated_patch_surface_is_backend_neutral() {
    use microsandbox::sandbox::{DestroyOptions, RestartOptions, SandboxId, SandboxRecord};

    let _: Option<SandboxId> = None;
    let _ = SandboxRecord::id;
    let _ = SandboxRecord::connect_or_start;
    let _ = SandboxRecord::wait_for_status;
    let _ = SandboxRecord::restart;
    let _ = SandboxRecord::destroy;
    let _ = (RestartOptions::default(), DestroyOptions::default());
    let _ = microsandbox::SandboxConfigPatch::new().spec(
        microsandbox::SandboxSpecPatch::new()
            .resources(microsandbox::SandboxResourcesPatch::new().cpus(2)),
    );
}

#[test]
fn rust_service_surface_stays_available() {
    use microsandbox::{
        ChangeState, MicrosandboxError, Operation, Service, ServiceBuilder, ServiceError,
        ServiceListBuilder, ServiceOps, ServicePage, ServiceTarget, ServiceUpdate,
    };

    let _ = Service::get;
    let _ = Service::list;
    let _ = Service::refresh;
    let _ = Service::remove;
    let _: ServiceBuilder = Service::builder("shop").target("web-1", 8080);
    let _ = Service::enable;
    let _ = Service::disable;
    let _ = ServiceUpdate::default().target("web-1", 8080);
    let _ = ServiceListBuilder::default()
        .sandbox("web-1")
        .cursor("c2hvcA")
        .limit(20);
    let _: Option<(ServicePage, ServiceTarget, &dyn ServiceOps)> = None;
    let _ = [
        Operation::ServiceCreate,
        Operation::ServiceGet,
        Operation::ServiceList,
        Operation::ServiceUpdate,
        Operation::ServiceEnable,
        Operation::ServiceDisable,
        Operation::ServiceRemove,
    ];

    let error = MicrosandboxError::Service {
        slug: "shop".into(),
        error: ServiceError::OutcomeUnknown,
    };
    assert_eq!(error.changed(), ChangeState::Unknown);
    let reason = ServiceError::Other {
        code: "new_service_refusal".into(),
        status: 409,
        message: "change refused".into(),
    };
    assert_eq!(reason.changed(), ChangeState::Unchanged);
}

#[allow(dead_code)]
async fn rust_sandbox_fs_handle_api_stays_available(
    fs: &microsandbox::sandbox::SandboxFsOps,
    entry: microsandbox::sandbox::FsEntry,
    metadata: microsandbox::sandbox::FsMetadata,
) -> microsandbox::MicrosandboxResult<()> {
    use microsandbox::sandbox::{FsHandle, FsOpenOptions, FsSetAttrs};

    let _: Option<FsHandle> = None;
    let file = fs.open_file("/tmp/file", FsOpenOptions::default()).await?;
    let dir = fs.open_dir("/tmp").await?;

    let _ = fs.read_handle(&file, 0, None).await?;
    let mut read_stream = fs.read_handle_stream(&file, 0, Some(1)).await?;
    let _ = read_stream.recv().await?;

    fs.write_handle(&file, 0, b"hello").await?;
    let write_stream = fs.write_handle_stream(&file, 0, None).await?;
    write_stream.close().await?;

    let _ = fs.read_dir_handle(&dir, None).await?;
    let _ = fs.read_dir(&dir, None).await?;

    let _ = fs.stat_handle(&file).await?;
    let _ = fs.fstat(&file).await?;
    fs.set_stat_handle(&file, FsSetAttrs::default()).await?;
    fs.fset_stat(&file, FsSetAttrs::default()).await?;

    let _ = fs.real_path(".").await?;
    fs.remove_empty_dir("/tmp/empty").await?;
    fs.close_handle(file).await?;
    fs.close_handle(dir).await?;

    let _ = (entry.uid, entry.gid, entry.accessed);
    let _ = (metadata.uid, metadata.gid, metadata.accessed);

    Ok(())
}

#[test]
fn boot_error_reason_is_preserved_in_every_backend_build() {
    use microsandbox::logs::{BootError, InitFailureReason};

    for (wire, expected) in [
        (
            Some("user_not_found"),
            Some(InitFailureReason::UserNotFound),
        ),
        (
            Some("group_not_found"),
            Some(InitFailureReason::GroupNotFound),
        ),
        (Some("future_reason"), Some(InitFailureReason::Unknown)),
        (None, None),
    ] {
        let mut record = serde_json::json!({
            "t": "2026-10-03T00:00:00Z",
            "stage": "config",
            "errno": null,
            "message": "guest initialization failed",
        });
        if let Some(wire) = wire {
            record["reason"] = wire.into();
        }
        let error: BootError = serde_json::from_value(record).unwrap();
        assert_eq!(error.reason, expected);
        let encoded = serde_json::to_value(&error).unwrap();
        if wire.is_none() {
            assert!(encoded.get("reason").is_none());
        } else {
            assert_eq!(encoded["reason"], serde_json::to_value(expected).unwrap());
        }
    }
}

#[test]
#[cfg(feature = "cloud")]
fn rust_modify_surface_is_available_on_cloud_builds() {
    let _ = microsandbox::Sandbox::modify;
    let _ = microsandbox::sandbox::SandboxRecord::modify;
    let _ = microsandbox::SandboxModificationBuilder::dry_run;
    let _ = microsandbox::SandboxModificationBuilder::apply;
    let _: Option<microsandbox::SandboxModificationPlan> = None;
    let not_confirmed = microsandbox::MicrosandboxError::ModificationNotConfirmed {
        cause: "the running sandbox does not hold the secret".into(),
    };
    assert_eq!(
        not_confirmed.to_string(),
        "the change did not complete as asked: the running sandbox does not hold the secret"
    );
}

#[test]
#[cfg(any(feature = "local", feature = "cloud"))]
fn provider_binding_lifecycle_surface_stays_available() {
    use microsandbox::sandbox::{
        DEFAULT_RESIZE_READ_TIMEOUT, ResizeOperation, SandboxModificationBuilder,
        SandboxModificationResult, SandboxRecord,
    };
    use microsandbox::{Checkpoint, Sandbox, Snapshot};

    // Native SDKs use this same API in both lean provider builds. A workspace
    // build can unify `local` into a remote crate and hide missing exports.
    let _: Option<(ResizeOperation, SandboxModificationResult)> = None;
    assert!(!DEFAULT_RESIZE_READ_TIMEOUT.is_zero());
    let _ = SandboxModificationBuilder::apply_with_resize_tracking;
    let _ = Sandbox::resize_status;
    let _ = Sandbox::resize_operations;
    let _ = Sandbox::wait_for_resize_operations;
    let _ = Sandbox::wait_until_resized;
    let _ = Sandbox::wait_until_resized_with_timeout;
    let _ = SandboxRecord::resize_status;
    let _ = SandboxRecord::resize_operations;
    let _ = SandboxRecord::wait_for_resize_operations;
    let _ = SandboxRecord::check_resize_operations_with_budget;
    let _ = SandboxRecord::wait_until_resized;
    let _ = SandboxRecord::wait_until_resized_with_timeout;
    let _ = Checkpoint::spawn_sandbox_with_progress;
    let _ = Snapshot::spawn_sandbox_with_progress;
}

#[test]
#[cfg(feature = "local")]
fn registry_and_image_metadata_keep_released_struct_literals() {
    let _ = microsandbox::config::RegistryOptions {
        auth: None,
        insecure: false,
        ca_certs: Vec::new(),
        ca_cert_files: Vec::new(),
    };
    let _ = microsandbox_image::CachedImageMetadata {
        manifest_digest: String::new(),
        config_digest: String::new(),
        raw_manifest_json: String::new(),
        raw_config_json: String::new(),
        config: microsandbox_image::ImageConfig::default(),
        layers: Vec::new(),
    };
}
