use std::path::PathBuf;

use super::*;
use crate::backend::{BackendSelectionSource, LocalBackend};
use crate::config::{GlobalConfig, PathsConfig, RegistriesConfig};

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn backend_paths_stay_bound_to_construction_directory() {
    const CHILD: &str = "MSB_TEST_BACKEND_PATH_CWD";
    if std::env::var_os(CHILD).is_none() {
        // Runtime overrides take precedence over the fixture's configured paths.
        // Clear them only in the child so CI settings cannot change its assertions.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("backend::local::config_paths::tests::backend_paths_stay_bound_to_construction_directory")
            .arg("--nocapture")
            .env(CHILD, "1")
            .env_remove("MSB_PATH")
            .env_remove("MSB_LIBKRUNFW_PATH")
            .env_remove("MSB_AGENTD_PATH")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("backend path lifetime checked"));
        return;
    }
    // All process-global cwd/environment mutations are isolated from other tests.
    let original_cwd = std::env::current_dir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let first = root.path().canonicalize().unwrap().join("first");
    let second = root.path().canonicalize().unwrap().join("second");
    std::fs::create_dir(&first).unwrap();
    std::fs::create_dir(&second).unwrap();
    std::env::set_current_dir(&first).unwrap();
    unsafe {
        std::env::set_var("MSB_HOME", "./ambient-home");
        std::env::set_var("MSB_CONFIG_PATH", root.path().join("missing-config.json"));
    }
    let ambient = LocalBackend::lazy().unwrap();
    let explicit = local_with_config(
        GlobalConfig {
            home: Some("./home".into()),
            paths: PathsConfig {
                msb: Some("./runtime/msb".into()),
                libkrunfw: Some("./runtime/libkrunfw".into()),
                agentd: Some("./runtime/agentd".into()),
                cache: Some("./cache".into()),
                sandboxes: Some("./sandboxes".into()),
                volumes: Some("./volumes".into()),
                snapshots: Some("./snapshots".into()),
                logs: Some("./logs".into()),
                secrets: Some("./secrets".into()),
            },
            registries: RegistriesConfig {
                ca_certs: Some("./cert.pem".into()),
                ..Default::default()
            },
            ..Default::default()
        },
        BackendSelectionSource::Programmatic,
        None,
    );
    let built = LocalBackend::builder()
        .home("./builder-home")
        .volumes_dir("./builder-volumes")
        .build_lazy()
        .unwrap();
    let names = |raw: &std::path::Path, normalized: &std::path::Path| {
        let new = microsandbox_utils::metrics_registry_shm_name(
            normalized,
            microsandbox_metrics::REGISTRY_ABI_VERSION,
        );
        let old = microsandbox_utils::metrics_registry_shm_name(
            raw,
            microsandbox_metrics::REGISTRY_ABI_VERSION,
        );
        if new == old {
            vec![new]
        } else {
            vec![new, old]
        }
    };
    assert_eq!(
        ambient.metrics_registry_names,
        names(
            std::path::Path::new("./ambient-home"),
            &first.join("ambient-home")
        )
    );
    assert_eq!(
        built.metrics_registry_names,
        names(
            std::path::Path::new("./builder-home"),
            &first.join("builder-home")
        )
    );
    // Persisted values use the document directory; programmatic arguments retain
    // the caller directory. Both remain stable after changing cwd.
    let persisted_path = root.path().join("persisted-config.json");
    std::fs::write(
        &persisted_path,
        r#"{"home":"./persisted-home","paths":{"cache":"./persisted-cache"}}"#,
    )
    .unwrap();
    unsafe {
        std::env::set_var("MSB_CONFIG_PATH", &persisted_path);
    }
    let persisted = LocalBackend::lazy().unwrap();
    assert_eq!(
        persisted.metrics_registry_names,
        names(
            std::path::Path::new("./persisted-home"),
            &root.path().join("persisted-home")
        )
    );
    crate::config::set_sdk_msb_path("./registered/msb");
    crate::config::set_sdk_libkrunfw_path("./registered/libkrunfw");
    crate::config::set_sdk_packaged_msb_path("./packaged/msb");
    std::env::set_current_dir(&second).unwrap();
    unsafe {
        std::env::set_var("MSB_HOME", "./different-home");
    }
    assert_eq!(
        persisted.config().home(),
        root.path().join("persisted-home")
    );
    assert_eq!(persisted.cache_dir(), root.path().join("persisted-cache"));
    assert_eq!(ambient.config().home(), first.join("ambient-home"));
    assert_eq!(
        ambient.config().volumes_dir(),
        first.join("ambient-home/volumes")
    );
    assert_eq!(built.config().home(), first.join("builder-home"));
    assert_eq!(
        built.volume_path("data"),
        first.join("builder-volumes/data")
    );
    let config = explicit.config();
    assert_eq!(config.home(), first.join("home"));
    for (actual, suffix) in [
        (config.paths.msb.as_ref().unwrap(), "runtime/msb"),
        (
            config.paths.libkrunfw.as_ref().unwrap(),
            "runtime/libkrunfw",
        ),
        (config.paths.agentd.as_ref().unwrap(), "runtime/agentd"),
        (config.paths.cache.as_ref().unwrap(), "cache"),
        (config.paths.sandboxes.as_ref().unwrap(), "sandboxes"),
        (config.paths.volumes.as_ref().unwrap(), "volumes"),
        (config.paths.snapshots.as_ref().unwrap(), "snapshots"),
        (config.paths.logs.as_ref().unwrap(), "logs"),
        (config.paths.secrets.as_ref().unwrap(), "secrets"),
        (config.registries.ca_certs.as_ref().unwrap(), "cert.pem"),
    ] {
        assert_eq!(actual, &first.join(suffix));
    }
    assert_eq!(
        crate::config::sdk_msb_path().unwrap(),
        Some(first.join("registered/msb"))
    );
    assert_eq!(
        crate::config::sdk_libkrunfw_path().unwrap(),
        Some(first.join("registered/libkrunfw"))
    );
    assert_eq!(
        crate::config::sdk_packaged_msb_path().unwrap(),
        Some(first.join("packaged/msb"))
    );
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            built.db().await.unwrap();
        });
    assert!(first.join("builder-home/db").is_dir());
    assert!(!second.join("builder-home").exists());
    std::env::set_current_dir(original_cwd).unwrap();
    println!("backend path lifetime checked");
}

#[cfg(unix)]
#[test]
fn unavailable_cwd_does_not_create_an_unanchored_backend() {
    const CHILD: &str = "MSB_TEST_BACKEND_MISSING_CWD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("backend::local::config_paths::tests::unavailable_cwd_does_not_create_an_unanchored_backend")
            .arg("--nocapture")
            .env(CHILD, "1")
            .output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("unavailable cwd checked"));
        return;
    }
    let original_cwd = std::env::current_dir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let cwd = root.path().join("removed");
    std::fs::create_dir(&cwd).unwrap();
    unsafe {
        std::env::set_var("MSB_CONFIG_PATH", root.path().join("missing-config.json"));
    }
    std::env::set_current_dir(&cwd).unwrap();
    std::fs::remove_dir(&cwd).unwrap();
    let error = LocalBackend::builder()
        .home("relative-home")
        .build_lazy()
        .err()
        .unwrap();
    assert!(
        error
            .to_string()
            .contains("cannot resolve relative local backend home")
    );
    let deferred = LocalBackend::builder().home("relative-home").build_lazy();
    assert!(deferred.is_err());
    // File-relative certificates do not require the deleted caller directory.
    let config_path = root.path().join("config.json");
    std::fs::write(
        &config_path,
        serde_json::to_vec(&serde_json::json!({
            "home": root.path().join("state"),
            "registries": {"ca_certs": "./company.pem"}
        }))
        .unwrap(),
    )
    .unwrap();
    unsafe {
        std::env::set_var("MSB_CONFIG_PATH", &config_path);
    }
    let from_file = LocalBackend::lazy().unwrap();
    assert_eq!(
        from_file.config().registries.ca_certs,
        Some(root.path().join("company.pem"))
    );
    unsafe {
        std::env::set_var("MSB_CONFIG_PATH", root.path().join("missing-config.json"));
    }

    // Absolute overrides do not need cwd and remain usable in this situation.
    let absolute = root.path().join("absolute-home");
    let backend = LocalBackend::builder()
        .home(&absolute)
        .build_lazy()
        .unwrap();
    assert_eq!(backend.config().home(), absolute);
    // Managed absolute paths win even when shadowed programmatic/environment
    // paths cannot be resolved. No operation should depend on those losing values.
    let managed = root.path().join("managed.json");
    std::fs::write(
        &managed,
        serde_json::to_vec(&serde_json::json!({
            "overrides": {"home": root.path().join("managed-home"),
                "paths": {"msb": root.path().join("managed-msb")}}
        }))
        .unwrap(),
    )
    .unwrap();
    unsafe {
        std::env::set_var("MSB_PATH", "./shadowed-runtime");
    }
    let enforced = LocalBackend::builder()
        .home("./shadowed-home")
        .managed_config_path(&managed)
        .build_lazy()
        .unwrap();
    assert_eq!(enforced.config().home(), root.path().join("managed-home"));
    assert_eq!(
        enforced.config().paths.msb,
        Some(root.path().join("managed-msb"))
    );
    unsafe {
        std::env::remove_var("MSB_PATH");
    }
    crate::config::set_sdk_msb_path("./missing-runtime");
    assert!(crate::config::sdk_msb_path().is_err());
    assert!(
        LocalBackend::builder()
            .home(root.path().join("absolute"))
            .build_lazy()
            .is_err()
    );
    std::env::set_current_dir(original_cwd).unwrap();
    println!("unavailable cwd checked");
}

#[test]
fn absolute_spelling_and_guest_defaults_are_preserved() {
    let home = std::env::current_dir().unwrap().join("missing/../home");
    let mut config = GlobalConfig {
        home: Some(home.clone()),
        ..Default::default()
    };
    config.sandbox_defaults.workdir = Some("./guest".into());
    resolve(&mut config).unwrap();
    assert_eq!(config.home, Some(home));
    assert_eq!(config.sandbox_defaults.workdir.as_deref(), Some("./guest"));
    assert_eq!(config.paths.msb, None::<PathBuf>);
}

// Programmatic settings use the same preparation as production constructors.
fn local_with_config(
    config: GlobalConfig,
    source: BackendSelectionSource,
    profile: Option<String>,
) -> LocalBackend {
    let config = crate::config::layers::BackendConfig::new(config.into(), Default::default())
        .prepare_for_local_backend(Default::default())
        .unwrap();
    LocalBackend::from_backend_config(config, source, profile)
}
