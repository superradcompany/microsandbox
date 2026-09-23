use microsandbox_types::{
    CpuPlacement, DnsConfig, EnvVar, SandboxResourcesPatch, SandboxRuntimeOptions,
    SandboxRuntimeOptionsPatch, SandboxSpec, SandboxSpecPatch, SecretEntry, SecretsConfig,
    SecretsConfigPatch, TransparentHugePagePolicy, VsockRouteSpec,
};

#[test]
fn builder_materializes_only_after_all_overlays() {
    let defaults = SandboxSpec::default();
    let config = SandboxSpecPatch::new()
        .name("example".into())
        .runtime(SandboxRuntimeOptionsPatch::new().workdir("/workspace".into()))
        .overlay(
            SandboxSpecPatch::new()
                .resources(SandboxResourcesPatch::new().cpus(1))
                .runtime(SandboxRuntimeOptionsPatch::new().set_workdir(None)),
        )
        .into_config();

    assert_eq!(config.name, "example");
    assert_eq!(config.resources.cpus, 1);
    assert_eq!(config.resources.memory_mib, defaults.resources.memory_mib);
    assert_eq!(config.resources.max_cpus, defaults.resources.max_cpus);
    assert_eq!(config.network.enabled, defaults.network.enabled);
    assert_eq!(config.runtime.workdir, None);
}

#[test]
fn complete_value_conversion_is_still_a_changeset() {
    let mut source = SandboxSpec {
        name: "source".into(),
        ..Default::default()
    };
    source.resources.cpus = 3;
    source.resources.max_cpus = 5;
    source.resources.memory_mib = 768;
    source.resources.max_memory_mib = 1536;
    source.resources.cpu_placement = CpuPlacement::Compact;
    source.resources.placement_profile = None;
    source.resources.thp = TransparentHugePagePolicy::Never;
    source.runtime.workdir = None;
    source.runtime.shell = Some("/bin/source".into());
    source
        .runtime
        .scripts
        .insert("source".into(), "echo source".into());
    source.env.push(EnvVar::new("SOURCE", "1"));
    source.labels.insert("source".into(), "true".into());
    source.vsock.routes.push(VsockRouteSpec {
        host_socket: "/tmp/source.sock".into(),
        port: 7000,
        socket_type: Default::default(),
    });
    source.lifecycle.ephemeral = true;
    source.lifecycle.max_duration_secs = None;

    let mut target = SandboxSpec {
        name: "target".into(),
        ..Default::default()
    };
    target.resources.placement_profile = Some("target-profile".into());
    target.runtime.workdir = Some("/target".into());
    target.env.push(EnvVar::new("TARGET", "1"));
    target.labels.insert("target".into(), "true".into());
    target.lifecycle.max_duration_secs = Some(60);

    SandboxSpecPatch::from(source).apply_to(&mut target);

    assert_eq!(target.name, "source");
    assert_eq!(target.resources.cpus, 3);
    assert_eq!(
        target.resources.placement_profile.as_deref(),
        Some("target-profile")
    );
    assert_eq!(target.runtime.workdir.as_deref(), Some("/target"));
    assert!(target.env.iter().any(|entry| entry.key == "TARGET"));
    assert!(target.env.iter().any(|entry| entry.key == "SOURCE"));
    assert_eq!(target.labels["target"], "true");
    assert_eq!(target.labels["source"], "true");
    assert_eq!(target.lifecycle.max_duration_secs, Some(60));
}

#[test]
fn absent_fields_preserve_lower_values_and_nested_patch_is_sparse() {
    let mut target = SandboxSpec::default();
    target.resources.placement_profile = Some("global-profile".into());
    target.runtime.workdir = Some("/global".into());
    target.lifecycle.max_duration_secs = Some(60);

    SandboxSpecPatch::from_present_fields(SandboxSpec::default()).apply_to(&mut target);

    assert_eq!(
        target.resources.placement_profile.as_deref(),
        Some("global-profile")
    );
    assert_eq!(target.runtime.workdir.as_deref(), Some("/global"));
    assert_eq!(target.lifecycle.max_duration_secs, Some(60));

    SandboxSpecPatch::new()
        .resources(SandboxResourcesPatch::new().cpus(4))
        .runtime(
            SandboxRuntimeOptionsPatch::new()
                .workdir("/discarded".into())
                .clear_workdir(),
        )
        .apply_to(&mut target);

    assert_eq!(target.resources.cpus, 4);
    assert_eq!(target.resources.memory_mib, 512);
    assert_eq!(target.runtime.workdir.as_deref(), Some("/global"));
}

#[test]
fn optional_nested_patch_preserves_unmentioned_and_cleared_changes() {
    let mut target = SandboxSpec::default();
    target.network.dns = Some(DnsConfig {
        rebind_protection: false,
        nameservers: vec!["1.1.1.1".into()],
        query_timeout_ms: 5000,
    });

    let mut patch = SandboxSpecPatch::new();
    patch.network.dns.get_or_insert_default().query_timeout_ms = Some(250);
    patch.apply_to(&mut target);

    let dns = target.network.dns.as_ref().unwrap();
    assert!(!dns.rebind_protection);
    assert_eq!(dns.nameservers, ["1.1.1.1"]);
    assert_eq!(dns.query_timeout_ms, 250);

    let mut patch = SandboxSpecPatch::new();
    patch.network.dns.get_or_insert_default().query_timeout_ms = Some(100);
    patch.network.dns = None;
    patch.apply_to(&mut target);
    assert_eq!(target.network.dns.as_ref().unwrap().query_timeout_ms, 250);
}

#[test]
fn declared_collection_strategies_merge_and_can_be_replaced() {
    let mut target = SandboxSpec {
        env: vec![EnvVar::new("KEEP", "lower"), EnvVar::new("CHANGE", "lower")],
        labels: [
            ("keep".into(), "lower".into()),
            ("change".into(), "lower".into()),
        ]
        .into(),
        runtime: SandboxRuntimeOptions {
            scripts: [
                ("keep".into(), "echo lower".into()),
                ("change".into(), "echo lower".into()),
            ]
            .into(),
            ..Default::default()
        },
        ..Default::default()
    };

    SandboxSpecPatch::new()
        .env(vec![
            EnvVar::new("CHANGE", "higher"),
            EnvVar::new("ADD", "higher"),
        ])
        .labels(
            [
                ("change".into(), "higher".into()),
                ("add".into(), "higher".into()),
            ]
            .into(),
        )
        .runtime(
            SandboxRuntimeOptionsPatch::new().scripts(
                [
                    ("change".into(), "echo higher".into()),
                    ("add".into(), "echo higher".into()),
                ]
                .into(),
            ),
        )
        .apply_to(&mut target);

    assert_eq!(
        target
            .env
            .iter()
            .map(|entry| (entry.key.as_str(), entry.value.as_str()))
            .collect::<Vec<_>>(),
        [("KEEP", "lower"), ("CHANGE", "higher"), ("ADD", "higher")]
    );
    assert_eq!(target.labels["keep"], "lower");
    assert_eq!(target.labels["change"], "higher");
    assert_eq!(target.labels["add"], "higher");
    assert_eq!(target.runtime.scripts["keep"], "echo lower");
    assert_eq!(target.runtime.scripts["change"], "echo higher");
    assert_eq!(target.runtime.scripts["add"], "echo higher");

    SandboxSpecPatch::new()
        .replace_env(vec![EnvVar::new("ONLY", "replacement")])
        .labels([("ignored".into(), "value".into())].into())
        .clear_labels()
        .runtime(
            SandboxRuntimeOptionsPatch::new()
                .replace_scripts([("only".into(), "echo replacement".into())].into()),
        )
        .apply_to(&mut target);

    assert_eq!(target.env.len(), 1);
    assert_eq!(target.env[0].key, "ONLY");
    assert_eq!(target.labels["keep"], "lower");
    assert_eq!(target.labels["change"], "higher");
    assert_eq!(target.labels["add"], "higher");
    assert_eq!(target.runtime.scripts.len(), 1);
    assert_eq!(target.runtime.scripts["only"], "echo replacement");
}

#[test]
fn secret_entries_merge_by_environment_variable_name() {
    let secret = |env_var: &str, placeholder: &str| -> SecretEntry {
        serde_json::from_value(serde_json::json!({
            "env_var": env_var,
            "placeholder": placeholder
        }))
        .unwrap()
    };
    let mut target = SecretsConfig {
        secrets: vec![
            secret("KEEP", "keep-lower"),
            secret("CHANGE", "change-lower"),
        ],
        ..Default::default()
    };

    SecretsConfigPatch::new()
        .secrets(vec![
            secret("CHANGE", "change-higher"),
            secret("ADD", "add-higher"),
        ])
        .apply_to(&mut target);

    assert_eq!(
        target
            .secrets
            .iter()
            .map(|entry| (entry.env_var.as_str(), entry.placeholder.as_str()))
            .collect::<Vec<_>>(),
        [
            ("KEEP", "keep-lower"),
            ("CHANGE", "change-higher"),
            ("ADD", "add-higher"),
        ]
    );

    SecretsConfigPatch::new()
        .secrets(vec![secret("IGNORED", "ignored")])
        .clear_secrets()
        .apply_to(&mut target);
    assert_eq!(target.secrets.len(), 3);
}

#[test]
fn deserialized_layers_reuse_overlay_and_apply_with_explicit_nulls() {
    use microsandbox_types::ConfigPatch;
    use serde::Deserialize;
    use std::collections::BTreeMap;

    #[derive(Debug, Clone, Default, ConfigPatch)]
    #[config_patch(serde)]
    struct Child {
        name: Option<String>,
        enabled: bool,
    }
    #[derive(Debug, Clone, Default, ConfigPatch)]
    #[config_patch(serde)]
    struct Settings {
        #[config_patch(nested)]
        child: Child,
        values: Vec<String>,
        #[config_patch(merge)]
        labels: BTreeMap<String, String>,
    }
    let mut target = Settings {
        child: Child {
            name: Some("original".into()),
            enabled: true,
        },
        ..Default::default()
    };
    let lower: SettingsPatch = serde_json::from_str(
        r#"{"child":{"name":"user"},"values":["user"],"labels":{"keep":"yes","replace":"user"}}"#,
    )
    .unwrap();
    let higher: SettingsPatch = serde_json::from_str(
        r#"{"child":{"name":null,"enabled":false},"values":[],"labels":{"replace":"admin"}}"#,
    )
    .unwrap();
    lower.overlay(higher).apply_to(&mut target);
    assert_eq!(target.child.name, None);
    assert!(!target.child.enabled);
    assert!(target.values.is_empty());
    assert_eq!(target.labels["keep"], "yes");
    assert_eq!(target.labels["replace"], "admin");
    let patch: ChildPatch = serde_json::from_str(r#"{"name":null}"#).unwrap();
    assert_eq!(patch.name, Some(None));
    assert!(serde_json::from_str::<ChildPatch>(r#"{"enabled":null}"#).is_err());
    assert!(
        serde_json::from_str::<SettingsPatch>(r#"{"child":{"unknown":1}}"#)
            .unwrap()
            .is_empty()
    );
    let mut target = Child {
        name: Some("keep".into()),
        enabled: true,
    };
    patch.clear_name().apply_to(&mut target);
    assert_eq!(target.name.as_deref(), Some("keep"));
    ChildPatch::from_present_fields(Child::default()).apply_to(&mut target);
    assert_eq!(target.name.as_deref(), Some("keep"));
    // Assert serde is implemented without requiring Deserialize on the original configuration.
    fn is_deserializable<T: for<'de> Deserialize<'de>>() {}
    is_deserializable::<SettingsPatch>();
}

#[test]
fn deserialized_patches_ignore_unknown_fields_and_validate_known_values() {
    use std::collections::BTreeMap;

    use microsandbox_types::ConfigPatch;

    #[derive(Debug, Clone, Default, serde::Deserialize, ConfigPatch)]
    #[config_patch(serde)]
    struct Child {
        #[serde(rename = "current", alias = "legacy")]
        name: Option<String>,
        enabled: bool,
    }

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    #[serde(tag = "mode", deny_unknown_fields)]
    enum Mode {
        Fixed { amount: u32 },
    }

    #[derive(Debug, Clone, Default, ConfigPatch)]
    #[config_patch(serde)]
    struct Settings {
        #[config_patch(nested)]
        child: Child,
        #[config_patch(nested, merge)]
        children: BTreeMap<String, Child>,
        mode: Option<Mode>,
    }

    let patch: SettingsPatch = serde_json::from_value(serde_json::json!({
        "unknown": true,
        "child": {"legacy": null, "unknown": true},
        "children": {
            "arbitrary-key": {"current": "kept", "enabled": false, "unknown": true}
        }
    }))
    .unwrap();
    assert_eq!(patch.child.name, Some(None));
    assert_eq!(patch.child.enabled, None);
    assert!(patch.mode.is_none());
    assert_eq!(
        serde_json::to_value(patch).unwrap(),
        serde_json::json!({
            "child": {"current": null},
            "children": {"arbitrary-key": {"current": "kept", "enabled": false}}
        })
    );

    for value in [
        serde_json::json!({"unknown": true}),
        serde_json::json!({"child": {"unknown": true}}),
        serde_json::json!({"children": {"entry": {"unknown": true}}}),
    ] {
        assert!(serde_json::from_value::<SettingsPatch>(value).is_ok());
    }

    for value in [
        serde_json::json!({"child": {"enabled": "yes"}}),
        serde_json::json!({"child": {"enabled": null}}),
        serde_json::json!({"child": {"current": "one", "legacy": "two"}}),
        serde_json::json!({"mode": {"mode": "Fixed", "amount": 1, "unknown": true}}),
        serde_json::json!({"mode": {"mode": "Unknown"}}),
    ] {
        assert!(serde_json::from_value::<SettingsPatch>(value).is_err());
    }
}

#[test]
fn serialized_patches_preserve_presence_and_config_field_shapes() {
    use microsandbox_types::ConfigPatch;
    use std::collections::BTreeMap;

    #[derive(Debug, Clone, Default, serde::Deserialize, ConfigPatch)]
    #[config_patch(serde)]
    struct Child {
        name: Option<String>,
        enabled: bool,
    }
    #[derive(Debug, Clone, Default, serde::Deserialize, ConfigPatch)]
    #[config_patch(serde)]
    struct Settings {
        #[config_patch(nested)]
        child: Child,
        #[serde(rename = "items", alias = "values")]
        values: Vec<String>,
        #[config_patch(merge)]
        labels: BTreeMap<String, String>,
    }

    assert_eq!(
        serde_json::to_value(SettingsPatch::new()).unwrap(),
        serde_json::json!({})
    );
    let expected =
        serde_json::json!({"child":{"name":null,"enabled":false},"items":[],"labels":{}});
    let patch: SettingsPatch = serde_json::from_value(expected.clone()).unwrap();
    assert_eq!(serde_json::to_value(&patch).unwrap(), expected);
    let loaded: SettingsPatch =
        serde_json::from_value(serde_json::to_value(patch).unwrap()).unwrap();
    assert_eq!(loaded.child.name, Some(None));
    assert_eq!(loaded.child.enabled, Some(false));
    assert_eq!(loaded.values, Some(Vec::new()));
    assert!(loaded.get_labels().unwrap().is_empty());

    let patch: SettingsPatch = serde_json::from_str(r#"{"values":["alias"]}"#).unwrap();
    assert_eq!(
        serde_json::to_value(patch).unwrap(),
        serde_json::json!({"items":["alias"]})
    );
    let patch =
        SettingsPatch::new().replace_labels(BTreeMap::from([("key".into(), "value".into())]));
    assert_eq!(
        serde_json::to_value(patch).unwrap(),
        serde_json::json!({"labels":{"key":"value"}})
    );
}

#[test]
fn mutable_nullable_setters_distinguish_clear_from_omission() {
    let mut runtime = SandboxRuntimeOptionsPatch::new();
    runtime
        .workdir_mut("/discarded".into())
        .set_workdir_mut(None)
        .set_shell_mut(None)
        .clear_shell_mut();
    let mut patch = SandboxSpecPatch::new();
    patch
        .image_mut(microsandbox_types::RootfsSource::oci("alpine:latest"))
        .runtime_mut(runtime)
        .replace_env_mut(vec![EnvVar::new("SOURCE", "builder")])
        .env_mut(vec![EnvVar::new("SOURCE", "higher")]);
    patch.resources.cpus = Some(2);
    let mut target = SandboxSpec::default();
    target.runtime.workdir = Some("/inherited".into());
    target.runtime.shell = Some("/bin/bash".into());
    target.env = vec![EnvVar::new("OLD", "discarded")];
    patch.apply_to(&mut target);
    assert_eq!(target.runtime.workdir, None);
    assert_eq!(target.runtime.shell.as_deref(), Some("/bin/bash"));
    assert_eq!(target.resources.cpus, 2);
    assert_eq!(target.env, vec![EnvVar::new("SOURCE", "higher")]);
    let microsandbox_types::RootfsSource::Oci(image) = target.image else {
        panic!("expected OCI rootfs");
    };
    assert_eq!(image.reference, "alpine:latest");
}
