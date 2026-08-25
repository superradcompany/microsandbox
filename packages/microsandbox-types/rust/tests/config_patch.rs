use microsandbox_types::{
    CpuPlacement, DnsConfig, EnvVar, NetworkSpecPatch, SandboxConfigPatch, SandboxResourcesPatch,
    SandboxRuntimeOptions, SandboxRuntimeOptionsPatch, SandboxSpec, SecretEntry, SecretsConfig,
    SecretsConfigPatch, TransparentHugePagePolicy, VsockRouteSpec,
};

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

    SandboxConfigPatch::from(source).apply_to(&mut target);

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

    SandboxConfigPatch::from_present_fields(SandboxSpec::default()).apply_to(&mut target);

    assert_eq!(
        target.resources.placement_profile.as_deref(),
        Some("global-profile")
    );
    assert_eq!(target.runtime.workdir.as_deref(), Some("/global"));
    assert_eq!(target.lifecycle.max_duration_secs, Some(60));

    SandboxConfigPatch::new()
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

    SandboxConfigPatch::new()
        .network(NetworkSpecPatch::new().modify_dns(|dns| dns.query_timeout_ms(250)))
        .apply_to(&mut target);

    let dns = target.network.dns.as_ref().unwrap();
    assert!(!dns.rebind_protection);
    assert_eq!(dns.nameservers, ["1.1.1.1"]);
    assert_eq!(dns.query_timeout_ms, 250);

    SandboxConfigPatch::new()
        .network(
            NetworkSpecPatch::new()
                .modify_dns(|dns| dns.query_timeout_ms(100))
                .clear_dns(),
        )
        .apply_to(&mut target);
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

    SandboxConfigPatch::new()
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

    SandboxConfigPatch::new()
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
