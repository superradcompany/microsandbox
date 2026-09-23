//! Restore a snapshot into a detached sandbox with explicit host resource bindings.

use clap::Args;
use microsandbox::sandbox::{
    BranchBuilder, BranchManyBuilder, RestoreBuilder, Sandbox, SecurityProfile,
};

#[cfg(feature = "net")]
use super::common::parse_port_mapping;
use super::common::{display_restore_warnings, parse_restore_volume, parse_vsock_route};
use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Restore an installed snapshot or archive into a new sandbox.
#[derive(Debug, Args)]
pub struct RestoreArgs {
    /// Snapshot group/member, ID, or archive path.
    pub snapshot: String,
    /// Unique name of the destination sandbox.
    #[arg(short, long)]
    pub name: String,
    /// Restore captured RAM using private copy-on-write mappings.
    #[arg(long, conflicts_with = "disk_only")]
    pub forked: bool,
    /// Cold-boot only the captured disk, without restoring processes or RAM.
    #[arg(long)]
    pub disk_only: bool,
    /// Exact base snapshot or archive for a dependent export.
    #[arg(long)]
    pub snapshot_base: Option<String>,
    /// Allow missing full-restore resources with warnings instead of refusing activation.
    #[arg(long)]
    pub allow_missing_resources: bool,
    /// Destination resource bindings.
    #[command(flatten)]
    pub resources: RestoreResourceArgs,
    /// Destination controls applied before the restored workload can run.
    #[command(flatten)]
    pub controls: RestoreControlArgs,
    /// Suppress progress output, but not unavailable-resource warnings.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Resource choices shared by restore and branch, separate from fresh-boot configuration.
#[derive(Debug, Args)]
pub struct RestoreResourceArgs {
    /// Bind a host socket/named pipe to a guest-to-host vsock port: PATH:PORT[/stream|/dgram].
    #[arg(long)]
    pub vsock: Vec<String>,
    /// Map `SOURCE:GUEST[:OPTIONS]`, or select a captured private disk with GUEST alone.
    #[arg(short, long, value_name = "SOURCE:GUEST|GUEST")]
    pub volume: Vec<String>,
    /// Publish a child listener: `[BIND:]HOST:GUEST[/tcp|udp]`.
    #[cfg(feature = "net")]
    #[arg(short, long)]
    pub port: Vec<String>,
    /// Default user for new exec commands; captured processes keep their credentials.
    #[arg(short, long)]
    pub user: Option<String>,
    /// Validate explicitly mapped filesystems strictly or allow supported stale resources.
    #[arg(long, value_parser = ["strict", "relaxed"])]
    pub external_mount_policy: Option<String>,
    /// Fill unspecified bindings from validated source-local records; may share host resources.
    #[arg(long)]
    pub dangerously_inherit_resources: bool,
}

/// Destination policy and geometry controls, separate from captured host-resource bindings.
#[derive(Debug, Default, Args)]
pub struct RestoreControlArgs {
    /// Guest CPU count for disk boot; full restore requires the captured count.
    #[arg(short = 'c', long)]
    pub cpus: Option<u8>,
    /// Guest memory for disk boot; full restore requires the captured size.
    #[arg(short = 'm', long, value_name = "SIZE")]
    pub memory: Option<String>,
    /// Guest security profile for disk boot; rejected for full execution restore.
    #[arg(long, value_parser = ["default", "restricted"])]
    pub security: Option<String>,
    /// Maximum lifetime of the destination sandbox (e.g. 30s, 5m, 1h).
    #[arg(long, value_name = "DURATION")]
    pub max_duration: Option<String>,
    /// Stop after this much inactivity in the destination sandbox.
    #[arg(long, value_name = "DURATION")]
    pub idle_timeout: Option<String>,
    /// Deny traffic by default; combine with --net-rule to allow selected destinations.
    #[cfg(feature = "net")]
    #[arg(long, conflicts_with = "net_default")]
    pub no_net: bool,
    /// Default action for both traffic directions in the destination host policy.
    #[cfg(feature = "net")]
    #[arg(long, value_parser = ["allow", "deny"])]
    pub net_default: Option<String>,
    /// Destination host policy rules, using the same syntax as create/run (repeatable).
    /// Requires --net-default or --no-net so the complete replacement policy is explicit.
    #[cfg(feature = "net")]
    #[arg(long, value_name = "TOKENS")]
    pub net_rule: Vec<String>,
    /// Deprecated alias for --max-tcp-connections.
    #[cfg(feature = "net")]
    #[arg(long, conflicts_with = "max_tcp_connections")]
    pub max_connections: Option<usize>,
    /// Concurrent TCP limit; zero explicitly selects unlimited.
    #[cfg(feature = "net")]
    #[arg(long)]
    pub max_tcp_connections: Option<usize>,
    /// Concurrent UDP session limit; zero explicitly selects unlimited.
    #[cfg(feature = "net")]
    #[arg(long)]
    pub max_udp_connections: Option<usize>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RestoreControlArgs {
    /// Parse controls before any asynchronous source resolution or destination mutation.
    fn apply(&self, mut builder: RestoreBuilder) -> anyhow::Result<RestoreBuilder> {
        if let Some(cpus) = self.cpus {
            builder = builder.cpus(cpus);
        }
        if let Some(memory) = &self.memory {
            builder = builder.memory(ui::parse_size_mib(memory).map_err(anyhow::Error::msg)?);
        }
        if let Some(security) = &self.security {
            let profile = match security.as_str() {
                "default" => SecurityProfile::Default,
                "restricted" => SecurityProfile::Restricted,
                other => anyhow::bail!("invalid security profile {other:?}"),
            };
            builder = builder.security(profile);
        }
        if let Some(duration) = &self.max_duration {
            builder = builder.max_duration(super::common::parse_duration_secs(duration)?);
        }
        if let Some(duration) = &self.idle_timeout {
            builder = builder.idle_timeout(super::common::parse_duration_secs(duration)?);
        }
        #[cfg(feature = "net")]
        {
            // Reuse the established CLI policy grammar and defaults. Do not reinterpret
            // --no-net as device removal: it is deny-both policy and supports an allowlist.
            if let Some(policy) = self.network_policy()? {
                builder = builder.network_policy(policy);
            }
            if let Some(limit) = self.max_tcp_connections.or(self.max_connections) {
                builder = builder.max_tcp_connections(limit);
            }
            if let Some(limit) = self.max_udp_connections {
                builder = builder.max_udp_connections(limit);
            }
        }
        Ok(builder)
    }

    #[cfg(feature = "net")]
    fn network_policy(
        &self,
    ) -> anyhow::Result<Option<microsandbox_network::policy::NetworkPolicy>> {
        if !self.net_rule.is_empty() && !self.no_net && self.net_default.is_none() {
            anyhow::bail!(
                "restore --net-rule requires --net-default or --no-net to select an explicit destination policy"
            );
        }
        super::common::SandboxOpts {
            no_net: self.no_net,
            net_default: self.net_default.clone(),
            net_rule: self.net_rule.clone(),
            ..Default::default()
        }
        .build_network_policy()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Restore captured state; use exec separately to start a new command.
pub async fn run(
    args: RestoreArgs,
    log_level: Option<microsandbox::LogLevel>,
) -> anyhow::Result<()> {
    let mut builder = Sandbox::restore(&args.snapshot).name(&args.name);
    if let Some(level) = log_level {
        builder = builder.log_level(level);
    }
    if args.forked {
        builder = builder.forked();
    }
    if args.disk_only {
        builder = builder.disk_only();
    }
    if args.allow_missing_resources {
        builder = builder.allow_missing_resources();
    }
    if let Some(base) = args.snapshot_base {
        builder = builder.snapshot_base(base);
    }
    builder = args.resources.apply_restore(builder)?;
    builder = args.controls.apply(builder)?;
    let (mut progress, task) = builder.restore_with_progress()?;
    let mut display = if args.quiet {
        ui::PullProgressDisplay::quiet(&args.snapshot)
    } else {
        ui::PullProgressDisplay::new(&args.snapshot)
    };
    while let Some(event) = progress.recv().await {
        display.handle_creation_event(event);
    }
    let result = task.await;
    display.finish();
    let sandbox = result.map_err(|error| anyhow::anyhow!("restore task failed: {error}"))??;
    display_restore_warnings(&sandbox).await;
    sandbox.detach().await;
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Macros
//--------------------------------------------------------------------------------------------------

macro_rules! apply_resources {
    ($method:ident, $builder:ty) => {
        impl RestoreResourceArgs {
            pub(crate) fn $method(&self, mut builder: $builder) -> anyhow::Result<$builder> {
                if let Some(user) = &self.user {
                    builder = builder.user(user);
                }
                if self.dangerously_inherit_resources {
                    builder = builder.dangerously_inherit_resources();
                }
                if let Some(policy) = &self.external_mount_policy {
                    builder = builder.external_mount_policy(match policy.as_str() {
                        "relaxed" => microsandbox::ExternalMountRestorePolicy::Relaxed,
                        _ => microsandbox::ExternalMountRestorePolicy::Strict,
                    });
                }
                for volume in &self.volume {
                    let (guest, mount) = parse_restore_volume(volume)?;
                    builder = builder.volume(guest, |_| mount);
                }
                for route in &self.vsock {
                    let (host, port, kind) = parse_vsock_route(route)?;
                    builder = match kind {
                        microsandbox::sandbox::VsockSocketType::Stream => builder.vsock(host, port),
                        microsandbox::sandbox::VsockSocketType::Dgram => {
                            builder.vsock_dgram(host, port)
                        }
                    };
                }
                #[cfg(feature = "net")]
                for port in &self.port {
                    let (bind, host, guest, udp) = parse_port_mapping(port)?;
                    #[cfg(feature = "net")]
                    {
                        builder = if udp {
                            builder.port_udp_bind(bind, host, guest)
                        } else {
                            builder.port_bind(bind, host, guest)
                        };
                    }
                }
                Ok(builder)
            }
        }
    };
}

apply_resources!(apply_restore, RestoreBuilder);
apply_resources!(apply_branch, BranchBuilder);
apply_resources!(apply_branch_many, BranchManyBuilder);

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(flatten)]
        args: RestoreArgs,
    }

    #[test]
    fn missing_resource_opt_out_is_independent_of_mapping_policy_and_inheritance() {
        let defaults = TestCli::try_parse_from(["restore", "saved", "--name", "child"]).unwrap();
        assert!(!defaults.args.allow_missing_resources);
        let explicit = TestCli::try_parse_from([
            "restore",
            "saved",
            "--name",
            "child",
            "--allow-missing-resources",
            "--external-mount-policy",
            "strict",
            "--dangerously-inherit-resources",
        ])
        .unwrap();
        assert!(explicit.args.allow_missing_resources);
        assert!(explicit.args.resources.dangerously_inherit_resources);
        assert_eq!(
            explicit.args.resources.external_mount_policy.as_deref(),
            Some("strict")
        );
    }

    #[test]
    fn restore_parses_destination_controls_without_creation_aliases() {
        let cli = TestCli::try_parse_from([
            "restore",
            "toolchain:ready",
            "--name",
            "worker",
            "--cpus",
            "2",
            "--memory",
            "2G",
            "--security",
            "restricted",
            "--max-duration",
            "10m",
            "--idle-timeout",
            "2m",
        ])
        .unwrap();
        assert_eq!(cli.args.controls.cpus, Some(2));
        assert_eq!(cli.args.controls.memory.as_deref(), Some("2G"));
        assert_eq!(cli.args.controls.security.as_deref(), Some("restricted"));
        assert!(
            cli.args
                .controls
                .apply(Sandbox::restore("toolchain:ready"))
                .is_ok()
        );
        for flag in ["--replace", "--from-snapshot", "--entrypoint"] {
            assert!(
                TestCli::try_parse_from(["restore", "ready", "--name", "worker", flag]).is_err()
            );
        }
    }

    #[test]
    fn invalid_destination_controls_fail_before_source_resolution() {
        for controls in [
            RestoreControlArgs {
                memory: Some("not-a-size".into()),
                ..Default::default()
            },
            RestoreControlArgs {
                max_duration: Some("not-a-duration".into()),
                ..Default::default()
            },
            RestoreControlArgs {
                security: Some("unknown".into()),
                ..Default::default()
            },
        ] {
            assert!(
                controls
                    .apply(Sandbox::restore("source-not-opened"))
                    .is_err()
            );
        }
    }

    #[cfg(feature = "net")]
    #[test]
    fn restore_parses_independent_tcp_udp_limits_and_rejects_duplicate_tcp_aliases() {
        for tcp_flag in ["--max-connections", "--max-tcp-connections"] {
            let cli = TestCli::try_parse_from([
                "restore",
                "ready",
                "--name",
                "child",
                tcp_flag,
                "0",
                "--max-udp-connections",
                "7",
            ])
            .unwrap();
            let controls = &cli.args.controls;
            assert_eq!(
                controls.max_tcp_connections.or(controls.max_connections),
                Some(0)
            );
            assert_eq!(controls.max_udp_connections, Some(7));
            assert!(controls.apply(Sandbox::restore("ready")).is_ok());
        }
        let defaults = TestCli::try_parse_from(["restore", "ready", "--name", "child"]).unwrap();
        assert_eq!(defaults.args.controls.max_tcp_connections, None);
        assert_eq!(defaults.args.controls.max_udp_connections, None);
        assert!(
            TestCli::try_parse_from([
                "restore",
                "ready",
                "--name",
                "child",
                "--max-connections",
                "1",
                "--max-tcp-connections",
                "2",
            ])
            .is_err()
        );
    }

    #[cfg(feature = "net")]
    #[test]
    fn restore_policy_requires_explicit_defaults_and_matches_create_grammar() {
        use microsandbox_network::policy::Action;

        let offline = TestCli::try_parse_from([
            "restore",
            "ready",
            "--name",
            "worker",
            "--no-net",
            "--max-connections",
            "0",
        ])
        .unwrap();
        assert_eq!(offline.args.controls.max_connections, Some(0));
        let offline_policy = offline.args.controls.network_policy().unwrap().unwrap();
        assert_eq!(offline_policy.default_egress, Action::Deny);
        assert_eq!(offline_policy.default_ingress, Action::Deny);
        assert!(offline_policy.rules.is_empty());
        assert!(
            offline
                .args
                .controls
                .apply(Sandbox::restore("ready"))
                .is_ok()
        );

        let omitted = RestoreControlArgs {
            max_connections: Some(8),
            ..Default::default()
        };
        assert!(omitted.network_policy().unwrap().is_none());
        let rule_only = RestoreControlArgs {
            net_rule: vec!["allow@books.toscrape.com:tcp:443".into()],
            ..Default::default()
        };
        assert!(
            rule_only
                .network_policy()
                .unwrap_err()
                .to_string()
                .contains("--net-default")
        );
        let allowlist = RestoreControlArgs {
            no_net: true,
            ..rule_only
        };
        let policy = allowlist.network_policy().unwrap().unwrap();
        assert_eq!(policy.default_egress, Action::Deny);
        assert_eq!(policy.default_ingress, Action::Deny);
        assert_eq!(policy.rules.len(), 1);
        let create_policy = super::super::common::SandboxOpts {
            no_net: true,
            net_rule: allowlist.net_rule,
            ..Default::default()
        }
        .build_network_policy()
        .unwrap()
        .unwrap();
        assert_eq!(
            serde_json::to_value(policy).unwrap(),
            serde_json::to_value(create_policy).unwrap()
        );
        assert!(
            TestCli::try_parse_from([
                "restore",
                "ready",
                "--name",
                "worker",
                "--no-net",
                "--net-default",
                "allow"
            ])
            .is_err()
        );
    }
}
