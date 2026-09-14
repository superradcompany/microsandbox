//! Restore a snapshot into a detached sandbox with explicit host resource bindings.

use clap::Args;
use microsandbox::sandbox::{BranchBuilder, BranchManyBuilder, RestoreBuilder, Sandbox};

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
    #[arg(long)]
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
    /// Destination resource bindings.
    #[command(flatten)]
    pub resources: RestoreResourceArgs,
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
    if let Some(base) = args.snapshot_base {
        builder = builder.snapshot_base(base);
    }
    builder = args.resources.apply_restore(builder)?;
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
