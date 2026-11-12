//! Manage Services from the CLI.

mod output;

use std::num::NonZeroU16;

use clap::{Args, Subcommand};
use microsandbox::{CloudService, MicrosandboxError, Service, ServiceTarget, UnsupportedReason};

use self::output::{print_service, service_record, service_table};
use crate::ui::{self, OutputFormat};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Services requested per page while `msb service ls` collects every page.
const LIST_PAGE_LIMIT: u32 = 100;

/// CLI guidance for a Service command refused by the local backend.
const LOCAL_BACKEND_MESSAGE: &str = "services require a cloud backend. Set MSB_BACKEND=cloud and \
    MSB_API_KEY, or run 'msb context use <name>'";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Manage public URLs for sandbox ports.
#[derive(Debug, Args)]
#[command(
    after_help = "Examples:\n  msb service create my-app --target web-1:8080\n  \
    msb service update my-app --target web-2:8080\n  msb service disable my-app\n  \
    msb service ls --sandbox web-2\n  msb service remove my-app\n\n\
    Requires a cloud backend."
)]
pub struct ServiceArgs {
    /// Service subcommand.
    #[command(subcommand)]
    pub command: ServiceCommands,
}

/// Service subcommands.
#[derive(Debug, Subcommand)]
pub enum ServiceCommands {
    /// Create a service for a running sandbox port.
    Create(ServiceCreateArgs),

    /// Change a service's target.
    Update(ServiceUpdateArgs),

    /// Enable a service.
    Enable(ServiceActionArgs),

    /// Disable a service while retaining its target.
    Disable(ServiceActionArgs),

    /// Show detailed service information.
    #[command(alias = "get")]
    Inspect(ServiceInspectArgs),

    /// List services, in slug order.
    #[command(visible_alias = "ls")]
    List(ServiceListArgs),

    /// Remove a service and release its slug.
    #[command(visible_alias = "rm")]
    Remove(ServiceRemoveArgs),
}

/// Arguments for `msb service create`.
#[derive(Debug, Args)]
pub struct ServiceCreateArgs {
    /// Service slug: 3-63 lowercase letters, digits or single hyphens.
    pub slug: String,

    /// Running target, as SANDBOX:PORT.
    #[arg(long, value_name = "SANDBOX:PORT", value_parser = parse_target)]
    pub target: ServiceTarget,

    /// Output format (json).
    #[arg(long, value_name = "FORMAT", value_enum)]
    pub format: Option<OutputFormat>,
}

/// Arguments for `msb service update`.
#[derive(Debug, Args)]
pub struct ServiceUpdateArgs {
    /// Service to update.
    pub slug: String,

    /// Set a running target. This also enables or reattaches the service.
    #[arg(long, value_name = "SANDBOX:PORT", value_parser = parse_target)]
    pub target: ServiceTarget,

    /// Output format (json).
    #[arg(long, value_name = "FORMAT", value_enum)]
    pub format: Option<OutputFormat>,
}

/// Arguments for `msb service enable` and `msb service disable`.
#[derive(Debug, Args)]
pub struct ServiceActionArgs {
    /// Service to change.
    pub slug: String,

    /// Output format (json).
    #[arg(long, value_name = "FORMAT", value_enum)]
    pub format: Option<OutputFormat>,
}

/// Arguments for `msb service inspect`.
#[derive(Debug, Args)]
pub struct ServiceInspectArgs {
    /// Service to show.
    pub slug: String,

    /// Output format (json).
    #[arg(long, value_name = "FORMAT", value_enum)]
    pub format: Option<OutputFormat>,
}

/// Arguments for `msb service list`.
#[derive(Debug, Args)]
pub struct ServiceListArgs {
    /// Only list services whose target is this sandbox.
    #[arg(long, value_name = "SANDBOX")]
    pub sandbox: Option<String>,

    /// Output format (json).
    #[arg(long, value_name = "FORMAT", value_enum)]
    pub format: Option<OutputFormat>,
}

/// Arguments for `msb service remove`.
#[derive(Debug, Args)]
pub struct ServiceRemoveArgs {
    /// Service to remove.
    pub slug: String,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb service` command.
pub async fn run(args: ServiceArgs) -> anyhow::Result<()> {
    let result = match args.command {
        ServiceCommands::Create(args) => create(args).await,
        ServiceCommands::Update(args) => update(args).await,
        ServiceCommands::Enable(args) => enable(args).await,
        ServiceCommands::Disable(args) => disable(args).await,
        ServiceCommands::Inspect(args) => inspect(args).await,
        ServiceCommands::List(args) => list(args).await,
        ServiceCommands::Remove(args) => remove(args).await,
    };

    result.map_err(explain_local_backend)
}

async fn create(args: ServiceCreateArgs) -> anyhow::Result<()> {
    let slug = args.slug;
    let ServiceTarget { sandbox, port } = args.target;
    let service = Service::builder(&slug).target(sandbox, port).create().await;

    let service = match service {
        Ok(service) => service,
        Err(original @ MicrosandboxError::ServiceAlreadyExists(_)) => {
            if Service::get(&slug).await.is_ok() {
                anyhow::bail!(
                    "service {slug} already exists; use 'msb service update' to change its target"
                );
            }
            return Err(original.into());
        }
        Err(error) => return Err(error.into()),
    };

    print_service(&service, args.format)
}

async fn update(args: ServiceUpdateArgs) -> anyhow::Result<()> {
    let service = Service::get(&args.slug).await?;
    let ServiceTarget { sandbox, port } = args.target;

    let updated = service
        .update(|update| update.target(sandbox, port))
        .await?;

    print_service(&updated, args.format)
}

async fn enable(args: ServiceActionArgs) -> anyhow::Result<()> {
    let service = Service::get(&args.slug).await?;
    let updated = service.enable().await?;

    print_service(&updated, args.format)
}

async fn disable(args: ServiceActionArgs) -> anyhow::Result<()> {
    let service = Service::get(&args.slug).await?;
    if service.target().is_none() {
        anyhow::bail!(
            "service {} is detached; set a target with 'msb service update'",
            args.slug
        );
    }
    let updated = service.disable().await?;

    print_service(&updated, args.format)
}

async fn inspect(args: ServiceInspectArgs) -> anyhow::Result<()> {
    let service = Service::get(&args.slug).await?;

    print_service(&service, args.format)
}

async fn list(args: ServiceListArgs) -> anyhow::Result<()> {
    let services = list_all(args.sandbox.as_deref()).await?;
    let records: Vec<CloudService> = services.iter().map(service_record).collect();

    if args.format == Some(OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&records)?);
        return Ok(());
    }

    if records.is_empty() {
        eprintln!("No services found.");
        return Ok(());
    }

    service_table(&records).print();
    Ok(())
}

async fn remove(args: ServiceRemoveArgs) -> anyhow::Result<()> {
    let service = Service::get(&args.slug).await?;
    service.remove().await?;

    ui::success("Removed", &args.slug);
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Parse a `SANDBOX:PORT` target. The port must be 1 through 65535.
fn parse_target(value: &str) -> Result<ServiceTarget, String> {
    let Some((sandbox, port)) = value.rsplit_once(':') else {
        return Err(format!("expected SANDBOX:PORT, got '{value}'"));
    };
    if sandbox.is_empty() {
        return Err(format!("expected SANDBOX:PORT, got '{value}'"));
    }
    let port = port
        .parse::<NonZeroU16>()
        .map_err(|_| format!("port must be between 1 and 65535, got '{port}'"))?;

    Ok(ServiceTarget {
        sandbox: sandbox.to_string(),
        port: port.get(),
    })
}

fn explain_local_backend(error: anyhow::Error) -> anyhow::Error {
    let cloud_only = matches!(
        error.downcast_ref::<MicrosandboxError>(),
        Some(MicrosandboxError::Unsupported {
            reason: UnsupportedReason::CloudOnly,
            ..
        })
    );
    if cloud_only {
        error.context(LOCAL_BACKEND_MESSAGE)
    } else {
        error
    }
}

async fn list_all(sandbox: Option<&str>) -> anyhow::Result<Vec<Service>> {
    let mut cursor: Option<String> = None;
    let mut services = Vec::new();

    loop {
        let page = Service::list_with(|list| {
            let list = list.limit(LIST_PAGE_LIMIT);
            let list = match sandbox {
                Some(sandbox) => list.sandbox(sandbox),
                None => list,
            };
            match cursor.take() {
                Some(cursor) => list.cursor(cursor),
                None => list,
            }
        })
        .await?;
        services.extend(page.services);

        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => return Ok(services),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests;
