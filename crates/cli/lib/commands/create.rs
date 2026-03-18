//! `msb create` command — create and boot a fresh sandbox.

use clap::Args;
use microsandbox::sandbox::Sandbox;

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Create and boot a fresh sandbox (no workload launch).
#[derive(Debug, Args)]
pub struct CreateArgs {
    /// Image reference (OCI image, directory, or disk image).
    pub image: String,

    /// Sandbox name. Auto-generated if not provided.
    #[arg(short, long)]
    pub name: Option<String>,

    /// Number of virtual CPUs.
    #[arg(short = 'c', long)]
    pub cpus: Option<u8>,

    /// Memory limit (e.g., 512M, 1G).
    #[arg(short, long)]
    pub memory: Option<String>,

    /// Volume mount (host:guest or name:guest). Can be repeated.
    #[arg(short, long)]
    pub volume: Vec<String>,

    /// Working directory inside sandbox.
    #[arg(short, long)]
    pub workdir: Option<String>,

    /// Default shell.
    #[arg(long)]
    pub shell: Option<String>,

    /// Environment variable (KEY=value). Can be repeated.
    #[arg(short, long)]
    pub env: Vec<String>,

    /// Replace existing stopped sandbox with same name.
    #[arg(long)]
    pub force: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb create` command.
pub async fn run(args: CreateArgs) -> anyhow::Result<()> {
    let name = args.name.unwrap_or_else(ui::generate_name);
    let spinner = ui::Spinner::start("Creating", &name);

    let mut builder = Sandbox::builder(&name).image(args.image.as_str());

    if let Some(cpus) = args.cpus {
        builder = builder.cpus(cpus);
    }
    if let Some(ref mem) = args.memory {
        builder = builder.memory(ui::parse_memory(mem).map_err(anyhow::Error::msg)?);
    }
    if let Some(ref workdir) = args.workdir {
        builder = builder.workdir(workdir);
    }
    if let Some(ref shell) = args.shell {
        builder = builder.shell(shell);
    }
    if args.force {
        builder = builder.force();
    }
    for env_str in &args.env {
        let (k, v) = ui::parse_env(env_str).map_err(anyhow::Error::msg)?;
        builder = builder.env(k, v);
    }
    for vol_str in &args.volume {
        builder = apply_volume(builder, vol_str)?;
    }

    match builder.create().await {
        Ok(_sandbox) => {
            spinner.finish_success("Created");
            // Sandbox stays running — supervisor continues as background process.
        }
        Err(e) => {
            spinner.finish_error();
            return Err(e.into());
        }
    }

    Ok(())
}

/// Parse a volume spec and apply it to the builder.
pub fn apply_volume(
    builder: microsandbox::sandbox::SandboxBuilder,
    spec: &str,
) -> anyhow::Result<microsandbox::sandbox::SandboxBuilder> {
    let (source, guest) = spec
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("volume must be in format source:guest"))?;

    if source.starts_with('/') || source.starts_with("./") || source.starts_with("../") {
        Ok(builder.volume(guest, |m| m.bind(source)))
    } else {
        Ok(builder.volume(guest, |m| m.named(source)))
    }
}
