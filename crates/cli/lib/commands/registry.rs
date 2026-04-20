//! `msb registry` command — manage OCI registry credentials.

use std::io::Read;

use anyhow::Context;
use clap::{Args, Subcommand};
use microsandbox::{
    RegistryAuth,
    config::{
        RegistryAuthEntry, RegistryCredentialStore, delete_registry_keyring_auth,
        get_registry_keyring_auth, load_persisted_config_or_default, save_persisted_config,
        set_registry_keyring_auth,
    },
};

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Manage registry credentials.
#[derive(Debug, Args)]
pub struct RegistryArgs {
    /// Registry subcommand.
    #[command(subcommand)]
    pub command: RegistryCommands,
}

/// Registry subcommands.
#[derive(Debug, Subcommand)]
pub enum RegistryCommands {
    /// Store credentials for a registry in the OS credential store.
    Login(RegistryLoginArgs),

    /// Remove stored credentials for a registry.
    Logout(RegistryLogoutArgs),

    /// List configured registries without printing secrets.
    #[command(visible_alias = "ls")]
    List(RegistryListArgs),
}

/// Arguments for `msb registry login`.
#[derive(Debug, Args)]
pub struct RegistryLoginArgs {
    /// Registry hostname (for example `ghcr.io`).
    pub registry: String,

    /// Registry username.
    #[arg(short, long)]
    pub username: String,

    /// Read the password/token from stdin.
    #[arg(long)]
    pub password_stdin: bool,
}

/// Arguments for `msb registry logout`.
#[derive(Debug, Args)]
pub struct RegistryLogoutArgs {
    /// Registry hostname (for example `ghcr.io`).
    pub registry: String,
}

/// Arguments for `msb registry list`.
#[derive(Debug, Args, Default)]
pub struct RegistryListArgs {}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb registry` command.
pub async fn run(args: RegistryArgs) -> anyhow::Result<()> {
    match args.command {
        RegistryCommands::Login(args) => run_login(args),
        RegistryCommands::Logout(args) => run_logout(args),
        RegistryCommands::List(args) => run_list(args),
    }
}

fn run_login(args: RegistryLoginArgs) -> anyhow::Result<()> {
    let password = read_registry_password(args.password_stdin)?;
    let previous_auth = get_registry_keyring_auth(&args.registry).ok().flatten();

    set_registry_keyring_auth(&args.registry, &args.username, &password).map_err(|error| {
        anyhow::anyhow!(
            "secure credential storage is unavailable for `{}`: {}",
            args.registry,
            error
        )
    })?;

    let mut config = load_persisted_config_or_default()?;
    config
        .registries
        .hosts
        .entry(args.registry.clone())
        .or_default()
        .auth = Some(RegistryAuthEntry {
        username: args.username,
        store: Some(RegistryCredentialStore::Keyring),
        password_env: None,
        secret_name: None,
    });

    if let Err(error) = save_persisted_config(&config) {
        let restore = match previous_auth {
            Some(RegistryAuth::Basic { username, password }) => {
                set_registry_keyring_auth(&args.registry, &username, &password)
            }
            Some(RegistryAuth::Anonymous) | None => delete_registry_keyring_auth(&args.registry),
        };

        if let Err(restore_error) = restore {
            return Err(anyhow::anyhow!(
                "{}; also failed to restore the previous keyring state for `{}`: {}",
                error,
                args.registry,
                restore_error
            ));
        }

        return Err(error.into());
    }

    ui::success("Logged in", &args.registry);
    Ok(())
}

fn run_logout(args: RegistryLogoutArgs) -> anyhow::Result<()> {
    let mut config = load_persisted_config_or_default()?;
    let previous_auth = get_registry_keyring_auth(&args.registry).ok().flatten();
    let had_config_entry = config
        .registries
        .hosts
        .get_mut(&args.registry)
        .and_then(|e| e.auth.take())
        .is_some();
    let had_keyring_entry = previous_auth.is_some();

    if !had_config_entry && !had_keyring_entry {
        ui::warn(&format!(
            "no stored registry credentials found for `{}`",
            args.registry
        ));
        return Ok(());
    }

    delete_registry_keyring_auth(&args.registry)?;

    if let Err(error) = save_persisted_config(&config) {
        if let Some(RegistryAuth::Basic { username, password }) = previous_auth {
            let _ = set_registry_keyring_auth(&args.registry, &username, &password);
        }
        return Err(error.into());
    }

    ui::success("Logged out", &args.registry);
    Ok(())
}

fn run_list(_args: RegistryListArgs) -> anyhow::Result<()> {
    let config = load_persisted_config_or_default()?;
    let auth_entries: Vec<_> = config
        .registries
        .hosts
        .iter()
        .filter_map(|(hostname, entry)| entry.auth.as_ref().map(|auth| (hostname, auth)))
        .collect();

    if auth_entries.is_empty() {
        println!("No registries configured.");
        return Ok(());
    }

    let mut entries: Vec<_> = auth_entries;
    entries.sort_by_key(|(name, _)| *name);

    let mut table = ui::Table::new(&["REGISTRY", "USERNAME", "SOURCE"]);
    for (registry, entry) in entries {
        table.add_row(vec![
            registry.clone(),
            entry.username.clone(),
            credential_source_label(entry).to_string(),
        ]);
    }
    table.print();
    Ok(())
}

fn read_registry_password(password_stdin: bool) -> anyhow::Result<String> {
    let password = if password_stdin {
        let mut password = String::new();
        std::io::stdin()
            .read_to_string(&mut password)
            .context("failed to read password from stdin")?;
        password.trim_end_matches(['\r', '\n']).to_string()
    } else {
        rpassword::prompt_password("Password/token: ")
            .context("failed to read password from the terminal")?
    };

    if password.is_empty() {
        anyhow::bail!("password/token cannot be empty");
    }

    Ok(password)
}

fn credential_source_label(entry: &RegistryAuthEntry) -> &'static str {
    let source_count = usize::from(entry.store.is_some())
        + usize::from(entry.password_env.is_some())
        + usize::from(entry.secret_name.is_some());

    if source_count > 1 {
        return "multiple";
    }

    match (
        entry.store,
        entry.password_env.as_ref(),
        entry.secret_name.as_ref(),
    ) {
        (Some(RegistryCredentialStore::Keyring), _, _) => "keyring",
        (None, Some(_), None) => "password_env",
        (None, None, Some(_)) => "secret_name",
        _ => "unset",
    }
}
