//! Home directory management for Microsandbox.
//!
//! This module provides functionality for managing the global microsandbox home directory,
//! which contains cached images, layers, and databases. It also includes functions for
//! cleaning up the home directory and checking its existence.

use crate::{
    MicrosandboxError, MicrosandboxResult,
    config::{EnvPair, Microsandbox, PathPair, PortPair, ReferenceOrPath, Sandbox},
    management::{config, db, menv},
    oci::{Image, Reference},
};
use microsandbox_utils::{
    MICROSANDBOX_CONFIG_FILENAME, MICROSANDBOX_HOME_DIR, OCI_DB_FILENAME, XDG_BIN_DIR,
    XDG_HOME_DIR, env, path::INSTALLS_SUBDIR,
};

#[cfg(feature = "cli")]
use microsandbox_utils::term;
use std::os::unix::fs::PermissionsExt;
use tokio::fs;
use typed_path::Utf8UnixPathBuf;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "cli")]
const REMOVE_HOME_DIR_MSG: &str = "Remove microsandbox home";

#[cfg(feature = "cli")]
const INSTALL_SANDBOX_MSG: &str = "Install sandbox";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Clean up the global microsandbox home directory
///
/// This removes the entire microsandbox home directory and all its contents, effectively
/// cleaning up all global microsandbox data including cached images, layers, and databases.
///
/// ## Arguments
/// * `force` - Whether to force cleaning even if configuration files exist
///
/// ## Example
/// ```no_run
/// use microsandbox_core::management::home;
///
/// # async fn example() -> anyhow::Result<()> {
/// // Clean with force = true to remove everything regardless of configs
/// home::clean(true).await?;
/// # Ok(())
/// # }
/// ```
pub async fn clean(force: bool) -> MicrosandboxResult<()> {
    // Get the microsandbox home path from environment or default
    let home_path = env::get_microsandbox_home_path();
    let installs_path = home_path.join(INSTALLS_SUBDIR);

    #[cfg(feature = "cli")]
    let remove_home_dir_sp = term::create_spinner(REMOVE_HOME_DIR_MSG.to_string(), None, None);

    // Check if installs directory exists and has config files
    if installs_path.exists() {
        let config_path = installs_path.join(MICROSANDBOX_CONFIG_FILENAME);

        // If config file exists and force is false, don't clean
        if config_path.exists() && !force {
            #[cfg(feature = "cli")]
            term::finish_with_error(&remove_home_dir_sp);

            #[cfg(feature = "cli")]
            println!(
                "Configuration file exists at {}. Use {} to clean the home directory",
                console::style(config_path.display()).yellow(),
                console::style("--force").yellow()
            );

            tracing::warn!(
                "Configuration file exists at {}. Use force=true to clean the home directory",
                config_path.display()
            );
            return Ok(());
        }
    }

    // Check if home directory exists
    if home_path.exists() {
        // Remove the home directory and all its contents
        fs::remove_dir_all(&home_path).await?;
        tracing::info!(
            "Removed microsandbox home directory at {}",
            home_path.display()
        );
    } else {
        tracing::info!(
            "No microsandbox home directory found at {}",
            home_path.display()
        );
    }

    #[cfg(feature = "cli")]
    remove_home_dir_sp.finish();

    Ok(())
}

/// Install a sandbox from an image and create an alias script for it
///
/// This function creates a permanent sandbox configuration in the global microsandbox
/// home directory and sets up an alias script that can be used to run the sandbox.
///
/// ## Arguments
/// * `image` - The OCI image reference to use as the base for the sandbox
/// * `script` - The name of the script to execute within the sandbox
/// * `alias` - The alias name to use for the script, if not provided, the script name is used
/// * `cpus` - Optional number of virtual CPUs to allocate to the sandbox
/// * `memory` - Optional amount of memory in MiB to allocate to the sandbox
/// * `volumes` - List of volume mappings in the format "host_path:guest_path"
/// * `ports` - List of port mappings in the format "host_port:guest_port"
/// * `envs` - List of environment variables in the format "KEY=VALUE"
/// * `workdir` - Optional working directory path inside the sandbox
/// * `scope` - Optional network scope for the sandbox
/// * `exec` - Optional command to execute within the sandbox
/// * `args` - Additional arguments to pass to the command
/// * `use_image_defaults` - Whether to apply default settings from the OCI image configuration
///
/// ## Returns
/// Returns `Ok(())` if the sandbox is successfully installed, or a `MicrosandboxError` if:
/// - The image cannot be pulled or found
/// - The sandbox configuration is invalid
/// - The filesystem operations fail
/// - There is a name conflict with an existing system command
///
/// ## Example
/// ```no_run
/// use microsandbox_core::oci::Reference;
/// use microsandbox_core::management::home;
/// use typed_path::Utf8UnixPathBuf;
///
/// # async fn example() -> anyhow::Result<()> {
/// let image = "ubuntu:latest".parse::<Reference>()?;
///
/// // Install Ubuntu sandbox with custom name and resources
/// home::install(
///     &image,
///     Some("shell"),          // Run shell script
///     Some("ubuntu-shell"),   // Custom alias
///     Some(2),                // 2 CPUs
///     Some(1024),             // 1GB RAM
///     vec![                   // Mount host's /tmp to sandbox's /data
///         "/tmp:/data".to_string()
///     ],
///     vec![                   // Map host port 8080 to sandbox port 80
///         "8080:80".to_string()
///     ],
///     vec![                   // Set environment variables
///         "DEBUG=1".to_string()
///     ],
///     Some("/app".into()),    // Set working directory
///     Some("local".to_string()), // Set network scope
///     None,                   // No exec command
///     vec![],                 // No additional args
///     true                    // Use image defaults
/// ).await?;
/// # Ok(())
/// # }
/// ```
pub async fn install(
    image: &Reference,
    script: Option<&str>,
    alias: Option<&str>,
    cpus: Option<u8>,
    memory: Option<u32>,
    volumes: Vec<String>,
    ports: Vec<String>,
    envs: Vec<String>,
    workdir: Option<Utf8UnixPathBuf>,
    scope: Option<String>,
    exec: Option<&str>,
    args: Vec<String>,
    use_image_defaults: bool,
) -> MicrosandboxResult<()> {
    // Get the microsandbox home path
    let home_path = env::get_microsandbox_home_path();
    let installs_path = home_path.join(INSTALLS_SUBDIR);

    // Determine the alias name to use:
    // 1. Use the provided alias if specified
    // 2. Use the script name if provided
    // 3. Otherwise extract a name from the image reference
    let alias_name = alias
        .map(|a| a.to_string())
        .or_else(|| script.map(|s| s.to_string()))
        .unwrap_or_else(|| extract_name_from_reference(image));

    tracing::info!("Setting up alias: {}", alias_name);

    // Check if a command with this name already exists in the system PATH
    if command_exists(&alias_name) {
        return Err(MicrosandboxError::CommandExists(alias_name));
    }

    // Initialize .menv in the installs directory if it doesn't exist
    // This creates necessary directories and the sandbox database
    menv::initialize(Some(installs_path.clone())).await?;

    // Parse the volume, port, and env strings into their respective types
    let volumes: Vec<PathPair> = volumes.into_iter().filter_map(|v| v.parse().ok()).collect();
    let ports: Vec<PortPair> = ports.into_iter().filter_map(|p| p.parse().ok()).collect();
    let envs: Vec<EnvPair> = envs.into_iter().filter_map(|e| e.parse().ok()).collect();

    // Build the sandbox configuration
    let mut sandbox = {
        let mut b = Sandbox::builder().image(ReferenceOrPath::Reference(image.clone()));

        if let Some(cpus) = cpus {
            b = b.cpus(cpus);
        }

        if let Some(memory) = memory {
            b = b.memory(memory);
        }

        if let Some(workdir) = workdir {
            b = b.workdir(workdir);
        }

        if !volumes.is_empty() {
            b = b.volumes(volumes);
        }

        if !ports.is_empty() {
            b = b.ports(ports);
        }

        if !envs.is_empty() {
            b = b.envs(envs);
        }

        if let Some(scope) = scope {
            b = b.scope(scope.parse()?);
        }

        b.build()
    };

    // Apply image configuration defaults if enabled
    if use_image_defaults {
        // Pull the image from the registry if not already pulled
        Image::pull(image.clone(), None).await?;

        // Get the OCI database path and create a connection pool
        let db_path = home_path.join(OCI_DB_FILENAME);
        let oci_pool = db::get_or_create_pool(&db_path, &db::OCI_DB_MIGRATOR).await?;

        // Apply image defaults to the sandbox configuration
        config::apply_image_defaults(&mut sandbox, image, &oci_pool).await?;
        tracing::debug!("applied image defaults to sandbox config");
    }

    // Create spinner for CLI feedback
    #[cfg(feature = "cli")]
    let install_sandbox_sp = term::create_spinner(
        format!("{} from '{}'", INSTALL_SANDBOX_MSG, image),
        None,
        None,
    );

    // Override the exec command if provided
    if let Some(exec) = exec {
        let mut command = Vec::with_capacity(args.len() + 1);
        command.push(exec.to_string());
        command.extend(args);
        sandbox.set_command(command);
    }

    // Create the microsandbox config with the sandbox
    let config = Microsandbox::builder()
        .sandboxes([(alias_name.clone(), sandbox)])
        .build_unchecked();

    // Write the config to the installs directory
    let config_path = installs_path.join(MICROSANDBOX_CONFIG_FILENAME);
    fs::write(&config_path, serde_yaml::to_string(&config)?).await?;
    tracing::info!("Wrote config to {}", config_path.display());

    // Create the alias script in ~/.local/bin
    let bin_dir = XDG_HOME_DIR.join(XDG_BIN_DIR);

    // Create the bin directory if it doesn't exist
    fs::create_dir_all(&bin_dir).await?;

    let script_path = bin_dir.join(&alias_name);
    let script_content = generate_alias_script(&alias_name, script);

    // Write the script file
    fs::write(&script_path, script_content).await?;

    // Make the script executable
    let mut perms = std::fs::metadata(&script_path)?.permissions();
    perms.set_mode(0o755); // rwxr-xr-x
    std::fs::set_permissions(&script_path, perms)?;

    tracing::info!("Created alias script at {}", script_path.display());

    #[cfg(feature = "cli")]
    install_sandbox_sp.finish();

    Ok(())
}

/// Uninstall a script alias from the local bin directory
///
/// This function removes a script alias that was previously installed using `install`.
/// It only removes scripts that contain the "MSB-ALIAS" marker to ensure it doesn't
/// delete unrelated files.
///
/// ## Arguments
/// * `script_name` - The name of the script to uninstall. This should match the alias name.
///
/// ## Returns
/// Returns `Ok(())` if the script is successfully uninstalled, or a `MicrosandboxError` if:
/// - The script doesn't exist in the bin directory
/// - The script doesn't contain the MSB-ALIAS marker
/// - The file system operations fail
///
/// ## Example
/// ```no_run
/// use microsandbox_core::management::home;
///
/// # async fn example() -> anyhow::Result<()> {
/// // Uninstall the "ubuntu-shell" script
/// home::uninstall("ubuntu-shell").await?;
/// # Ok(())
/// # }
/// ```
pub async fn uninstall(script_name: &str) -> MicrosandboxResult<()> {
    // Get the bin directory path
    let bin_dir = XDG_HOME_DIR.join(XDG_BIN_DIR);
    let script_path = bin_dir.join(script_name);

    // Check if the script exists
    if !script_path.exists() {
        return Err(MicrosandboxError::PathNotFound(format!(
            "Script '{}' not found at {}",
            script_name,
            script_path.display()
        )));
    }

    // Read the script file
    let script_content = fs::read_to_string(&script_path).await?;

    // Check if it's a microsandbox alias script (contains MSB-ALIAS marker)
    if !script_content.contains("# MSB-ALIAS:") {
        return Err(MicrosandboxError::InvalidArgument(format!(
            "Script '{}' is not a microsandbox alias (missing MSB-ALIAS marker)",
            script_name
        )));
    }

    // Extract the alias name from the script for verification
    let alias_marker = format!("# MSB-ALIAS: {}", script_name);
    if !script_content.contains(&alias_marker) {
        tracing::warn!(
            "Script '{}' has a different alias name in its marker. Continuing with uninstall.",
            script_name
        );
    }

    // All checks passed, remove the script
    fs::remove_file(&script_path).await?;
    tracing::info!("Removed alias script: {}", script_path.display());

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Check if a command with the given name exists in the system PATH
///
/// This function uses `which` to check if a command exists in any directory
/// listed in the PATH environment variable.
///
/// ## Arguments
/// * `command` - The name of the command to check
///
/// ## Returns
/// Returns `true` if the command exists in PATH, `false` otherwise
fn command_exists(command: &str) -> bool {
    use std::process::Command;

    Command::new("which")
        .arg(command)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Extracts a simple name from an OCI image reference
///
/// For example:
/// - "docker.io/library/ubuntu:latest" -> "ubuntu"
/// - "registry.com/org/app:v1.0" -> "app"
/// - "myapp:stable" -> "myapp"
fn extract_name_from_reference(reference: &Reference) -> String {
    let image_str = reference.to_string();

    // Split the image string by '/' and take the last part
    let name_with_tag = image_str.split('/').last().unwrap_or(&image_str);

    // Split by ':' to remove the tag and take the first part
    name_with_tag
        .split(':')
        .next()
        .unwrap_or(name_with_tag)
        .to_string()
}

/// Generate the content for the alias script based on the alias name and optional script.
fn generate_alias_script(alias: &str, script: Option<&str>) -> String {
    let run_command = if let Some(script_name) = script {
        format!(
            "exec \"$MSB_PATH\" run \"{}~{}\" -f \"$HOME/{}\" \"$@\"",
            alias,
            script_name,
            MICROSANDBOX_HOME_DIR.to_string() + "/" + INSTALLS_SUBDIR
        )
    } else {
        format!(
            "exec \"$MSB_PATH\" run \"{}\" -f \"$HOME/{}\" \"$@\"",
            alias,
            MICROSANDBOX_HOME_DIR.to_string() + "/" + INSTALLS_SUBDIR
        )
    };

    format!(
        r#"#!/bin/sh
# MSB-ALIAS: {}
# Alias for 'msb run {}{}' from installed sandbox

# Find the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Assuming msb is in the same directory as this script
if [ -x "$SCRIPT_DIR/msb" ]; then
  MSB_PATH="$SCRIPT_DIR/msb"
else
  # Otherwise, rely on PATH
  MSB_PATH="msb"
fi

{}
"#,
        alias,
        alias,
        script.map(|s| format!("~{}", s)).unwrap_or_default(),
        run_command
    )
}
