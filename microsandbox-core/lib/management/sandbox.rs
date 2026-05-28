//! Sandbox management functionality for Microsandbox.
//!
//! This module provides functionality for managing sandboxes, which are isolated execution
//! environments for running applications. It handles sandbox creation, configuration,
//! and execution based on the Microsandbox configuration file.

use std::{
    path::{Path, PathBuf},
    process::Stdio,
};

use chrono::{DateTime, Utc};
use microsandbox_utils::{
    DEFAULT_MSBRUN_EXE_PATH, DEFAULT_SHELL, EXTRACTED_LAYER_SUFFIX, LAYERS_SUBDIR, LOG_SUBDIR,
    MICROSANDBOX_CONFIG_FILENAME, MICROSANDBOX_ENV_DIR, MSBRUN_EXE_ENV_VAR, OCI_DB_FILENAME,
    PATCH_SUBDIR, RW_SUBDIR, SANDBOX_DB_FILENAME, SANDBOX_DIR, SCRIPTS_DIR, SHELL_SCRIPT_NAME, env,
};
#[cfg(target_os = "macos")]
use microsandbox_utils::get_fex_emulator_path;
use sqlx::{Pool, Sqlite};
use tempfile;
use tokio::{fs, process::Command};
use typed_path::Utf8UnixPathBuf;

use crate::{
    MicrosandboxError, MicrosandboxResult,
    config::{
        EnvPair, Microsandbox, PathPair, PortPair, ReferenceOrPath, START_SCRIPT_NAME, Sandbox,
    },
    management::{config, db, menv, rootfs},
    oci::{Image, Reference},
    vm::Rootfs,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const TEMPORARY_SANDBOX_NAME: &str = "tmp";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Runs a sandbox with the specified configuration and script.
///
/// This function executes a sandbox environment based on the configuration specified in the Microsandbox
/// config file. It handles both native rootfs and image-based rootfs setups.
///
/// ## Arguments
///
/// * `sandbox` - The name of the sandbox to run as defined in the Microsandbox config file
/// * `script` - The name of the script to execute within the sandbox (e.g., "start", "shell")
/// * `project_dir` - Optional path to the project directory. If None, defaults to current directory
/// * `config_file` - Optional path to the Microsandbox config file. If None, uses default filename
/// * `args` - Additional arguments to pass to the sandbox script
/// * `detach` - Whether to run the sandbox in the background
/// * `exec` - Optional command to execute within the sandbox. Overrides `script` if provided.
/// * `use_image_defaults` - Whether to apply default settings from the OCI image configuration
///
/// ## Returns
///
/// Returns `Ok(())` if the sandbox runs and exits successfully, or a `MicrosandboxError` if:
/// - The config file is not found
/// - The specified sandbox is not found in the config
/// - The supervisor process fails to start or exits with an error
/// - Any filesystem operations fail
///
/// ## Example
///
/// ```no_run
/// use std::path::PathBuf;
/// use microsandbox_core::management::sandbox;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Run a sandbox named "dev" with the "start" script
///     sandbox::run(
///         "dev",
///         Some("start"),
///         None,
///         None,
///         vec![],
///         false,
///         None,
///         true
///     ).await?;
///     Ok(())
/// }
/// ```
pub async fn run(
    sandbox_name: &str,
    script_name: Option<&str>,
    project_dir: Option<&Path>,
    config_file: Option<&str>,
    args: Vec<String>,
    detach: bool,
    exec: Option<&str>,
    use_image_defaults: bool,
) -> MicrosandboxResult<()> {
    // Prepare the command
    let (mut command, is_detached) = prepare_run(
        sandbox_name,
        script_name,
        project_dir,
        config_file,
        args,
        detach,
        exec,
        use_image_defaults,
    )
    .await?;

    // Spawn the command
    let mut child = command.spawn()?;

    tracing::info!(
        "started supervisor process with PID: {}",
        child.id().unwrap_or(0)
    );

    // If in detached mode, don't wait for the child process to complete
    if is_detached {
        return Ok(());
    }

    // Wait for the child process to complete
    let status = child.wait().await?;
    if !status.success() {
        tracing::error!(
            "child process — supervisor — exited with status: {}",
            status
        );
        return Err(MicrosandboxError::SupervisorError(format!(
            "child process — supervisor — failed with exit status: {}",
            status
        )));
    }

    Ok(())
}

/// Prepares a sandbox command for execution without running it.
///
/// This function performs all the setup required to run a sandbox, including configuration loading,
/// rootfs setup, and command preparation, but does not execute the command. Instead, it returns
/// the prepared command that can be executed later.
///
/// The arguments and behavior are identical to `run()`, except this function returns the prepared
/// command instead of executing it.
///
/// ## Returns
///
/// Returns a tuple containing:
/// - The prepared command ready for execution
/// - Whether the command should be run in detached mode
pub async fn prepare_run(
    sandbox_name: &str,
    script_name: Option<&str>,
    project_dir: Option<&Path>,
    config_file: Option<&str>,
    args: Vec<String>,
    detach: bool,
    exec: Option<&str>,
    use_image_defaults: bool,
) -> MicrosandboxResult<(Command, bool)> {
    // Load the configuration
    let (config, canonical_project_dir, config_file) =
        config::load_config(project_dir, config_file).await?;

    let config_path = canonical_project_dir.join(&config_file);

    // Ensure the .menv files exist
    let menv_path = canonical_project_dir.join(MICROSANDBOX_ENV_DIR);
    menv::ensure_menv_files(&menv_path).await?;

    // Get the sandbox config
    let Some(mut sandbox_config) = config.get_sandbox(sandbox_name).cloned() else {
        return Err(MicrosandboxError::SandboxNotFoundInConfig(
            sandbox_name.to_string(),
            config_path,
        ));
    };

    tracing::debug!("original sandbox config: {:#?}", sandbox_config);

    // Sandbox database path
    let sandbox_db_path = menv_path.join(SANDBOX_DB_FILENAME);

    // Get sandbox database connection pool
    let sandbox_pool = db::get_or_create_pool(&sandbox_db_path, &db::SANDBOX_DB_MIGRATOR).await?;

    // Get the config last modified timestamp
    let config_last_modified: DateTime<Utc> = fs::metadata(&config_path).await?.modified()?.into();

    let rootfs = match sandbox_config.get_image().clone() {
        ReferenceOrPath::Path(root_path) => {
            setup_native_rootfs(
                &canonical_project_dir.join(root_path),
                sandbox_name,
                &sandbox_config,
                &config_file,
                &config_last_modified,
                &sandbox_pool,
            )
            .await?
        }
        ReferenceOrPath::Reference(ref reference) => {
            setup_image_rootfs(
                reference,
                sandbox_name,
                &mut sandbox_config,
                &menv_path,
                &config_file,
                &config_last_modified,
                &sandbox_pool,
                use_image_defaults,
            )
            .await?
        }
    };

    // Determine the exec path and args
    let (exec_path, exec_args) =
        determine_exec_path_and_args(exec, script_name, &sandbox_config, sandbox_name)?;

    // Log directory
    let log_dir = menv_path.join(LOG_SUBDIR);
    fs::create_dir_all(&log_dir).await?;

    tracing::info!("preparing sandbox supervisor...");
    tracing::debug!("rootfs: {:?}", rootfs);
    tracing::debug!("exec_path: {}", exec_path);
    tracing::debug!("exec_args: {:?}", exec_args);

    let msbrun_path =
        microsandbox_utils::path::resolve_env_path(MSBRUN_EXE_ENV_VAR, &*DEFAULT_MSBRUN_EXE_PATH)?;

    let mut command = Command::new(msbrun_path);
    command
        .arg("supervisor")
        .arg("--log-dir")
        .arg(&log_dir)
        .arg("--sandbox-name")
        .arg(sandbox_name)
        .arg("--config-file")
        .arg(&config_file)
        .arg("--config-last-modified")
        .arg(&config_last_modified.to_rfc3339())
        .arg("--sandbox-db-path")
        .arg(&sandbox_db_path)
        .arg("--scope")
        .arg(sandbox_config.get_scope().to_string())
        .arg("--exec-path")
        .arg(&exec_path);

    // CPU
    if let Some(cpus) = sandbox_config.get_cpus() {
        command.arg("--num-vcpus").arg(cpus.to_string());
    }

    // Memory
    if let Some(memory) = sandbox_config.get_memory() {
        command.arg("--memory-mib").arg(memory.to_string());
    }

    // Workdir
    if let Some(workdir) = sandbox_config.get_workdir() {
        command.arg("--workdir-path").arg(workdir);
    }

    // Env
    for env in sandbox_config.get_envs() {
        command.arg("--env").arg(env.to_string());
    }

    // Ports
    for port in sandbox_config.get_ports() {
        command.arg("--port-map").arg(port.to_string());
    }

    // Volumes
    for volume in sandbox_config.get_volumes() {
        match volume {
            PathPair::Distinct { host, guest } => {
                if host.is_absolute() {
                    // Absolute host path, use as is
                    command.arg("--mapped-dir").arg(volume.to_string());
                } else {
                    // Relative host path, join with project directory
                    let host_path = canonical_project_dir.join(host.as_str());
                    let combined_volume = format!("{}:{}", host_path.display(), guest);
                    command.arg("--mapped-dir").arg(combined_volume);
                }
            }
            PathPair::Same(path) => {
                if path.is_absolute() {
                    // Absolute path, use as is
                    command.arg("--mapped-dir").arg(volume.to_string());
                } else {
                    // Relative path, join with project directory
                    let host_path = canonical_project_dir.join(path.as_str());
                    let combined_volume = format!("{}:{}", host_path.display(), path);
                    command.arg("--mapped-dir").arg(combined_volume);
                }
            }
        }
    }

    // Pass the rootfs
    match rootfs {
        Rootfs::Native(path) => {
            command.arg("--native-rootfs").arg(path);
        }
        Rootfs::Overlayfs(paths) => {
            for path in paths {
                command.arg("--overlayfs-layer").arg(path);
            }
        }
    }

    // Only pass RUST_LOG if it's set in the environment
    if let Some(rust_log) = std::env::var_os("RUST_LOG") {
        tracing::debug!("using existing RUST_LOG: {:?}", rust_log);
        command.env("RUST_LOG", rust_log);
    }

    // In detached mode, ignore the i/o of the supervisor process.
    if detach {
        // Safety:
        // We call `libc::setsid()` to detach the child process from the parent's session and controlling terminal.
        //
        // This call is safe in our context because:
        // - It only creates a new session and process group for the child, which is exactly what we intend.
        // - We are not modifying any shared mutable state.
        // - The call has no side-effects beyond detaching the process.
        //
        // ASCII diagram illustrating the detachment:
        //
        //      [ Main Process ]
        //             │
        //             ├── spawns ──► [ Supervisor ]
        //                                 │
        //                                 └─ calls setsid() ─► [ New Session & Process Group ]
        //                                               (Detached)
        //
        // This ensures that the supervisor runs independently, even if the orchestrator exits.
        unsafe {
            command.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }

        // TODO: Redirect to log file
        // Redirect the i/o to /dev/null
        command.stdout(Stdio::null());
        command.stderr(Stdio::null());
        command.stdin(Stdio::null());
    } else {
        command.arg("--forward-output");
    }

    // Pass the extra arguments last.
    if !args.is_empty() {
        command.arg("--");
        for arg in args {
            command.arg(arg);
        }
    } else if !exec_args.is_empty() {
        // If no explicit args were provided but we got args from the command, use those
        command.arg("--");
        for arg in exec_args {
            command.arg(arg);
        }
    }

    Ok((command, detach))
}

/// Creates and runs a temporary sandbox from an OCI image.
///
/// This function creates a temporary sandbox environment from a container image without requiring
/// a Microsandbox configuration file. It's useful for quick, one-off sandbox executions.
/// The temporary sandbox and its associated files are automatically cleaned up after execution.
///
/// # Arguments
///
/// * `image` - The OCI image reference to use as the base for the sandbox
/// * `script` - The name of the script to execute within the sandbox
/// * `cpus` - Optional number of virtual CPUs to allocate to the sandbox
/// * `memory` - Optional amount of memory in MiB to allocate to the sandbox
/// * `volumes` - List of volume mappings in the format "host_path:guest_path"
/// * `ports` - List of port mappings in the format "host_port:guest_port"
/// * `envs` - List of environment variables in the format "KEY=VALUE"
/// * `workdir` - Optional working directory path inside the sandbox
/// * `exec` - Optional command to execute within the sandbox. Overrides `script` if provided.
/// * `args` - Additional arguments to pass to the specified script or command
/// * `use_image_defaults` - Whether to apply default settings from the OCI image configuration
///
/// # Returns
///
/// Returns `Ok(())` if the temporary sandbox runs and exits successfully, or a `MicrosandboxError` if:
/// - The image cannot be pulled or found
/// - The sandbox configuration is invalid
/// - The supervisor process fails to start or exits with an error
/// - Any filesystem operations fail
///
/// # Example
///
/// ```no_run
/// use microsandbox_core::oci::Reference;
/// use microsandbox_core::management::sandbox;
/// use typed_path::Utf8UnixPathBuf;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let image = "ubuntu:latest".parse::<Reference>()?;
///
///     // Run a temporary Ubuntu sandbox with custom resources
///     sandbox::run_temp(
///         &image,
///         Some("start"),     // Script name
///         Some(2),           // 2 CPUs
///         Some(1024),        // 1GB RAM
///         vec![              // Mount host's /tmp to sandbox's /data
///             "/tmp:/data".to_string()
///         ],
///         vec![              // Map host port 8080 to sandbox port 80
///             "8080:80".to_string()
///         ],
///         vec![              // Set environment variables
///             "DEBUG=1".to_string()
///         ],
///         Some("/app".into()), // Set working directory
///         None,              // No network scope override
///         None,              // No exec command
///         vec![],            // No additional args
///         true               // Use image defaults
///     ).await?;
///     Ok(())
/// }
/// ```
pub async fn run_temp(
    image: &Reference,
    script: Option<&str>,
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
    // Create a temporary directory without losing the TempDir guard for automatic cleanup
    let temp_dir = tempfile::tempdir()?;
    let temp_dir_path = temp_dir.path().to_path_buf();

    // Initialize menv in the temporary directory
    menv::initialize(Some(temp_dir_path.clone())).await?;

    // Parse the volume, port, and env strings into their respective types
    let volumes: Vec<PathPair> = volumes.into_iter().filter_map(|v| v.parse().ok()).collect();
    let ports: Vec<PortPair> = ports.into_iter().filter_map(|p| p.parse().ok()).collect();
    let envs: Vec<EnvPair> = envs.into_iter().filter_map(|e| e.parse().ok()).collect();

    // Build the temporary sandbox configuration.
    let sandbox = {
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

    // Create the microsandbox config with the temporary sandbox
    let config = Microsandbox::builder()
        .sandboxes([(TEMPORARY_SANDBOX_NAME.to_string(), sandbox)])
        .build_unchecked();

    // Write the config to the temporary directory
    let config_path = temp_dir_path.join(MICROSANDBOX_CONFIG_FILENAME);
    tokio::fs::write(&config_path, serde_yaml::to_string(&config)?).await?;

    // Run the sandbox with the temporary configuration
    run(
        TEMPORARY_SANDBOX_NAME,
        script,
        Some(&temp_dir_path),
        None,
        args,
        false,
        exec,
        use_image_defaults,
    )
    .await?;

    // Explicitly close the TempDir to clean up the temporary directory
    temp_dir.close()?;
    tracing::info!("temporary sandbox directory cleaned up");

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

async fn setup_image_rootfs(
    image: &Reference,
    sandbox_name: &str,
    sandbox_config: &mut Sandbox,
    menv_path: &Path,
    config_file: &str,
    config_last_modified: &DateTime<Utc>,
    sandbox_pool: &Pool<Sqlite>,
    use_image_defaults: bool,
) -> MicrosandboxResult<Rootfs> {
    tracing::info!(?image, "pulling image");
    Image::pull(image.clone(), None).await?;

    // Get the microsandbox home path and database path
    let microsandbox_home_path = env::get_microsandbox_home_path();
    let db_path = microsandbox_home_path.join(OCI_DB_FILENAME);
    let layers_dir = microsandbox_home_path.join(LAYERS_SUBDIR);

    // Get or create a connection pool to the database
    let pool = db::get_or_create_pool(&db_path, &db::OCI_DB_MIGRATOR).await?;

    // Apply image configuration defaults if enabled.
    if use_image_defaults {
        config::apply_image_defaults(sandbox_config, image, &pool).await?;
        tracing::debug!("updated sandbox config: {:#?}", sandbox_config);
    }

    // Get the layers for the image
    let digests = db::get_image_layer_digests(&pool, &image.to_string()).await?;
    let layers = db::get_layers_by_digest(&pool, &digests).await?;
    tracing::info!("found {} layers for image {}", layers.len(), image);

    // Get the extracted layer paths
    // TODO: Switch to using `LayerOps` trait
    let mut layer_paths = Vec::new();
    for layer in &layers {
        let layer_path = layers_dir.join(format!("{}.{}", layer.digest, EXTRACTED_LAYER_SUFFIX));
        if !layer_path.exists() {
            return Err(MicrosandboxError::PathNotFound(format!(
                "extracted layer {} not found at {}",
                layer.digest,
                layer_path.display()
            )));
        }
        tracing::info!("found extracted layer: {}", layer_path.display());
        layer_paths.push(layer_path);
    }

    // Get sandbox namespace
    let namespaced_name = PathBuf::from(config_file).join(sandbox_name);

    // Create the scripts directory
    let patch_dir = menv_path.join(PATCH_SUBDIR).join(&namespaced_name);
    let script_dir = patch_dir.join(SANDBOX_DIR).join(SCRIPTS_DIR);
    fs::create_dir_all(&script_dir).await?;
    tracing::info!("script_dir: {}", script_dir.display());

    // Create the top root path
    let top_rw_path = menv_path.join(RW_SUBDIR).join(&namespaced_name);
    fs::create_dir_all(&top_rw_path).await?;
    tracing::info!("top_rw_path: {}", top_rw_path.display());

    // Check if we need to patch rootfs (scripts, volumes, etc.)
    let should_patch = has_sandbox_config_changed(
        sandbox_pool,
        sandbox_name,
        config_file,
        config_last_modified,
    )
    .await?;

    // Only patch if sandbox doesn't exist or config has changed
    if should_patch {
        tracing::info!("patching sandbox - config has changed");

        // If `/.sandbox` exists at the top layer, delete it
        let rw_scripts_dir = top_rw_path.join(SANDBOX_DIR);
        if rw_scripts_dir.exists() {
            fs::remove_dir_all(&rw_scripts_dir).await?;
        }

        // Patch with sandbox scripts
        rootfs::patch_with_sandbox_scripts(
            &script_dir,
            &sandbox_config.get_scripts(),
            sandbox_config
                .get_shell()
                .as_ref()
                .unwrap_or(&DEFAULT_SHELL.to_string()),
        )
        .await?;

        // Patch with default DNS settings - check all layers
        let mut all_layers = layer_paths.clone();
        all_layers.push(patch_dir.clone());
        rootfs::patch_with_default_dns_settings(&all_layers).await?;

        // Patch with volume mounts if there are any volumes defined
        let volumes = &sandbox_config.get_volumes();
        if !volumes.is_empty() {
            tracing::info!("patching with {} volume mounts", volumes.len());
            rootfs::patch_with_virtiofs_mounts(&patch_dir, volumes).await?;
        }

        // Set stat override on the rootfs to ensure proper permissions inside the container
        rootfs::patch_with_stat_override(&top_rw_path).await?;
    } else {
        tracing::info!("skipping sandbox patch - config unchanged");
    }

    // Add FEX-Emu overlay layer for x86_64 emulation on ARM64
    #[cfg(target_os = "macos")] {
        let fex_path = get_fex_emulator_path();
        if fex_path.exists() {
            tracing::info!("Adding FEX-Emu overlay layer from {}", fex_path.display());
            layer_paths.push(fex_path);
        } else {
            tracing::debug!("FEX-Emu not found at {}, skipping overlay layer", fex_path.display());
        }
    }

    // Add the scripts and rootfs directories to the layer paths
    layer_paths.push(patch_dir);
    layer_paths.push(top_rw_path);

    Ok(Rootfs::Overlayfs(layer_paths))
}

async fn setup_native_rootfs(
    root_path: &Path,
    sandbox_name: &str,
    sandbox_config: &Sandbox,
    config_file: &str,
    config_last_modified: &DateTime<Utc>,
    sandbox_pool: &Pool<Sqlite>,
) -> MicrosandboxResult<Rootfs> {
    // Create the scripts directory
    let scripts_dir = root_path.join(SANDBOX_DIR).join(SCRIPTS_DIR);
    fs::create_dir_all(&scripts_dir).await?;

    // Check if we need to patch rootfs (scripts, volumes, etc.)
    let should_patch = has_sandbox_config_changed(
        sandbox_pool,
        sandbox_name,
        config_file,
        config_last_modified,
    )
    .await?;

    // Only patch if sandbox doesn't exist or config has changed
    if should_patch {
        tracing::info!("patching sandbox - config has changed");

        // Patch with sandbox scripts
        rootfs::patch_with_sandbox_scripts(
            &scripts_dir,
            &sandbox_config.get_scripts(),
            sandbox_config
                .get_shell()
                .as_ref()
                .unwrap_or(&DEFAULT_SHELL.to_string()),
        )
        .await?;

        // Patch with default DNS settings - for native rootfs, just pass the single root path
        rootfs::patch_with_default_dns_settings(&[root_path.to_path_buf()]).await?;

        // Patch with volume mounts if there are any volumes defined
        let volumes = &sandbox_config.get_volumes();
        if !volumes.is_empty() {
            tracing::info!("patching with {} volume mounts", volumes.len());
            // For native rootfs, mount points should be created under the root path
            rootfs::patch_with_virtiofs_mounts(root_path, volumes).await?;
        }

        // Set stat override on the rootfs to ensure proper permissions inside the container
        rootfs::patch_with_stat_override(root_path).await?;
    } else {
        tracing::info!("skipping sandbox patch - config unchanged");
    }

    Ok(Rootfs::Native(root_path.to_path_buf()))
}

/// Checks if a sandbox's configuration has changed by comparing the current config's last modified
/// timestamp with the stored timestamp in the database. Returns true if the sandbox doesn't exist
/// or if the config has been modified since the last run.
async fn has_sandbox_config_changed(
    sandbox_pool: &Pool<Sqlite>,
    sandbox_name: &str,
    config_file: &str,
    config_last_modified: &DateTime<Utc>,
) -> MicrosandboxResult<bool> {
    // Check if sandbox exists and config hasn't changed
    let sandbox = db::get_sandbox(sandbox_pool, sandbox_name, config_file).await?;
    Ok(match sandbox {
        Some(sandbox) => {
            // Compare timestamps to see if config has changed
            sandbox.config_last_modified != *config_last_modified
        }
        None => true, // No existing sandbox, need to patch
    })
}

/// Determines the execution command and arguments for a sandbox based on the provided configuration.
///
/// The function follows this priority order:
/// 1. Use the explicit exec command if provided
/// 2. Use the specified script name if provided
/// 3. Use the start script if it exists
/// 4. Use the exec command from sandbox config if it exists
/// 5. Fall back to the shell command from sandbox config
///
/// Only the command from the sandbox config (get_command) is split into executable path and arguments.
/// For all other sources, the command is treated as an executable path with no arguments.
///
/// ## Arguments
///
/// * `exec` - Optional explicit command to execute
/// * `script_name` - Optional name of the script to run
/// * `sandbox_config` - The sandbox configuration
/// * `sandbox_name` - The name of the sandbox (for error reporting)
///
/// ## Returns
///
/// Returns a tuple of (exec_path, args) or a `MicrosandboxError` if no valid
/// execution path could be determined.
pub fn determine_exec_path_and_args(
    exec: Option<&str>,
    script_name: Option<&str>,
    sandbox_config: &Sandbox,
    sandbox_name: &str,
) -> MicrosandboxResult<(String, Vec<String>)> {
    match exec {
        Some(exec) => Ok((exec.to_string(), Vec::new())),
        None => match script_name {
            Some(script_name) => {
                // Validate script exists
                if script_name != SHELL_SCRIPT_NAME
                    && !sandbox_config.get_scripts().contains_key(script_name)
                {
                    return Err(MicrosandboxError::ScriptNotFoundInSandbox(
                        script_name.to_string(),
                        sandbox_name.to_string(),
                    ));
                }

                let script_path = format!("{}/{}/{}", SANDBOX_DIR, SCRIPTS_DIR, script_name);
                Ok((script_path, Vec::new()))
            }
            None => match sandbox_config.get_scripts().get(START_SCRIPT_NAME) {
                Some(_) => {
                    let script_path =
                        format!("{}/{}/{}", SANDBOX_DIR, SCRIPTS_DIR, START_SCRIPT_NAME);
                    Ok((script_path, Vec::new()))
                }
                None => {
                    let command = sandbox_config.get_command();
                    if !command.is_empty() {
                        // First element is the command, rest are arguments
                        let cmd = command[0].clone();
                        let args = command.iter().skip(1).cloned().collect();
                        Ok((cmd, args))
                    } else {
                        sandbox_config
                            .get_shell()
                            .as_ref()
                            .map(|s| (s.to_string(), Vec::new()))
                            .ok_or(MicrosandboxError::MissingStartOrExecOrShell)
                    }
                }
            },
        },
    }
}
