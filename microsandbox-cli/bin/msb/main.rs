#[path = "mod.rs"]
mod msb;

use clap::{CommandFactory, Parser};
use microsandbox_cli::{
    AnsiStyles, MicrosandboxArgs, MicrosandboxCliResult, MicrosandboxSubcommand, ServerSubcommand,
};
use microsandbox_core::{management::orchestra, oci::Image};
use msb::handlers;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const SHELL_SCRIPT: &str = "shell";

//--------------------------------------------------------------------------------------------------
// Functions: main
//--------------------------------------------------------------------------------------------------

#[tokio::main]
async fn main() -> MicrosandboxCliResult<()> {
    // Parse command line arguments
    let args = MicrosandboxArgs::parse();

    handlers::log_level(&args);
    tracing_subscriber::fmt::init();

    // Print version if requested
    if args.version {
        println!("{}", format!("v{}", env!("CARGO_PKG_VERSION")).literal());
        return Ok(());
    }

    match args.subcommand {
        Some(MicrosandboxSubcommand::Init { file }) => {
            let (path, _) = handlers::parse_file_path(file);
            handlers::init_subcommand(path).await?;
        }
        Some(MicrosandboxSubcommand::Add {
            sandbox,
            build,
            names,
            image,
            memory,
            cpus,
            volumes,
            ports,
            envs,
            env_file,
            depends_on,
            workdir,
            shell,
            scripts,
            start,
            imports,
            exports,
            scope,
            file,
        }) => {
            let (path, config) = handlers::parse_file_path(file);
            handlers::add_subcommand(
                sandbox, build, names, image, memory, cpus, volumes, ports, envs, env_file,
                depends_on, workdir, shell, scripts, start, imports, exports, scope, path, config,
            )
            .await?;
        }
        Some(MicrosandboxSubcommand::Remove {
            sandbox,
            build,
            names,
            file,
        }) => {
            handlers::remove_subcommand(sandbox, build, names, file).await?;
        }
        Some(MicrosandboxSubcommand::List {
            sandbox,
            build,
            file,
        }) => {
            handlers::list_subcommand(sandbox, build, file).await?;
        }
        Some(MicrosandboxSubcommand::Pull { name, layer_path }) => {
            Image::pull(name, layer_path).await?;
        }
        Some(MicrosandboxSubcommand::Run {
            sandbox,
            build,
            name,
            file,
            detach,
            exec,
            args,
        }) => {
            handlers::run_subcommand(sandbox, build, name, file, detach, exec, args).await?;
        }
        Some(MicrosandboxSubcommand::Shell {
            sandbox,
            build,
            name,
            file,
            detach,
            args,
        }) => {
            handlers::script_run_subcommand(
                sandbox,
                build,
                name,
                SHELL_SCRIPT.to_string(),
                file,
                detach,
                args,
            )
            .await?;
        }
        Some(MicrosandboxSubcommand::Exe {
            image: _image,
            name,
            cpus,
            memory,
            volumes,
            ports,
            envs,
            workdir,
            scope,
            exec,
            args,
        }) => {
            handlers::exe_subcommand(
                name, cpus, memory, volumes, ports, envs, workdir, scope, exec, args,
            )
            .await?;
        }
        Some(MicrosandboxSubcommand::Install {
            image: _image,
            name,
            alias,
            cpus,
            memory,
            volumes,
            ports,
            envs,
            workdir,
            scope,
            exec,
            args,
        }) => {
            handlers::install_subcommand(
                name, alias, cpus, memory, volumes, ports, envs, workdir, scope, exec, args,
            )
            .await?;
        }
        Some(MicrosandboxSubcommand::Uninstall { script }) => {
            handlers::uninstall_subcommand(script).await?;
        }
        Some(MicrosandboxSubcommand::Apply { file, detach }) => {
            let (path, config) = handlers::parse_file_path(file);
            orchestra::apply(path.as_deref(), config.as_deref(), detach).await?;
        }
        Some(MicrosandboxSubcommand::Up {
            sandbox,
            build,
            names,
            file,
            detach,
        }) => {
            handlers::up_subcommand(sandbox, build, names, file, detach).await?;
        }
        Some(MicrosandboxSubcommand::Down {
            sandbox,
            build,
            names,
            file,
        }) => {
            handlers::down_subcommand(sandbox, build, names, file).await?;
        }
        Some(MicrosandboxSubcommand::Status {
            sandbox,
            build,
            names,
            file,
        }) => {
            handlers::status_subcommand(sandbox, build, names, file).await?;
        }
        Some(MicrosandboxSubcommand::Log {
            sandbox,
            build,
            name,
            file,
            follow,
            tail,
        }) => {
            handlers::log_subcommand(sandbox, build, name, file, follow, tail).await?;
        }
        Some(MicrosandboxSubcommand::Clean {
            sandbox,
            name,
            user,
            all,
            file,
            force,
        }) => {
            handlers::clean_subcommand(sandbox, name, user, all, file, force).await?;
        }
        Some(MicrosandboxSubcommand::Self_ { action }) => {
            handlers::self_subcommand(action).await?;
        }
        Some(MicrosandboxSubcommand::Server { subcommand }) => match subcommand {
            ServerSubcommand::Start {
                host,
                port,
                namespace_dir,
                dev_mode,
                key,
                detach,
                reset_key,
            } => {
                handlers::server_start_subcommand(
                    host,
                    port,
                    namespace_dir,
                    dev_mode,
                    key,
                    detach,
                    reset_key,
                )
                .await?;
            }
            ServerSubcommand::Stop => {
                handlers::server_stop_subcommand().await?;
            }
            ServerSubcommand::Keygen { expire, namespace } => {
                handlers::server_keygen_subcommand(expire, namespace).await?;
            }
            ServerSubcommand::Log {
                sandbox,
                name,
                namespace,
                follow,
                tail,
            } => {
                handlers::server_log_subcommand(sandbox, name, namespace, follow, tail).await?;
            }
            ServerSubcommand::List { namespace } => {
                handlers::server_list_subcommand(namespace).await?;
            }
            ServerSubcommand::Status {
                sandbox,
                names,
                namespace,
            } => {
                handlers::server_status_subcommand(sandbox, names, namespace).await?;
            }
            ServerSubcommand::Ssh {
                namespace,
                sandbox,
                name,
            } => {
                handlers::server_ssh_subcommand(namespace, sandbox, name).await?;
            }
        },
        Some(MicrosandboxSubcommand::Login) => {
            handlers::login_subcommand().await?;
        }
        Some(MicrosandboxSubcommand::Push { image, name }) => {
            handlers::push_subcommand(image, name).await?;
        }
        Some(_) => (), // TODO: implement other subcommands
        None => {
            MicrosandboxArgs::command().print_help()?;
        }
    }

    Ok(())
}
