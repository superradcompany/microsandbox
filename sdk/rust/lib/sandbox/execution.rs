//! Guest execution prepares a resource once and pins the selected runtime.

use super::{
    AttachOptionsBuilder, ExecOptionsBuilder, ExecOutput, Sandbox,
    agent_lease::PreparedAgent,
    exec::{ExecHandle, ExecOptions, agent},
    state::RuntimeSession,
};
use crate::MicrosandboxResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

enum ExecCommand {
    Explicit {
        program: String,
        explicit_argv: bool,
    },
    Default,
    Shell,
}

//--------------------------------------------------------------------------------------------------
// Methods: ExecCommand
//--------------------------------------------------------------------------------------------------

impl ExecCommand {
    fn resolve(
        self,
        session: &RuntimeSession,
        args: &mut Vec<String>,
    ) -> MicrosandboxResult<(String, bool)> {
        match self {
            Self::Explicit {
                program,
                explicit_argv,
            } => Ok((program, explicit_argv)),
            Self::Default => {
                let resolved = session.default_command()?;
                args.splice(0..0, resolved.args);
                Ok((resolved.program, false))
            }
            Self::Shell => Ok((session.shell(), true)),
        }
    }

    fn resolve_attach(
        self,
        session: &RuntimeSession,
        options: AttachOptionsBuilder,
    ) -> MicrosandboxResult<(String, AttachOptionsBuilder)> {
        match self {
            Self::Explicit { program, .. } => Ok((program, options)),
            Self::Default => {
                let resolved = session.default_command()?;
                Ok((resolved.program, options.prepend_args(resolved.args)))
            }
            Self::Shell => Ok((session.shell(), options)),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Execution
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Execute the sandbox's effective OCI entrypoint and CMD and return a streaming handle.
    pub async fn exec_default_stream(&self) -> MicrosandboxResult<ExecHandle> {
        self.exec_default_stream_with(|options| options).await
    }

    /// Execute the sandbox's effective OCI entrypoint and CMD with full streaming options.
    ///
    /// Arguments configured through the options builder are appended after the resolved default
    /// argv. They are execution arguments, not an OCI CMD override.
    pub async fn exec_default_stream_with(
        &self,
        f: impl FnOnce(ExecOptionsBuilder) -> ExecOptionsBuilder,
    ) -> MicrosandboxResult<ExecHandle> {
        let opts = f(ExecOptionsBuilder::default()).build()?;
        self.execute_stream(ExecCommand::Default, opts).await
    }

    /// Execute the sandbox's effective OCI entrypoint and CMD and wait for completion.
    pub async fn exec_default(&self) -> MicrosandboxResult<ExecOutput> {
        self.exec_default_with(|options| options).await
    }

    /// Execute the sandbox's effective OCI entrypoint and CMD with full options.
    ///
    /// Arguments configured through the options builder are appended after the resolved default
    /// argv. They are execution arguments, not an OCI CMD override.
    pub async fn exec_default_with(
        &self,
        f: impl FnOnce(ExecOptionsBuilder) -> ExecOptionsBuilder,
    ) -> MicrosandboxResult<ExecOutput> {
        let opts = f(ExecOptionsBuilder::default()).build()?;
        self.execute_buffered(ExecCommand::Default, opts).await
    }

    /// Execute a command and return a streaming handle.
    ///
    /// ```ignore
    /// let mut handle = sb.exec_stream("tail", ["-f", "/var/log/app.log"]).await?;
    /// ```
    pub async fn exec_stream(
        &self,
        cmd: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> MicrosandboxResult<ExecHandle> {
        let opts = ExecOptions {
            args: args.into_iter().map(Into::into).collect(),
            ..Default::default()
        };
        self.execute_stream(
            ExecCommand::Explicit {
                program: cmd.into(),
                explicit_argv: true,
            },
            opts,
        )
        .await
    }

    /// Execute a command with full options and return a streaming handle.
    ///
    /// ```ignore
    /// let mut handle = sb.exec_stream_with("python", |e| e.stdin_pipe().tty(true)).await?;
    /// ```
    pub async fn exec_stream_with(
        &self,
        cmd: impl Into<String>,
        f: impl FnOnce(ExecOptionsBuilder) -> ExecOptionsBuilder,
    ) -> MicrosandboxResult<ExecHandle> {
        let builder = f(ExecOptionsBuilder::default());
        let explicit_argv = builder.explicit_argv();
        let opts = builder.build()?;
        self.execute_stream(
            ExecCommand::Explicit {
                program: cmd.into(),
                explicit_argv,
            },
            opts,
        )
        .await
    }

    /// Execute a command and wait for completion.
    ///
    /// ```ignore
    /// let output = sb.exec("python", ["-c", "print('hi')"]).await?;
    /// ```
    pub async fn exec(
        &self,
        cmd: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> MicrosandboxResult<ExecOutput> {
        let opts = ExecOptions {
            args: args.into_iter().map(Into::into).collect(),
            ..Default::default()
        };
        self.execute_buffered(
            ExecCommand::Explicit {
                program: cmd.into(),
                explicit_argv: true,
            },
            opts,
        )
        .await
    }

    /// Execute a command with full options and wait for completion.
    ///
    /// ```ignore
    /// let output = sb.exec_with("python", |e| e.args(["compute.py"]).cwd("/app")).await?;
    /// ```
    pub async fn exec_with(
        &self,
        cmd: impl Into<String>,
        f: impl FnOnce(ExecOptionsBuilder) -> ExecOptionsBuilder,
    ) -> MicrosandboxResult<ExecOutput> {
        let builder = f(ExecOptionsBuilder::default());
        let explicit_argv = builder.explicit_argv();
        let opts = builder.build()?;
        self.execute_buffered(
            ExecCommand::Explicit {
                program: cmd.into(),
                explicit_argv,
            },
            opts,
        )
        .await
    }

    /// Run a shell command and wait for completion.
    ///
    /// Uses the sandbox's configured shell (default: `/bin/sh`) to interpret
    /// the script via `<shell> -c "<script>"`.
    ///
    /// - `sandbox.shell("echo hello")`
    /// - `sandbox.shell("ENV=val cmd | other_cmd")`
    pub async fn shell(&self, script: impl Into<String>) -> MicrosandboxResult<ExecOutput> {
        let opts = ExecOptions {
            args: vec!["-c".to_string(), script.into()],
            ..Default::default()
        };
        self.execute_buffered(ExecCommand::Shell, opts).await
    }

    /// Run a shell command with full options and wait for completion.
    pub async fn shell_with(
        &self,
        script: impl Into<String>,
        f: impl FnOnce(ExecOptionsBuilder) -> ExecOptionsBuilder,
    ) -> MicrosandboxResult<ExecOutput> {
        let mut opts = f(ExecOptionsBuilder::default()).build()?;
        opts.args.splice(0..0, ["-c".to_string(), script.into()]);
        self.execute_buffered(ExecCommand::Shell, opts).await
    }

    /// Run a shell command with streaming I/O.
    ///
    /// Like [`shell`](Self::shell) but returns a streaming [`ExecHandle`]
    /// instead of waiting for completion.
    pub async fn shell_stream(&self, script: impl Into<String>) -> MicrosandboxResult<ExecHandle> {
        let opts = ExecOptions {
            args: vec!["-c".to_string(), script.into()],
            ..Default::default()
        };
        self.execute_stream(ExecCommand::Shell, opts).await
    }

    /// Run a shell command with full options and streaming I/O.
    pub async fn shell_stream_with(
        &self,
        script: impl Into<String>,
        f: impl FnOnce(ExecOptionsBuilder) -> ExecOptionsBuilder,
    ) -> MicrosandboxResult<ExecHandle> {
        let mut opts = f(ExecOptionsBuilder::default()).build()?;
        opts.args.splice(0..0, ["-c".to_string(), script.into()]);
        self.execute_stream(ExecCommand::Shell, opts).await
    }
}

impl Sandbox {
    async fn execute_stream(
        &self,
        command: ExecCommand,
        mut options: ExecOptions,
    ) -> MicrosandboxResult<ExecHandle> {
        match self.open_agent().await? {
            PreparedAgent::Direct(lease) => {
                let (program, explicit_argv) =
                    command.resolve(&lease.session, &mut options.args)?;
                let mut execution = agent::exec_stream_on_connection(
                    lease.connection,
                    &self.name,
                    &lease.session.config,
                    program,
                    options,
                    (24, 80),
                    explicit_argv,
                )
                .await?;
                execution.retain_runtime(lease.session);
                Ok(execution)
            }
            PreparedAgent::Fallback(session) => {
                let (program, _) = command.resolve(&session, &mut options.args)?;
                let mut execution = self
                    .backend
                    .sandbox_ops()
                    .exec_stream(
                        self.backend.clone(),
                        &self.name,
                        &session.config,
                        program,
                        options,
                    )
                    .await?;
                execution.retain_runtime(session);
                Ok(execution)
            }
        }
    }

    async fn execute_buffered(
        &self,
        command: ExecCommand,
        mut options: ExecOptions,
    ) -> MicrosandboxResult<ExecOutput> {
        match self.open_agent().await? {
            PreparedAgent::Direct(lease) => {
                let timeout = options.timeout.take();
                let (program, explicit_argv) =
                    command.resolve(&lease.session, &mut options.args)?;
                let mut execution = agent::exec_stream_on_connection(
                    lease.connection,
                    &self.name,
                    &lease.session.config,
                    program,
                    options,
                    (24, 80),
                    explicit_argv,
                )
                .await?;
                execution.retain_runtime(lease.session);
                agent::collect_buffered(execution, timeout).await
            }
            PreparedAgent::Fallback(session) => {
                let (program, _) = command.resolve(&session, &mut options.args)?;
                self.backend
                    .sandbox_ops()
                    .exec(
                        self.backend.clone(),
                        &self.name,
                        &session.config,
                        program,
                        options,
                    )
                    .await
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Attach
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Attach to the sandbox's effective OCI entrypoint and CMD.
    pub async fn attach_default(&self) -> MicrosandboxResult<i32> {
        self.attach_default_with(|options| options).await
    }

    /// Attach to the sandbox's effective OCI entrypoint and CMD with full options.
    ///
    /// Arguments configured through the options builder are appended after the resolved default
    /// argv. They are execution arguments, not an OCI CMD override.
    pub async fn attach_default_with(
        &self,
        f: impl FnOnce(AttachOptionsBuilder) -> AttachOptionsBuilder,
    ) -> MicrosandboxResult<i32> {
        let builder = f(AttachOptionsBuilder::default()).with_inherited_command(true);
        self.attach_command(ExecCommand::Default, builder).await
    }

    /// Attach to the sandbox with an interactive terminal session.
    ///
    /// ```ignore
    /// let exit_code = sb.attach("bash", ["-l"]).await?;
    /// ```
    pub async fn attach(
        &self,
        cmd: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> MicrosandboxResult<i32> {
        let mut builder = AttachOptionsBuilder::default();
        for arg in args {
            builder = builder.arg(arg);
        }
        self.attach_command(
            ExecCommand::Explicit {
                program: cmd.into(),
                explicit_argv: true,
            },
            builder,
        )
        .await
    }

    /// Attach to the sandbox with full options.
    ///
    /// ```ignore
    /// let exit_code = sb.attach_with("zsh", |a| a.env("TERM", "xterm").detach_keys("ctrl-q")).await?;
    /// ```
    pub async fn attach_with(
        &self,
        cmd: impl Into<String>,
        f: impl FnOnce(AttachOptionsBuilder) -> AttachOptionsBuilder,
    ) -> MicrosandboxResult<i32> {
        let builder = f(AttachOptionsBuilder::default());
        self.attach_command(
            ExecCommand::Explicit {
                program: cmd.into(),
                explicit_argv: true,
            },
            builder,
        )
        .await
    }

    /// Attach to the sandbox's default shell.
    ///
    /// Uses the sandbox's configured shell (default: `/bin/sh`).
    pub async fn attach_shell(&self) -> MicrosandboxResult<i32> {
        self.attach_command(ExecCommand::Shell, AttachOptionsBuilder::default())
            .await
    }
}

impl Sandbox {
    async fn attach_command(
        &self,
        command: ExecCommand,
        options: AttachOptionsBuilder,
    ) -> MicrosandboxResult<i32> {
        match self.open_agent().await? {
            PreparedAgent::Direct(lease) => {
                let (program, options) = command.resolve_attach(&lease.session, options)?;
                super::attach::agent::attach_on_client(
                    lease.connection.into_client(),
                    &lease.session.config,
                    program,
                    options,
                )
                .await
            }
            PreparedAgent::Fallback(session) => {
                let (program, options) = command.resolve_attach(&session, options)?;
                self.backend
                    .sandbox_ops()
                    .attach(
                        self.backend.clone(),
                        &self.name,
                        &session.config,
                        program,
                        options,
                    )
                    .await
            }
        }
    }
}
