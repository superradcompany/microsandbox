//! Guest execution prepares a resource once and pins the selected runtime.

use std::sync::Arc;

use super::{
    AttachOptionsBuilder, ExecOptionsBuilder, ExecOutput, Sandbox,
    exec::{ExecHandle, ExecOptions, agent},
    state::RuntimeSession,
};
use crate::MicrosandboxResult;

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
        let session = self.prepare_runtime().await?;
        let command = microsandbox_types::resolve_default_command(
            session.config.spec.runtime.entrypoint.as_deref(),
            session.config.spec.runtime.cmd.as_deref(),
            None,
        )?;
        let opts = f(ExecOptionsBuilder::default())
            .prepend_args(command.args)
            .build()?;
        self.execute_stream_prepared(session, command.program, opts, false)
            .await
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
        let session = self.prepare_runtime().await?;
        let command = microsandbox_types::resolve_default_command(
            session.config.spec.runtime.entrypoint.as_deref(),
            session.config.spec.runtime.cmd.as_deref(),
            None,
        )?;
        let opts = f(ExecOptionsBuilder::default())
            .prepend_args(command.args)
            .build()?;
        self.execute_prepared(session, command.program, opts, false)
            .await
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
        let session = self.prepare_runtime().await?;
        let opts = ExecOptions {
            args: args.into_iter().map(Into::into).collect(),
            ..Default::default()
        };
        self.execute_stream_prepared(session, cmd.into(), opts, true)
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
        let session = self.prepare_runtime().await?;
        self.execute_stream_prepared(session, cmd.into(), opts, explicit_argv)
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
        let session = self.prepare_runtime().await?;
        let opts = ExecOptions {
            args: args.into_iter().map(Into::into).collect(),
            ..Default::default()
        };
        self.execute_prepared(session, cmd.into(), opts, true).await
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
        let session = self.prepare_runtime().await?;
        self.execute_prepared(session, cmd.into(), opts, explicit_argv)
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
        let session = self.prepare_runtime().await?;
        let shell = session
            .config
            .spec
            .runtime
            .shell
            .as_deref()
            .unwrap_or("/bin/sh")
            .to_string();
        let opts = ExecOptions {
            args: vec!["-c".to_string(), script.into()],
            ..Default::default()
        };
        self.execute_prepared(session, shell, opts, true).await
    }

    /// Run a shell command with full options and wait for completion.
    pub async fn shell_with(
        &self,
        script: impl Into<String>,
        f: impl FnOnce(ExecOptionsBuilder) -> ExecOptionsBuilder,
    ) -> MicrosandboxResult<ExecOutput> {
        let session = self.prepare_runtime().await?;
        let shell = session
            .config
            .spec
            .runtime
            .shell
            .as_deref()
            .unwrap_or("/bin/sh")
            .to_string();
        let mut opts = f(ExecOptionsBuilder::default()).build()?;
        opts.args.splice(0..0, ["-c".to_string(), script.into()]);
        self.execute_prepared(session, shell, opts, true).await
    }

    /// Run a shell command with streaming I/O.
    ///
    /// Like [`shell`](Self::shell) but returns a streaming [`ExecHandle`]
    /// instead of waiting for completion.
    pub async fn shell_stream(&self, script: impl Into<String>) -> MicrosandboxResult<ExecHandle> {
        let session = self.prepare_runtime().await?;
        let shell = session
            .config
            .spec
            .runtime
            .shell
            .as_deref()
            .unwrap_or("/bin/sh")
            .to_string();
        let opts = ExecOptions {
            args: vec!["-c".to_string(), script.into()],
            ..Default::default()
        };
        self.execute_stream_prepared(session, shell, opts, true)
            .await
    }

    /// Run a shell command with full options and streaming I/O.
    pub async fn shell_stream_with(
        &self,
        script: impl Into<String>,
        f: impl FnOnce(ExecOptionsBuilder) -> ExecOptionsBuilder,
    ) -> MicrosandboxResult<ExecHandle> {
        let session = self.prepare_runtime().await?;
        let shell = session
            .config
            .spec
            .runtime
            .shell
            .as_deref()
            .unwrap_or("/bin/sh")
            .to_string();
        let mut opts = f(ExecOptionsBuilder::default()).build()?;
        opts.args.splice(0..0, ["-c".to_string(), script.into()]);
        self.execute_stream_prepared(session, shell, opts, true)
            .await
    }
}

impl Sandbox {
    async fn execute_stream_prepared(
        &self,
        session: Arc<RuntimeSession>,
        command: String,
        options: ExecOptions,
        explicit_argv: bool,
    ) -> MicrosandboxResult<ExecHandle> {
        #[cfg(feature = "local")]
        if let crate::context::SandboxInner::Local(local) = &session.inner {
            let mut execution = agent::exec_stream_on_client(
                local.client.clone(),
                &self.name,
                &session.config,
                command,
                options,
                (24, 80),
                explicit_argv,
            )
            .await?;
            execution.retain_runtime(session);
            return Ok(execution);
        }
        let mut execution = self
            .backend
            .sandbox_ops()
            .exec_stream(
                self.backend.clone(),
                &self.name,
                &session.config,
                command,
                options,
            )
            .await?;
        execution.retain_runtime(session);
        Ok(execution)
    }

    async fn execute_prepared(
        &self,
        session: Arc<RuntimeSession>,
        command: String,
        mut options: ExecOptions,
        explicit_argv: bool,
    ) -> MicrosandboxResult<ExecOutput> {
        #[cfg(feature = "local")]
        if matches!(&session.inner, crate::context::SandboxInner::Local(_)) {
            // Preserve buffered execution's existing deadline/kill contract.
            let timeout = options.timeout.take();
            let execution = self
                .execute_stream_prepared(session, command, options, explicit_argv)
                .await?;
            return agent::collect_buffered(execution, timeout).await;
        }
        self.backend
            .sandbox_ops()
            .exec(
                self.backend.clone(),
                &self.name,
                &session.config,
                command,
                options,
            )
            .await
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
        let session = self.prepare_runtime().await?;
        let command = microsandbox_types::resolve_default_command(
            session.config.spec.runtime.entrypoint.as_deref(),
            session.config.spec.runtime.cmd.as_deref(),
            None,
        )?;
        let builder = f(AttachOptionsBuilder::default())
            .prepend_args(command.args)
            .with_inherited_command(true);
        self.attach_prepared(session, command.program, builder)
            .await
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
        let session = self.prepare_runtime().await?;
        let mut builder = AttachOptionsBuilder::default();
        for arg in args {
            builder = builder.arg(arg);
        }
        self.attach_prepared(session, cmd.into(), builder).await
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
        let session = self.prepare_runtime().await?;
        self.attach_prepared(session, cmd.into(), builder).await
    }

    /// Attach to the sandbox's default shell.
    ///
    /// Uses the sandbox's configured shell (default: `/bin/sh`).
    pub async fn attach_shell(&self) -> MicrosandboxResult<i32> {
        let session = self.prepare_runtime().await?;
        let shell = session
            .config
            .spec
            .runtime
            .shell
            .as_deref()
            .unwrap_or("/bin/sh")
            .to_string();
        self.attach_prepared(session, shell, AttachOptionsBuilder::default())
            .await
    }
}

impl Sandbox {
    async fn attach_prepared(
        &self,
        session: Arc<RuntimeSession>,
        command: String,
        options: AttachOptionsBuilder,
    ) -> MicrosandboxResult<i32> {
        #[cfg(feature = "local")]
        if let crate::context::SandboxInner::Local(local) = &session.inner {
            return super::attach::agent::attach_on_client(
                local.client.clone(),
                &session.config,
                command,
                options,
            )
            .await;
        }
        self.backend
            .sandbox_ops()
            .attach(
                self.backend.clone(),
                &self.name,
                &session.config,
                command,
                options,
            )
            .await
    }
}
