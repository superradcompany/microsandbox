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
        let (session, from_cache) = self.prepare_runtime_tracked().await?;
        let command = microsandbox_types::resolve_default_command(
            session.config.spec.runtime.entrypoint.as_deref(),
            session.config.spec.runtime.cmd.as_deref(),
            None,
        )?;
        let opts = f(ExecOptionsBuilder::default()).build()?;
        self.execute_stream_with_default_command(session, from_cache, command, opts)
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
        let (session, from_cache) = self.prepare_runtime_tracked().await?;
        let command = microsandbox_types::resolve_default_command(
            session.config.spec.runtime.entrypoint.as_deref(),
            session.config.spec.runtime.cmd.as_deref(),
            None,
        )?;
        let opts = f(ExecOptionsBuilder::default()).build()?;
        self.execute_with_default_command(session, from_cache, command, opts)
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
        let (session, from_cache) = self.prepare_runtime_tracked().await?;
        let opts = ExecOptions {
            args: args.into_iter().map(Into::into).collect(),
            ..Default::default()
        };
        self.execute_stream_prepared(session, from_cache, cmd.into(), opts, true)
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
        let (session, from_cache) = self.prepare_runtime_tracked().await?;
        self.execute_stream_prepared(session, from_cache, cmd.into(), opts, explicit_argv)
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
        let (session, from_cache) = self.prepare_runtime_tracked().await?;
        let opts = ExecOptions {
            args: args.into_iter().map(Into::into).collect(),
            ..Default::default()
        };
        self.execute_prepared(session, from_cache, cmd.into(), opts, true)
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
        let (session, from_cache) = self.prepare_runtime_tracked().await?;
        self.execute_prepared(session, from_cache, cmd.into(), opts, explicit_argv)
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
        let (session, from_cache) = self.prepare_runtime_tracked().await?;
        let opts = ExecOptions {
            args: vec!["-c".to_string(), script.into()],
            ..Default::default()
        };
        self.execute_shell(session, from_cache, opts).await
    }

    /// Run a shell command with full options and wait for completion.
    pub async fn shell_with(
        &self,
        script: impl Into<String>,
        f: impl FnOnce(ExecOptionsBuilder) -> ExecOptionsBuilder,
    ) -> MicrosandboxResult<ExecOutput> {
        let (session, from_cache) = self.prepare_runtime_tracked().await?;
        let mut opts = f(ExecOptionsBuilder::default()).build()?;
        opts.args.splice(0..0, ["-c".to_string(), script.into()]);
        self.execute_shell(session, from_cache, opts).await
    }

    /// Run a shell command with streaming I/O.
    ///
    /// Like [`shell`](Self::shell) but returns a streaming [`ExecHandle`]
    /// instead of waiting for completion.
    pub async fn shell_stream(&self, script: impl Into<String>) -> MicrosandboxResult<ExecHandle> {
        let (session, from_cache) = self.prepare_runtime_tracked().await?;
        let opts = ExecOptions {
            args: vec!["-c".to_string(), script.into()],
            ..Default::default()
        };
        self.execute_shell_stream(session, from_cache, opts).await
    }

    /// Run a shell command with full options and streaming I/O.
    pub async fn shell_stream_with(
        &self,
        script: impl Into<String>,
        f: impl FnOnce(ExecOptionsBuilder) -> ExecOptionsBuilder,
    ) -> MicrosandboxResult<ExecHandle> {
        let (session, from_cache) = self.prepare_runtime_tracked().await?;
        let mut opts = f(ExecOptionsBuilder::default()).build()?;
        opts.args.splice(0..0, ["-c".to_string(), script.into()]);
        self.execute_shell_stream(session, from_cache, opts).await
    }
}

impl Sandbox {
    async fn execute_stream_with_default_command(
        &self,
        session: Arc<RuntimeSession>,
        from_cache: bool,
        mut command: microsandbox_types::ResolvedCommand,
        mut options: ExecOptions,
    ) -> MicrosandboxResult<ExecHandle> {
        #[cfg(feature = "cloud")]
        if self.backend.as_cloud().is_some()
            && matches!(&session.inner, crate::context::SandboxInner::Cloud(_))
        {
            let (fresh_session, connection) = self
                .connect_cloud_connection(Arc::clone(&session), from_cache)
                .await?;
            if !Arc::ptr_eq(&fresh_session, &session) {
                command = microsandbox_types::resolve_default_command(
                    fresh_session.config.spec.runtime.entrypoint.as_deref(),
                    fresh_session.config.spec.runtime.cmd.as_deref(),
                    None,
                )?;
            }
            options.args.splice(0..0, command.args);
            let mut execution = agent::exec_stream_on_connection(
                connection,
                &self.name,
                &fresh_session.config,
                command.program,
                options,
                (24, 80),
                true,
            )
            .await?;
            execution.retain_runtime(fresh_session);
            return Ok(execution);
        }

        options.args.splice(0..0, command.args);
        self.execute_stream_prepared(session, from_cache, command.program, options, false)
            .await
    }

    async fn execute_with_default_command(
        &self,
        session: Arc<RuntimeSession>,
        from_cache: bool,
        command: microsandbox_types::ResolvedCommand,
        mut options: ExecOptions,
    ) -> MicrosandboxResult<ExecOutput> {
        #[cfg(feature = "cloud")]
        if self.backend.as_cloud().is_some()
            && matches!(&session.inner, crate::context::SandboxInner::Cloud(_))
        {
            let timeout = options.timeout.take();
            let execution = self
                .execute_stream_with_default_command(session, from_cache, command, options)
                .await?;
            return agent::collect_buffered(execution, timeout).await;
        }

        options.args.splice(0..0, command.args);
        self.execute_prepared(session, from_cache, command.program, options, false)
            .await
    }

    async fn execute_shell_stream(
        &self,
        session: Arc<RuntimeSession>,
        from_cache: bool,
        options: ExecOptions,
    ) -> MicrosandboxResult<ExecHandle> {
        #[cfg(feature = "cloud")]
        if self.backend.as_cloud().is_some()
            && matches!(&session.inner, crate::context::SandboxInner::Cloud(_))
        {
            let (session, connection) = self.connect_cloud_connection(session, from_cache).await?;
            let shell = configured_shell(&session);
            let mut execution = agent::exec_stream_on_connection(
                connection,
                &self.name,
                &session.config,
                shell,
                options,
                (24, 80),
                true,
            )
            .await?;
            execution.retain_runtime(session);
            return Ok(execution);
        }

        let shell = configured_shell(&session);
        self.execute_stream_prepared(session, from_cache, shell, options, true)
            .await
    }

    async fn execute_shell(
        &self,
        session: Arc<RuntimeSession>,
        from_cache: bool,
        mut options: ExecOptions,
    ) -> MicrosandboxResult<ExecOutput> {
        #[cfg(feature = "cloud")]
        if self.backend.as_cloud().is_some()
            && matches!(&session.inner, crate::context::SandboxInner::Cloud(_))
        {
            let timeout = options.timeout.take();
            let execution = self
                .execute_shell_stream(session, from_cache, options)
                .await?;
            return agent::collect_buffered(execution, timeout).await;
        }

        let shell = configured_shell(&session);
        self.execute_prepared(session, from_cache, shell, options, true)
            .await
    }

    async fn execute_stream_prepared(
        &self,
        session: Arc<RuntimeSession>,
        from_cache: bool,
        command: String,
        options: ExecOptions,
        explicit_argv: bool,
    ) -> MicrosandboxResult<ExecHandle> {
        #[cfg(not(feature = "cloud"))]
        let _ = from_cache;
        #[cfg(not(feature = "local"))]
        let _ = explicit_argv;

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

        #[cfg(feature = "cloud")]
        if self.backend.as_cloud().is_some()
            && matches!(&session.inner, crate::context::SandboxInner::Cloud(_))
        {
            let (session, connection) = self.connect_cloud_connection(session, from_cache).await?;
            let mut execution = agent::exec_stream_on_connection(
                connection,
                &self.name,
                &session.config,
                command,
                options,
                (24, 80),
                true,
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
        from_cache: bool,
        command: String,
        mut options: ExecOptions,
        explicit_argv: bool,
    ) -> MicrosandboxResult<ExecOutput> {
        #[cfg(not(feature = "cloud"))]
        let _ = from_cache;

        #[cfg(feature = "local")]
        if matches!(&session.inner, crate::context::SandboxInner::Local(_)) {
            // Preserve buffered execution's existing deadline/kill contract.
            let timeout = options.timeout.take();
            let execution = self
                .execute_stream_prepared(session, from_cache, command, options, explicit_argv)
                .await?;
            return agent::collect_buffered(execution, timeout).await;
        }

        #[cfg(feature = "cloud")]
        if self.backend.as_cloud().is_some()
            && matches!(&session.inner, crate::context::SandboxInner::Cloud(_))
        {
            let timeout = options.timeout.take();
            let execution = self
                .execute_stream_prepared(session, from_cache, command, options, explicit_argv)
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

    #[cfg(feature = "cloud")]
    async fn connect_cloud_connection(
        &self,
        session: Arc<RuntimeSession>,
        from_cache: bool,
    ) -> MicrosandboxResult<(Arc<RuntimeSession>, crate::agent::AgentConnection)> {
        match crate::agent::connect_for(self.backend.as_ref(), &self.name).await {
            Ok(connection) => Ok((session, connection)),
            Err(error) if from_cache && crate::context::is_cloud_sandbox_not_running(&error) => {
                let fresh = self.recover_cloud_runtime(&session).await?;
                let connection =
                    crate::agent::connect_for(self.backend.as_ref(), &self.name).await?;
                Ok((fresh, connection))
            }
            Err(error) => Err(error),
        }
    }

    #[cfg(feature = "cloud")]
    async fn connect_cloud_agent_client(
        &self,
        session: Arc<RuntimeSession>,
        from_cache: bool,
    ) -> MicrosandboxResult<(Arc<RuntimeSession>, Arc<crate::agent::AgentClient>)> {
        match super::fs::agent::connect_agent(self.backend.as_ref(), &self.name).await {
            Ok(client) => Ok((session, Arc::new(client))),
            Err(error) if from_cache && crate::context::is_cloud_sandbox_not_running(&error) => {
                let fresh = self.recover_cloud_runtime(&session).await?;
                let client =
                    super::fs::agent::connect_agent(self.backend.as_ref(), &self.name).await?;
                Ok((fresh, Arc::new(client)))
            }
            Err(error) => Err(error),
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
        let (session, from_cache) = self.prepare_runtime_tracked().await?;
        let mut command = microsandbox_types::resolve_default_command(
            session.config.spec.runtime.entrypoint.as_deref(),
            session.config.spec.runtime.cmd.as_deref(),
            None,
        )?;
        let builder = f(AttachOptionsBuilder::default()).with_inherited_command(true);

        #[cfg(feature = "cloud")]
        if self.backend.as_cloud().is_some()
            && matches!(&session.inner, crate::context::SandboxInner::Cloud(_))
        {
            let (fresh_session, client) = self
                .connect_cloud_agent_client(Arc::clone(&session), from_cache)
                .await?;
            if !Arc::ptr_eq(&fresh_session, &session) {
                command = microsandbox_types::resolve_default_command(
                    fresh_session.config.spec.runtime.entrypoint.as_deref(),
                    fresh_session.config.spec.runtime.cmd.as_deref(),
                    None,
                )?;
            }
            let builder = builder.prepend_args(command.args);
            return super::attach::agent::attach_on_client(
                client,
                &fresh_session.config,
                command.program,
                builder,
            )
            .await;
        }

        let builder = builder.prepend_args(command.args);
        self.attach_prepared(session, from_cache, command.program, builder)
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
        let (session, from_cache) = self.prepare_runtime_tracked().await?;
        let mut builder = AttachOptionsBuilder::default();
        for arg in args {
            builder = builder.arg(arg);
        }
        self.attach_prepared(session, from_cache, cmd.into(), builder)
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
        let (session, from_cache) = self.prepare_runtime_tracked().await?;
        self.attach_prepared(session, from_cache, cmd.into(), builder)
            .await
    }

    /// Attach to the sandbox's default shell.
    ///
    /// Uses the sandbox's configured shell (default: `/bin/sh`).
    pub async fn attach_shell(&self) -> MicrosandboxResult<i32> {
        let (session, from_cache) = self.prepare_runtime_tracked().await?;

        #[cfg(feature = "cloud")]
        if self.backend.as_cloud().is_some()
            && matches!(&session.inner, crate::context::SandboxInner::Cloud(_))
        {
            let (session, client) = self.connect_cloud_agent_client(session, from_cache).await?;
            let shell = configured_shell(&session);
            return super::attach::agent::attach_on_client(
                client,
                &session.config,
                shell,
                AttachOptionsBuilder::default(),
            )
            .await;
        }

        let shell = configured_shell(&session);
        self.attach_prepared(session, from_cache, shell, AttachOptionsBuilder::default())
            .await
    }
}

impl Sandbox {
    async fn attach_prepared(
        &self,
        session: Arc<RuntimeSession>,
        from_cache: bool,
        command: String,
        options: AttachOptionsBuilder,
    ) -> MicrosandboxResult<i32> {
        #[cfg(not(feature = "cloud"))]
        let _ = from_cache;

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

        #[cfg(feature = "cloud")]
        if self.backend.as_cloud().is_some()
            && matches!(&session.inner, crate::context::SandboxInner::Cloud(_))
        {
            let (session, client) = self.connect_cloud_agent_client(session, from_cache).await?;
            return super::attach::agent::attach_on_client(
                client,
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

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn configured_shell(session: &RuntimeSession) -> String {
    session
        .config
        .spec
        .runtime
        .shell
        .as_deref()
        .unwrap_or("/bin/sh")
        .to_string()
}
