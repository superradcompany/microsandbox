//! Startup workload execution for detached `msb run -- CMD`.

use std::path::Path;

use microsandbox_agent_client::AgentClient;
use microsandbox_protocol::{
    exec::{ExecExited, ExecFailed, ExecRequest},
    message::MessageType,
};

use crate::vm::StartupCommand;
use crate::{RuntimeError, RuntimeResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Terminal status for the startup workload exec session.
pub(crate) enum StartupCommandExit {
    /// The command ran and exited with the contained status code.
    Exited(i32),

    /// agentd could not spawn the command.
    Failed(ExecFailed),
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) async fn run_startup_command(
    agent_sock_path: &Path,
    command: StartupCommand,
) -> RuntimeResult<StartupCommandExit> {
    let client = AgentClient::connect(agent_sock_path)
        .await
        .map_err(|err| RuntimeError::Custom(format!("startup command connect: {err}")))?;

    let request = ExecRequest {
        cmd: command.cmd,
        args: command.args,
        env: command.env,
        cwd: command.cwd,
        user: command.user,
        tty: false,
        rows: 24,
        cols: 80,
        rlimits: Vec::new(),
    };

    let (_id, mut rx) = client
        .stream(MessageType::ExecRequest, &request)
        .await
        .map_err(|err| RuntimeError::Custom(format!("startup command dispatch: {err}")))?;

    while let Some(message) = rx.recv().await {
        match message.t {
            MessageType::ExecExited => {
                let exited = message
                    .payload::<ExecExited>()
                    .map_err(|err| RuntimeError::Custom(format!("startup command exit: {err}")))?;
                return Ok(StartupCommandExit::Exited(exited.code));
            }
            MessageType::ExecFailed => {
                let failed = message.payload::<ExecFailed>().map_err(|err| {
                    RuntimeError::Custom(format!("startup command failure: {err}"))
                })?;
                return Ok(StartupCommandExit::Failed(failed));
            }
            _ => {}
        }
    }

    Err(RuntimeError::Custom(
        "startup command stream ended before terminal event".into(),
    ))
}
