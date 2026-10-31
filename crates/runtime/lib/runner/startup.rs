//! Startup workload execution for detached `msb run -- CMD`.

use std::path::Path;

use microsandbox_agent_client::{AgentClient, OutputAcknowledgements, TypedMessage};
use microsandbox_protocol::{
    exec::{ExecExited, ExecFailed, ExecOutputAck, ExecRequest, ExecStderr, ExecStdout},
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
        security: None,
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

    let rx = client
        .stream(TypedMessage::new(MessageType::ExecRequest, &request))
        .await
        .map_err(|err| RuntimeError::Custom(format!("startup command dispatch: {err}")))?;

    let controlled = client.ready().agent.exec_limits.is_some()
        && client.ready().supports(MessageType::ExecOutputAck);
    let (sender, mut output) = rx.into_parts();
    let acknowledgements = OutputAcknowledgements::default();
    let consumed = acknowledgements.consumed.clone();
    let mut acknowledgement = ExecOutputAck::default();
    let worker = tokio::spawn(acknowledgements.run(move |acknowledgement| {
        let sender = sender.clone();
        async move {
            sender
                .send(TypedMessage::new(
                    MessageType::ExecOutputAck,
                    &acknowledgement,
                ))
                .await
        }
    }));
    let mut worker = tokio_util::task::AbortOnDropHandle::new(worker);

    loop {
        let message = tokio::select! {
            result = &mut worker => {
                return Err(RuntimeError::Custom(format!("startup command output acknowledgement: {result:?}")));
            }
            message = output.recv() => match message
                .map_err(|err| RuntimeError::Custom(format!("startup command stream: {err}")))? {
                Some(message) => message,
                None => break,
            },
        };
        match MessageType::from_wire_str(&message.t) {
            Some(kind @ (MessageType::ExecStdout | MessageType::ExecStderr)) if controlled => {
                let bytes = match kind {
                    MessageType::ExecStdout => {
                        message.payload::<ExecStdout>().map(|p| p.data.len())
                    }
                    _ => message.payload::<ExecStderr>().map(|p| p.data.len()),
                }
                .map_err(|err| RuntimeError::Custom(format!("startup command output: {err}")))?;
                acknowledgement.consume(bytes).ok_or_else(|| {
                    RuntimeError::Custom("startup command output counter overflow".into())
                })?;
                // Discarding output releases its allowance; the sender coalesces these updates.
                consumed.send_replace(acknowledgement.clone());
            }
            Some(MessageType::ExecExited) => {
                let exited = message
                    .payload::<ExecExited>()
                    .map_err(|err| RuntimeError::Custom(format!("startup command exit: {err}")))?;
                return Ok(StartupCommandExit::Exited(exited.code));
            }
            Some(MessageType::ExecFailed) => {
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
