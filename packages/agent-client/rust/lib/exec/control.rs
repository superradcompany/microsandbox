//! Capability-gated signals over the existing host-control endpoint.

use std::time::Duration;

use microsandbox_control_client::ControlClient;
use microsandbox_protocol::exec_control::{
    EXEC_CONTROL_REQUEST, EXEC_CONTROL_RESPONSE, EXEC_CONTROL_VERSION, ExecControlDiscovery,
    ExecControlReady, ExecControlRequest, ExecControlResponse,
};
use microsandbox_protocol::wire::Envelope;
use microsandbox_protocol_client::{ClientError, Delivery, ErrorKind, TypedMessage};

use crate::{AgentClientError, AgentClientResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const SIGNAL_DEADLINE: Duration = Duration::from_secs(5);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Ephemeral, connection-scoped control route. Dropping it does not signal or close stdin.
#[derive(Clone, Debug)]
pub struct ExecController {
    ready: ExecControlReady,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ExecController {
    /// Inspect the original Ready envelope; older relays do not advertise this route.
    pub fn from_ready_body(body: &[u8]) -> AgentClientResult<Option<Self>> {
        let envelope =
            Envelope::decode(body).map_err(|error| AgentClientError::Cbor(error.to_string()))?;
        let discovery = envelope
            .payload::<ExecControlDiscovery>()
            .map_err(|error| AgentClientError::Cbor(error.to_string()))?;
        discovery
            .exec_control
            .filter(|ready| ready.version == EXEC_CONTROL_VERSION)
            .map(|ready| {
                if ready.endpoint.is_empty() {
                    return Err(AgentClientError::LocalTransport(
                        "unsupported exec control capability".into(),
                    ));
                }
                Ok(Self { ready })
            })
            .transpose()
    }

    /// Deliver through reserved control capacity, independent of the agent stdin socket.
    ///
    /// Success confirms a complete console write. Observe the exec terminal result to confirm exit.
    /// A timeout after admission has unknown delivery and must not be automatically replayed.
    pub async fn signal(&self, id: u32, signal: i32) -> AgentClientResult<()> {
        tokio::time::timeout(SIGNAL_DEADLINE, async {
            let client = ControlClient::connect(&self.ready.endpoint).await?;
            if client.ready().welcome.generation < 2 {
                return Err(AgentClientError::LocalTransport(
                    "exec control requires framed generation two".into(),
                ));
            }
            let request = ExecControlRequest {
                version: self.ready.version,
                connection: self.ready.connection,
                id,
                signal,
            };
            let message = client
                .request(TypedMessage::new(EXEC_CONTROL_REQUEST, &request))
                .await?;
            if message.t == "control.error" {
                let refusal = message.payload::<microsandbox_protocol::control::ControlError>()?;
                return Err(AgentClientError::LocalTransport(format!(
                    "{}: {}",
                    refusal.code, refusal.message
                )));
            }
            if message.t != EXEC_CONTROL_RESPONSE {
                return Err(AgentClientError::LocalTransport(
                    "unexpected exec control response".into(),
                ));
            }
            let response = message.payload::<ExecControlResponse>()?;
            if !response.delivered {
                return Err(AgentClientError::LocalTransport(format!(
                    "{}: {}",
                    response.error_code.as_deref().unwrap_or("delivery_failed"),
                    response
                        .error
                        .as_deref()
                        .unwrap_or("signal delivery failed")
                )));
            }
            Ok(())
        })
        .await
        .map_err(|_| {
            AgentClientError::Client(
                ClientError::new(ErrorKind::Timeout).with_delivery(Delivery::Unknown),
            )
        })?
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use microsandbox_protocol::core::Ready;
    use microsandbox_protocol::exec_control::ExecControlAdvertisement;

    #[test]
    fn ready_extension_preserves_released_decoders_and_redacts_authority() {
        let ready = Ready::default();
        let capability = ExecControlReady {
            version: 1,
            endpoint: "local-control".into(),
            connection: [137; 16],
        };
        let envelope = Envelope::new(
            8,
            "core.ready",
            &ExecControlAdvertisement {
                ready: &ready,
                exec_control: &capability,
            },
        )
        .unwrap();
        let bytes = envelope.encode().unwrap();
        let decoded = Envelope::decode(&bytes)
            .unwrap()
            .payload::<Ready>()
            .unwrap();
        assert_eq!(decoded.agent_version, ready.agent_version);
        let controller = ExecController::from_ready_body(&bytes).unwrap().unwrap();
        assert_eq!(controller.ready.connection, capability.connection);
        assert!(!format!("{controller:?}").contains("137"));
    }

    #[test]
    fn old_or_unknown_optional_capability_retains_ordinary_exec_transport() {
        let ready = Ready::default();
        let old = Envelope::new(8, "core.ready", &ready)
            .unwrap()
            .encode()
            .unwrap();
        assert!(ExecController::from_ready_body(&old).unwrap().is_none());
        let capability = ExecControlReady {
            version: 2,
            endpoint: "local-control".into(),
            connection: [0; 16],
        };
        let newer = Envelope::new(
            8,
            "core.ready",
            &ExecControlAdvertisement {
                ready: &ready,
                exec_control: &capability,
            },
        )
        .unwrap()
        .encode()
        .unwrap();
        assert!(ExecController::from_ready_body(&newer).unwrap().is_none());
    }
}
