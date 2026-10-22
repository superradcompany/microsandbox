//! Fresh query-bound guest resource observations over the existing agent connection.

use std::time::Duration;

use microsandbox_protocol::message::{FLAG_TERMINAL, MessageType};
use microsandbox_protocol::resources::{
    ObserveResources, ObservedResources, RESOURCE_OBSERVATION_RELAY_VERSION, ResourceRelayDiscovery,
};
use microsandbox_protocol::wire::Envelope;

use crate::{
    AgentClient, AgentReady, ClientError, ClientResult, Delivery, ErrorKind, TypedMessage,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Read one fresh CPU/memory observation, refusing unsupported relays or guests before sending.
/// Discovery reads the connection's original Ready; it sends no probe to older components.
///
/// Choose a fresh `query_id` for each query. A successful response is not resize completion:
/// callers must bracket the request with runtime/operation identity checks, validate the expected
/// device/target, and retain the request's monotonic start time for conservative freshness.
/// Unavailable kernel evidence remains a successful query with an explicit unavailable resource.
/// Timeout stops waiting and does not mutate, cancel or repeat a resize.
pub async fn observe_resources(
    client: &AgentClient,
    query_id: [u8; 16],
    timeout: Duration,
) -> ClientResult<ObservedResources> {
    let request = ObserveResources { query_id };
    let reply = client
        .request_with(
            TypedMessage::new(MessageType::ObserveResources, &request),
            |options| options.request_timeout(timeout),
        )
        .await?;
    let invalid = || ClientError::new(ErrorKind::InvalidData).with_delivery(Delivery::Unknown);
    if reply.t != MessageType::ObservedResources.as_str()
        || reply.flags != FLAG_TERMINAL
        || !MessageType::ObservedResources.is_available_at(reply.v)
    {
        return Err(invalid());
    }
    let observation = reply
        .payload::<ObservedResources>()
        .map_err(|_| invalid())?;
    if observation.query_id != query_id || !observation.is_valid() {
        return Err(invalid());
    }
    Ok(observation)
}

/// Admission is also used by the ordinary typed client path, not only this helper.
pub(crate) fn ensure_observation_support(ready: &AgentReady) -> ClientResult<()> {
    let relay = Envelope::decode(ready.ready_bytes())
        .and_then(|envelope| envelope.payload::<ResourceRelayDiscovery>())
        .ok()
        .and_then(|discovery| discovery.relay_resource_observation);
    if !ready.supports(MessageType::ObserveResources)
        || relay != Some(RESOURCE_OBSERVATION_RELAY_VERSION)
    {
        return Err(
            ClientError::new(ErrorKind::UnsupportedOperation).with_delivery(Delivery::NotSent)
        );
    }
    Ok(())
}
