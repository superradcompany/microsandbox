//! Checked unary operations and prepared watch openings.

use microsandbox_protocol::{
    message::FLAG_TERMINAL,
    supervisor::{
        CreateSandboxIntent, Empty, GetRequest, InspectSandbox, ListSandboxes, ModifySandboxIntent,
        Mutation, OperationAccepted, OperationRecord, OperationSelector, RequestRecord,
        SandboxActionIntent, SandboxList, SandboxRecord, SupervisorCapabilities, SupervisorError,
        SupervisorStatus, WatchCatalog, WatchEnd,
    },
    wire,
};
use microsandbox_protocol_client::{EncodedMessage, Message, Request};
use serde::{Serialize, de::DeserializeOwned};

use crate::{SupervisorClientError, SupervisorClientResult, SupervisorProtocol};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Query supervisor health and catalog position.
#[derive(Debug, Clone, Copy, Default)]
pub struct GetSupervisorStatus;
/// Query generation-one supervisor facilities.
#[derive(Debug, Clone, Copy, Default)]
pub struct GetSupervisorCapabilities;
/// Look up a durable idempotent request.
#[derive(Debug, Clone, Copy)]
pub struct LookupRequest(pub GetRequest);
/// Inspect one sandbox.
#[derive(Debug, Clone)]
pub struct GetSandbox(pub InspectSandbox);
/// List a page of sandboxes.
#[derive(Debug, Clone)]
pub struct GetSandboxes(pub ListSandboxes);
/// Create durable sandbox state.
#[derive(Debug, Clone)]
pub struct CreateSandbox(pub Mutation<CreateSandboxIntent>);
/// Start a sandbox runtime.
#[derive(Debug, Clone)]
pub struct StartSandbox(pub Mutation<SandboxActionIntent>);
/// Gracefully stop a sandbox runtime.
#[derive(Debug, Clone)]
pub struct StopSandbox(pub Mutation<SandboxActionIntent>);
/// Force-stop a sandbox runtime.
#[derive(Debug, Clone)]
pub struct KillSandbox(pub Mutation<SandboxActionIntent>);
/// Restart a sandbox runtime.
#[derive(Debug, Clone)]
pub struct RestartSandbox(pub Mutation<SandboxActionIntent>);
/// Remove sandbox state.
#[derive(Debug, Clone)]
pub struct RemoveSandbox(pub Mutation<SandboxActionIntent>);
/// Apply a portable sandbox modification.
#[derive(Debug, Clone)]
pub struct ModifySandbox(pub Mutation<ModifySandboxIntent>);
/// Look up one asynchronous operation.
#[derive(Debug, Clone, Copy)]
pub struct GetOperation(pub OperationSelector);
/// Request idempotent operation cancellation.
#[derive(Debug, Clone)]
pub struct CancelOperation(pub Mutation<OperationSelector>);
/// Request an idempotent retry of a failed operation.
#[derive(Debug, Clone)]
pub struct RetryOperation(pub Mutation<OperationSelector>);
/// Prepare a catalog watch opening for [`microsandbox_protocol_client::Client::stream`].
#[derive(Debug, Clone, Copy)]
pub struct WatchSupervisor(pub WatchCatalog);
/// Prepare an operation watch opening.
#[derive(Debug, Clone, Copy)]
pub struct WatchOperation(pub OperationSelector);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl WatchSupervisor {
    /// Encode a stream-opening catalog request.
    pub fn message(&self) -> SupervisorClientResult<EncodedMessage> {
        prepared("supervisor.watch", &self.0)
    }
}

impl WatchOperation {
    /// Encode a stream-opening operation request.
    pub fn message(&self) -> SupervisorClientResult<EncodedMessage> {
        prepared("operation.watch", &self.0)
    }
}

/// Decode one nonterminal catalog event.
pub fn decode_catalog_event(
    response: Message,
) -> SupervisorClientResult<microsandbox_protocol::supervisor::CatalogEvent> {
    checked(response, false, "supervisor.event")
}

/// Decode one nonterminal operation event.
pub fn decode_operation_event(response: Message) -> SupervisorClientResult<OperationRecord> {
    checked(response, false, "operation.event")
}

/// Decode the terminal record for a supervisor catalog watch.
pub fn decode_catalog_watch_end(response: Message) -> SupervisorClientResult<WatchEnd> {
    checked(response, true, "supervisor.watch.end")
}

/// Decode the terminal record for an operation watch.
pub fn decode_operation_watch_end(response: Message) -> SupervisorClientResult<WatchEnd> {
    checked(response, true, "operation.watch.end")
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

macro_rules! unary_empty {
    ($request:ty, $response:ty, $request_name:literal, $response_name:literal) => {
        impl Request<SupervisorProtocol> for $request {
            type Response = $response;
            type Error = SupervisorClientError;

            fn message(&self) -> SupervisorClientResult<EncodedMessage> {
                prepared($request_name, &Empty {})
            }

            fn decode(&self, response: Message) -> SupervisorClientResult<Self::Response> {
                checked(response, true, $response_name)
            }
        }
    };
}

macro_rules! unary_tuple {
    ($request:ty, $response:ty, $request_name:literal, $response_name:literal) => {
        impl Request<SupervisorProtocol> for $request {
            type Response = $response;
            type Error = SupervisorClientError;

            fn message(&self) -> SupervisorClientResult<EncodedMessage> {
                prepared($request_name, &self.0)
            }

            fn decode(&self, response: Message) -> SupervisorClientResult<Self::Response> {
                checked(response, true, $response_name)
            }
        }
    };
}

macro_rules! unary_mutation {
    ($request:ty, $response:ty, $request_name:literal, $response_name:literal) => {
        impl Request<SupervisorProtocol> for $request {
            type Response = $response;
            type Error = SupervisorClientError;

            fn message(&self) -> SupervisorClientResult<EncodedMessage> {
                if !self.0.validate() {
                    return Err(microsandbox_protocol::wire::WireError::InvalidRecord.into());
                }
                prepared($request_name, &self.0)
            }

            fn decode(&self, response: Message) -> SupervisorClientResult<Self::Response> {
                checked(response, true, $response_name)
            }
        }
    };
}

unary_empty!(
    GetSupervisorStatus,
    SupervisorStatus,
    "supervisor.status",
    "supervisor.status.result"
);
unary_empty!(
    GetSupervisorCapabilities,
    SupervisorCapabilities,
    "supervisor.capabilities",
    "supervisor.capabilities.result"
);
unary_tuple!(
    LookupRequest,
    RequestRecord,
    "request.get",
    "request.get.result"
);
unary_tuple!(
    GetSandbox,
    SandboxRecord,
    "sandbox.inspect",
    "sandbox.inspect.result"
);
unary_tuple!(
    GetSandboxes,
    SandboxList,
    "sandbox.list",
    "sandbox.list.result"
);
unary_mutation!(
    CreateSandbox,
    OperationAccepted,
    "sandbox.create",
    "operation.accepted"
);
unary_mutation!(
    StartSandbox,
    OperationAccepted,
    "sandbox.start",
    "operation.accepted"
);
unary_mutation!(
    StopSandbox,
    OperationAccepted,
    "sandbox.stop",
    "operation.accepted"
);
unary_mutation!(
    KillSandbox,
    OperationAccepted,
    "sandbox.kill",
    "operation.accepted"
);
unary_mutation!(
    RestartSandbox,
    OperationAccepted,
    "sandbox.restart",
    "operation.accepted"
);
unary_mutation!(
    RemoveSandbox,
    OperationAccepted,
    "sandbox.remove",
    "operation.accepted"
);
unary_mutation!(
    ModifySandbox,
    OperationAccepted,
    "sandbox.modify",
    "operation.accepted"
);
unary_tuple!(
    GetOperation,
    OperationRecord,
    "operation.get",
    "operation.get.result"
);
unary_mutation!(
    CancelOperation,
    OperationRecord,
    "operation.cancel",
    "operation.action.result"
);
unary_mutation!(
    RetryOperation,
    OperationRecord,
    "operation.retry",
    "operation.action.result"
);

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn prepared(name: &str, payload: &impl Serialize) -> SupervisorClientResult<EncodedMessage> {
    Ok(EncodedMessage::new(name, wire::encode(payload)?))
}

fn checked<T: DeserializeOwned>(
    response: Message,
    terminal: bool,
    name: &str,
) -> SupervisorClientResult<T> {
    let expected_terminal = if terminal { FLAG_TERMINAL } else { 0 };
    if response.v != 1 || response.id == 0 {
        return Err(SupervisorClientError::InvalidResponse {
            response: Box::new(response),
        });
    }
    if response.t == "supervisor.error" {
        if response.flags != FLAG_TERMINAL {
            return Err(SupervisorClientError::InvalidResponse {
                response: Box::new(response),
            });
        }
        let error: SupervisorError = match response.payload() {
            Ok(error) => error,
            Err(_) => {
                return Err(SupervisorClientError::InvalidResponse {
                    response: Box::new(response),
                });
            }
        };
        return Err(SupervisorClientError::Peer {
            error,
            response: Box::new(response),
        });
    }
    if response.flags != expected_terminal || response.t != name {
        return Err(SupervisorClientError::InvalidResponse {
            response: Box::new(response),
        });
    }
    response
        .payload()
        .map_err(|_| SupervisorClientError::InvalidResponse {
            response: Box::new(response),
        })
}
