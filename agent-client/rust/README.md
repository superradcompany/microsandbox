# microsandbox-agent-client

Low-level Rust client for speaking the microsandbox agent protocol.

This crate sits below the high-level `microsandbox` SDK. It owns the transport connection, relay handshake, correlation ID allocation, request/stream routing, message framing, protocol-version gating, and typed/raw message helpers. It does not resolve sandbox names, manage sandbox lifecycle, pull images, create volumes, or expose ergonomic filesystem/process APIs.

Use this crate when you already have an agent relay endpoint and want direct protocol access. Use the high-level `microsandbox` crate when you want to start, stop, discover, or manage sandboxes.

## Install

```toml
[dependencies]
microsandbox-agent-client = "0.5.6"
microsandbox-protocol = "0.5.6"
```

The crate is transport-agnostic by default. Enable exactly the transport adapter you need:

```toml
# Local microsandbox relay sockets.
microsandbox-agent-client = { version = "0.5.6", features = ["uds"] }

# WebSocket relay endpoints.
microsandbox-agent-client = { version = "0.5.6", features = ["websocket"] }
```

The high-level `microsandbox` SDK enables `uds` explicitly because local sandboxes are reached through Unix domain sockets.

## Protocol Model

The agent protocol is a length-prefixed binary frame:

```text
[len: u32 BE][id: u32 BE][flags: u8][CBOR Message body]
```

The CBOR `Message` body contains:

```text
{ v, t, p }
```

- `v`: protocol generation.
- `t`: wire message type such as `core.exec.request`.
- `p`: CBOR-encoded payload for that message type.

`AgentClient` owns `id` allocation from the relay-assigned range. Callers choose message types and payloads; the client computes flags, gates unsupported message types against the negotiated protocol generation, frames messages, and routes responses by correlation ID.

The relay handshake happens before regular frames:

```text
[id_min: u32 BE][id_max: u32 BE][core.ready packet]
```

`id_min..id_max` is the correlation ID range reserved for this client connection. `core.ready` advertises the agent protocol generation and runtime metadata; the client uses it to negotiate the effective protocol version.

For the 0.5 release line, the shared handshake parser also accepts the pre-0.5 relay handshake:

```text
[id_offset: u32 BE][core.ready packet]
```

Legacy connections are marked as generation 1, emit a warning, and only allow message types supported by that generation. This compatibility path is scheduled for removal in 0.6 or later.

## UDS Example

```rust
use microsandbox_agent_client::AgentClient;
use microsandbox_protocol::{
    fs::{FsOp, FsRequest, FsResponse},
    message::MessageType,
};

async fn example() -> Result<(), Box<dyn std::error::Error>> {
    let client = AgentClient::connect("/tmp/msb-agent.sock").await?;

    let response = client
        .request(
            MessageType::FsRequest,
            &FsRequest {
                op: FsOp::Stat {
                    path: "/etc/os-release".to_string(),
                    follow_symlink: true,
                },
            },
        )
        .await?;

    let payload: FsResponse = response.payload()?;
    println!("ok = {}", payload.ok);
    client.close().await;
    Ok(())
}
```

## WebSocket Example

Enable the `websocket` feature:

```toml
microsandbox-agent-client = { version = "0.5.6", features = ["websocket"] }
```

Then connect to a relay endpoint:

```rust
use microsandbox_agent_client::AgentClient;

async fn example() -> Result<(), Box<dyn std::error::Error>> {
    let client = AgentClient::connect_websocket("wss://relay.example.com/agent").await?;
    println!("agent version: {}", client.agent_version());
    Ok(())
}
```

The WebSocket transport uses `tokio-tungstenite`. Each protocol frame is sent as one binary WebSocket message. Incoming binary messages may contain any number of bytes; the client buffers them and decodes complete protocol packets.

## Typed And Raw APIs

Typed APIs serialize outbound payloads and deserialize inbound protocol envelopes:

```rust
client.request(MessageType::FsRequest, &payload).await?;
client.stream(MessageType::ExecRequest, &payload).await?;
client.send(id, MessageType::ExecStdin, &payload).await?;
```

Raw APIs move complete CBOR message envelope bodies while still letting the client own frame headers, ID allocation, and response routing:

```rust
let frame = client.request_raw(flags, body).await?;
let (id, rx) = client.stream_raw(flags, body).await?;
client.send_raw(id, flags, &body).await?;
```

Use raw APIs for bindings, protocol tools, or callers that already encode complete CBOR `Message` envelope bodies in another language. Prefer typed APIs in ordinary Rust code.

## Protocol Errors

Peers may send `core.error` as a terminal response when they can recover from a message-level protocol problem for a specific correlation ID. Examples include malformed message envelopes, invalid flags, and invalid payloads. Frame-level transport corruption still closes the connection instead.

`core.error` is surfaced as an ordinary `Message`/`RawFrame`; callers can inspect `MessageType::CoreError` and decode `microsandbox_protocol::core::CoreError`.

```rust
use microsandbox_protocol::{
    core::CoreError,
    message::MessageType,
};

async fn example(
    client: microsandbox_agent_client::AgentClient,
    payload: microsandbox_protocol::fs::FsRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = client.request(MessageType::FsRequest, &payload).await?;
    if response.t == MessageType::CoreError {
        let err: CoreError = response.payload()?;
        eprintln!("agent rejected request: {}", err.message);
    }
    Ok(())
}
```

## Feature Reference

| Feature | Default | Description |
| --- | --- | --- |
| `uds` | no | Enables Unix domain socket connections with `AgentClient::connect*`. |
| `websocket` | no | Enables `AgentClient::connect_websocket*` using `tokio-tungstenite`. |

## Validation

Useful focused checks:

```bash
cargo check -p microsandbox-agent-client --no-default-features
cargo test -p microsandbox-agent-client --features uds
cargo test -p microsandbox-agent-client --features websocket
```
