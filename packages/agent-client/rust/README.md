# microsandbox-agent-client

`AgentClient` is `Client<AgentProtocol>` from `microsandbox-protocol-client`. The agent package supplies relay setup and generation metadata; the shared engine supplies one reader, writer, allocator, and ownership registry. SDK services such as execution collection and filesystem handles remain in `microsandbox`.

```text
TypedMessage / EncodedMessage / raw envelope / exact packet
                           |
                 Client<AgentProtocol>
                           |
          current or legacy relay handshake
                           |
                       agent relay
```

## Native, encoded, and raw messages

```rust,no_run
use microsandbox_agent_client::{AgentClient, TypedMessage, EncodedMessage};
use microsandbox_protocol::{fs::{FsOp, FsRequest, FsResponse}, message::MessageType};

async fn inspect(client: &AgentClient) -> Result<(), Box<dyn std::error::Error>> {
    let request = FsRequest {
        bulk: None,
        op: FsOp::Stat { path: "/etc/os-release".into(), follow_symlink: true },
    };
    let reply = client.request(TypedMessage::new(MessageType::FsRequest, &request)).await?;
    let response: FsResponse = reply.payload()?;
    println!("{}", response.ok);

    // The caller's payload bytes are not parsed or normalized by this path.
    let payload = vec![0xa0];
    let _reply = client.request(EncodedMessage::new(MessageType::Ping, payload)).await?;
    Ok(())
}
```

`Message.t` is the actual wire string. Unknown names and unknown envelope fields remain inspectable: `Message::raw()` borrows the original frame and `into_raw()` returns it. Ordinary requests surface peer error messages as messages. Optional `Request<AgentProtocol>` implementations add checked unary decoding without narrowing the generic API.

## Owned streams and explicit IDs

```rust,no_run
use microsandbox_agent_client::{AgentClient, TypedMessage};
use microsandbox_protocol::{exec::{ExecRequest, ExecStdin}, message::MessageType};

async fn exchange(client: &AgentClient, request: &ExecRequest) -> Result<(), Box<dyn std::error::Error>> {
    let stream = client.stream(TypedMessage::new(MessageType::ExecRequest, request)).await?;
    let id = stream.id();
    let (sender, mut receiver) = stream.into_parts();
    client.send(id, TypedMessage::new(MessageType::ExecStdin, ExecStdin { data: vec![] })).await?;
    sender.send(TypedMessage::new(MessageType::ExecStdin, ExecStdin { data: b"input".to_vec() })).await?;
    while let Some(message) = receiver.recv().await? {
        println!("{}", message.t);
    }
    Ok(())
}
```

Both split parts retain the connection and ID lease; sender handles may be cloned and there is one consuming receiver. Terminal receipt disables sends and delivers the terminal frame once. Closing or dropping the receiver disables sends and retains bounded drain state until terminal completion. It sends no process signal or filesystem EOF. Transport loss before a terminal frame is an error, distinct from clean exhaustion.

`request_raw(flags, body)`, `stream_raw(flags, body)`, and `send_raw(id, flags, body)` exchange opaque envelopes without CBOR decoding. `write_unchecked(packet_bytes)` serializes exact caller bytes without allocating an ID or subscribing for replies. `TransportPacket` remains an optional standalone framing helper; `packet.into_bytes()` feeds the exact write API. Standalone packet readers require exclusive transport ownership.

## Setup and metadata

Enable `uds` for native Unix sockets or `named-pipe` for Windows pipes. `connect_stream` accepts an owned `AsyncRead + AsyncWrite + Unpin + Send` transport, including `UdsTransport` and `NamedPipeTransport`. The `stream` feature name remains accepted for existing manifests; generic owned transports are available without additional dependencies.

```rust,no_run
use microsandbox_agent_client::AgentClient;
use std::time::Duration;

async fn connect(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let client = AgentClient::connect_with(path, |o| o.setup_timeout(Duration::from_secs(5))).await?;
    println!("{}", client.ready().agent_version());
    println!("{}", client.ready().negotiated_version);
    println!("{} ready bytes", client.ready().ready_bytes().len());
    client.close().await;
    Ok(())
}
```

Setup has one deadline across dial and handshake. The current `[id_min,id_max]` relay prologue and the supported pre-0.5 `[id_offset]` prologue retain their existing parsing, ID ranges, and ready payload behavior. Known operations use the smaller host/peer generation as their availability gate. Current connections continue emitting the host's existing envelope generation; legacy connections emit generation one. Source-level API changes do not retire the legacy wire path.

## Migration from the previous active client

| Previous API | Shared-client API |
| --- | --- |
| `connect(path)` / `connect_stream(stream)` | Same entry points; owned streams no longer require the `stream` feature |
| `request(type, &payload)` | `request(TypedMessage::new(type, &payload))` |
| `stream(type, &payload) -> (id, receiver)` | `stream(TypedMessage::new(type, &payload))`, then `id()` / `into_parts()` |
| `send(id, type, &payload)` | `send(id, TypedMessage::new(type, &payload))` |
| `request_raw(flags, body)` | Same call; retains drain state after a nonterminal first reply |
| `stream_raw(flags, body) -> (id, receiver)` | Owned raw stream, then `id()` / `into_parts()` |
| `send_raw(id, flags, body)` | Same call, requiring a live owned ID |
| `connect_with_timeout(path, duration)` | `connect_with(path, |o| o.setup_timeout(duration))` |
| `connect_stream_with_timeout(stream, duration)` | `connect_stream_with(stream, |o| o.setup_timeout(duration))` |
| `connect_with_deadline(path, deadline)` | `connect_with(path, |o| o.setup_timeout(deadline.saturating_duration_since(Instant::now())))` |
| `connect_stream_with_deadline(stream, deadline)` | `connect_stream_with(stream, |o| o.setup_timeout(deadline.saturating_duration_since(Instant::now())))` |
| `ready()` | `ready().agent` |
| `ready_bytes()` | `ready().ready_bytes()` |
| `negotiated_version()` / `supports(type)` | `ready().negotiated_version` / `ready().supports(type)` |
| `protocol()` / `is_legacy_protocol()` | `ready().wire_format` / `ready().is_legacy_protocol()` |
| `agent_version()` | `ready().agent_version()` |
| `ensure_version_compat(type)` | `AgentProtocol::ensure_version_compat_for(type, client.ready().negotiated_version)` |
| `AgentClient::ensure_version_compat_for(type, generation)` | `AgentProtocol::ensure_version_compat_for(type, generation)` |
| Unwired `AgentStream<T>` / packet-only `AgentTransport` | Active `AgentStream` / owned byte transports accepted directly by `connect_stream` |
| Connection close by ownership transfer | Shared `close(&self)`; last client/stream owner also closes the transport |

`ClientError.delivery` distinguishes `NotSent` from `Unknown` after writer admission. Requests are never automatically replayed. Raw stream access, known-ID sends, custom transports, ready bytes, dynamic names, and encoded payloads remain available without adopting SDK domain objects.

Deadline conversions use `tokio::time::Instant`, matching the original absolute-deadline API. Keep the conversion inside the options closure so it uses the remaining duration when setup begins. Known native and encoded sends perform the same availability check automatically; the public `AgentProtocol` helper supports callers retaining only the generation. Unsupported operations now use the shared `ClientError` category rather than the previous agent-specific error fields.

Validation: `cargo test -p microsandbox-agent-client --all-features --locked`. Unix-socket tests require permission to bind temporary local sockets. The migrated historical handshake cases are source-level regression tests; they do not replace live historical runtime/SDK validation.

The SDK retains an internal optimized client for generation-eight bulk transfers and Unix shared arenas. Its existing bulk APIs remain available; the generic client is the public transport-independent framed API.
