# Rust control client

`ControlConnection` discovers whether an existing control endpoint supports framed CBOR or legacy JSON. `ControlClient` is the explicitly framed `Client<ControlProtocol>` entry point, and `JsonControlClient` is an explicit legacy unary adapter. Their checked helpers share the same operation records.

```text
ControlConnection -- JSON capabilities --+-- advertised CBOR: fresh stream + hello
                                        |                      |
                                        |               ControlClient
                                        |
                                        +-- legacy: JsonControlClient
```

Automatic discovery has one deadline across the probe, redial, and hello. It selects CBOR only after a valid affirmative capability response. Malformed replies, arbitrary peer errors, empty EOF, and failed framed setup are errors. There is no error-string downgrade or mutation replay. `ControlClient` sends its hello directly when callers already know the peer supports framed control.

```rust,no_run
use microsandbox_control_client::{
    ControlConnection, ControlMessageType, ControlReply, Empty, GetMemoryState, TypedMessage,
};

async fn inspect(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let connection = ControlConnection::connect(path).await?;
    let reply = connection.request(TypedMessage::new(ControlMessageType::MemoryState, Empty {})).await?;
    match reply {
        ControlReply::Framed(message) => println!("{}", message.t),
        ControlReply::Json(reply) => println!("{} original JSON bytes", reply.raw().len()),
    }
    println!("{} MiB", connection.request_typed(&GetMemoryState).await?.target_mib);
    connection.close().await;
    Ok(())
}
```

In framed mode, clones reuse one connection. Automatic JSON mode rediscovers before each fresh exchange when its connector cannot prove runtime identity. An owner implementing `VerifiedControlConnector` verifies the connected peer and the runtime's OS birth token on every dial, then rechecks the active run before each operation; `connect_verified_connector` can reuse that owner's JSON selection. A path or PID alone is insufficient. A detected change invalidates the handle before sending instead of silently retargeting the request. The runtime owner, such as an SDK backend, supplies that identity implementation; the protocol package does not claim to verify it itself.

`JsonControlClient::new(path)` and `from_connector(...)` are inert constructors for callers explicitly choosing legacy mode. Its `request` translates only known native requests and returns the actual `JsonReply`, including `ok:false` replies. Checked helpers report `LegacyRemote` with the original reply and unknown batch progress. JSON numbers retain their original tokens; checked memory fields use `u64` without a floating-point intermediate. `connection.framed()` fails locally in JSON mode, and encoded-payload input is rejected there before dialing. Raw streams and exact packets remain available on the explicitly framed client.

`connection.capabilities()` borrows the validated discovery snapshot without network I/O. `GetCapabilities` remains available for an explicit fresh observation. `closed().await` observes shared closure, including an idle framed disconnect; a successful JSON exchange ending in EOF does not close the session.

Enable `uds` for Unix endpoint connections or `named-pipe` for Windows endpoint connections. Caller-owned transports and connectors can be used without either native feature. Endpoint paths are accepted verbatim.

```rust,no_run
use microsandbox_control_client::{
    ControlClient, GetMemoryState, SetMemoryTarget, size::SizeExt,
};

async fn resize(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let client = ControlClient::connect(path).await?;
    let before = client.request_typed(&GetMemoryState).await?;
    let accepted = client.request_typed(&SetMemoryTarget::new(2048.mib())).await?;
    println!("{} -> {} MiB", before.target_mib, accepted.target_mib);
    client.close().await;
    Ok(())
}
```

Memory wire records retain `u64` values. The existing size helpers retain their conversion rules; direct `SetMemoryTarget { total_mib }` construction provides full-width wire input. Target responses report acceptance and current observations, not guest convergence. Ordered secret batches preserve partial completion and the index of the first failed entry.

The client keeps `request`, `stream`, `request_raw`, `stream_raw`, explicit-ID `send`/`send_raw`, exact `write_unchecked`, owned `into_parts`, and checked `request_typed` operations. Generic requests return peer error frames as messages; checked helpers interpret them and retain the original response. No sandbox, execution, filesystem, or convergence service is required to use any of these paths.

```rust,no_run
use microsandbox_control_client::{ControlClient, EncodedMessage};

async fn inspect(client: &ControlClient, payload: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    let response = client.request(EncodedMessage::new("extension.inspect", payload)).await?;
    println!("{}: {} payload bytes", response.t, response.p.len());
    Ok(())
}
```

Setup defaults to one ten-second deadline and requests to a thirty-second local wait. Request expiry does not cancel remote work or trigger replay. `ClientError` retains `NotSent` versus `Unknown` delivery. Clones and owned streams share a connection; `close` closes it for all owners.

Run `cargo test -p microsandbox-control-client --all-features --locked`. For live tests, set `MSB_CONTROL_TEST_SOCKET` and `MSB_CONTROL_TEST_MODE=cbor` or `json`. The explicitly framed test requires CBOR; run only `live_automatic_discovery_and_explicit_json -- --ignored --exact` against a JSON-only runtime. Use bounded disposable fixtures (512 MiB and two CPUs), and run live tests serially. The automatic test changes targets and restores them through explicit JSON. Optional `MSB_CONTROL_TEST_SECRET` names a dummy fixture initially set to `before` and allowed for `example.invalid`; the test exercises legacy partial-failure reporting and restores that fixture. Skipped live tests are not runtime or platform validation.
