# microsandbox agent client

Transport-agnostic clients for speaking the microsandbox agent protocol.

This layer sits between the protocol package and the high-level SDKs:

```text
sdk ──▶ agent-client ──▶ protocol
```

The agent client owns connection handshakes, correlation IDs, request/stream routing, message encoding, and transport adapters. It does not own sandbox lifecycle, sandbox-name resolution, image management, volumes, metrics, or other high-level SDK workflows.

## Layout

```text
packages/agent-client/
├── rust/
└── typescript/
```

- `rust/` publishes as `microsandbox-agent-client`.
- `typescript/` publishes as `@microsandbox/agent-client`.

The Rust crate has no default transport feature. SDK crates that connect to local sandbox relays opt into `uds` explicitly. Rust WebSocket support is available behind the `websocket` feature and uses `tokio-tungstenite`.

The TypeScript package exposes a browser-safe default entry and keeps Node-only Unix sockets behind `@microsandbox/agent-client/node`; browser/front-end callers use `WebSocketTransport`.

## Message Model

The public API names protocol boundaries by structure:

- `TypedMessage`: message type plus a native payload object.
- `EncodedMessage`: message type plus already-CBOR-encoded payload bytes.
- `RawFrame` / `InboundFrame`: id, flags, and encoded message body.
- `TransportPacket`: exact transport bytes, including length prefix.

Unchecked packet writes are an explicit escape hatch for relays, tests, and specialized tooling.
