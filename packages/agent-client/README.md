# microsandbox agent client

Transport-agnostic clients for speaking the microsandbox agent protocol.

This layer sits between the protocol package and the high-level SDKs:

```text
sdk -> agent-client -> protocol-client -> protocol
```

The agent package supplies connection handshakes, its existing message codec, and protocol-generation gates. Its public client is a specialization of the shared generic router, which owns IDs, framing, transport lifetime, and request/stream routing. SDK packages own sandbox lifecycle, name resolution, image management, volumes, and metrics.

## Layout

```text
packages/agent-client/
├── rust/
└── typescript/
```

- `rust/` publishes as `microsandbox-agent-client`.
- `typescript/` publishes as `@microsandbox/agent-client`.

The Rust crate has no default transport feature. Local SDK connections opt into `uds` on Unix or `named-pipe` on Windows. An owned `AsyncRead + AsyncWrite` transport can also be supplied, including a caller-authenticated WebSocket adapted to bytes.

The TypeScript package exposes a browser-safe default entry and keeps Node-only Unix sockets behind `@microsandbox/agent-client/node`; browser/front-end callers use `WebSocketTransport`.

## Message Model

The public API names protocol boundaries by structure:

- `TypedMessage`: message type plus a native payload object.
- `EncodedMessage`: message type plus already-CBOR-encoded payload bytes.
- `RawFrame`: routing fields and an opaque envelope body.
- `Message` (Rust) / `InboundFrame` (TypeScript): an inspectable envelope retaining its original raw frame.
- `TransportPacket`: exact transport bytes, including length prefix.

Unchecked packet writes are an explicit escape hatch for relays, tests, and specialized tooling.

Rust and TypeScript preserve native, encoded, raw, exact-packet, explicit-ID, and owned split-stream access. See each package README for the API migration and validated examples. Shared TypeScript packages build together through the private npm workspace in `packages`.
