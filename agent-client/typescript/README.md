# @microsandbox/agent-client

Low-level TypeScript client for speaking the microsandbox agent protocol from Node.js or browser/front-end runtimes.

This package sits below the high-level microsandbox SDK. It owns the transport connection, relay handshake, correlation ID allocation, request/stream routing, message framing, protocol-version gating, and typed/encoded message helpers. It does not create sandboxes, resolve sandbox names, pull images, manage volumes, or expose high-level process/filesystem convenience APIs.

Use this package when you already have an agent relay endpoint and want direct protocol access from TypeScript. Use a higher-level microsandbox SDK when you want sandbox lifecycle management.

## Install

```bash
npm install @microsandbox/agent-client
```

Node.js 22 or newer is required.

## Entry Points

The default entry is browser-safe and does not import Node builtins:

```ts
import {
  AgentClient,
  WebSocketTransport,
  typedMessage,
} from "@microsandbox/agent-client";
```

Unix domain sockets are Node-only and live behind a separate entry:

```ts
import { connectUnix } from "@microsandbox/agent-client/node";
```

This split matters for front-end builds: importing from `@microsandbox/agent-client` is browser-safe, while `@microsandbox/agent-client/node` imports Node's `net` module.

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
- `t`: wire message type such as `"core.exec.request"`.
- `p`: CBOR-encoded payload for that message type.

`AgentClient` owns correlation IDs from the relay-assigned range. Callers pass typed or already-encoded messages; the client computes flags, gates unsupported message types against the negotiated protocol generation, frames messages, and routes responses by ID.

The relay handshake happens before regular frames:

```text
[id_min: u32 BE][id_max: u32 BE][core.ready packet]
```

`id_min..id_max` is the correlation ID range reserved for this client connection. `core.ready` advertises the agent protocol generation and runtime metadata; the client uses it to negotiate the effective protocol version.

Payload objects passed to `typedMessage()` must match the CBOR schema expected by `microsandbox-protocol` for the selected message type. This package validates message type support and frame shape, but it does not yet ship generated domain payload types.

## Node UDS Example

```ts
import { connectUnix } from "@microsandbox/agent-client/node";
import { typedMessage } from "@microsandbox/agent-client";

const client = await connectUnix("/tmp/msb-agent.sock", {
  handshakeTimeoutMs: 10_000,
});

const response = await client.request(
  typedMessage("core.fs.request", {
    op: {
      Stat: {
        path: "/etc/os-release",
        follow_symlink: true,
      },
    },
  }),
);

if (response.type === "core.fs.response") {
  console.log(response.decodePayload());
}
await client.close();
```

## Browser WebSocket Example

```ts
import {
  AgentClient,
  WebSocketTransport,
  typedMessage,
} from "@microsandbox/agent-client";

const transport = await WebSocketTransport.connect(
  "wss://relay.example.com/agent",
);
const client = await AgentClient.connectTransport(transport);

const stream = await client.openStream(
  typedMessage("core.exec.request", {
    cmd: "sh",
    args: ["-lc", "echo hello"],
  }),
);

for await (const frame of stream) {
  if (frame.type === "core.exec.stdout") {
    console.log(frame.decodePayload());
  }
  if (frame.type === "core.exec.exited") break;
}

await client.close();
```

Browsers cannot dial Unix domain sockets directly. A front-end integration needs a WebSocket relay endpoint that forwards binary agent protocol packets to the runtime-side agent relay.

## Typed And Encoded Messages

Use `typedMessage()` when this package should CBOR-encode the payload:

```ts
await client.request(
  typedMessage("core.fs.request", {
    op: { List: { path: "/" } },
  }),
);
```

Use `encodedMessage()` when another layer already produced CBOR payload bytes:

```ts
await client.request(
  encodedMessage("core.fs.request", payloadBytes),
);
```

Both forms still include a message type so the client can compute flags and fail fast when the connected peer does not support that message type.

`encodedMessage()` expects only the CBOR payload bytes for the message type, not the outer `{ v, t, p }` envelope and not the length-prefixed transport frame. The client builds the envelope and frame after it assigns the correlation ID.

## Streams

`openStream()` starts a session and returns an `AgentStream`:

```ts
const stream = await client.openStream(
  typedMessage("core.exec.request", { cmd: "cat" }),
);

await stream.send(
  typedMessage("core.exec.stdin", {
    data: new TextEncoder().encode("hello\n"),
  }),
);

const frame = await stream.next(5_000);
```

Streams are async iterable:

```ts
for await (const frame of stream) {
  if (frame.isTerminal()) break;
}
```

## Protocol Errors

Peers may send `core.error` as a terminal response when they can recover from a message-level protocol problem for a specific correlation ID. The client surfaces it as an ordinary `InboundFrame`:

```ts
const frame = await client.request(message);
if (frame.type === "core.error") {
  const err = frame.decodePayload<{
    kind: string;
    message: string;
    offending_type?: string;
  }>();
  console.error(err.message);
}
```

Frame-level transport corruption still closes the connection instead.

## TransportPacket Escape Hatch

`TransportPacket` represents exact wire bytes, including the length prefix. Use `writeUnchecked()` only for relays, tests, and specialized protocol tooling:

```ts
await client.writeUnchecked(TransportPacket.fromBytes(bytes));
```

Ordinary callers should use `request()`, `openStream()`, and `stream.send()`.

## Validation

Focused package checks:

```bash
npm run typecheck
npm run build
npm test
```
