# @microsandbox/agent-client

Low-level TypeScript access to the microsandbox agent protocol. `AgentClient` is `Client<AgentProtocol>` from `@microsandbox/protocol-client`; the agent package supplies relay setup, its existing encoder, and generation gates. The shared engine owns framing, IDs, queues, cancellation, and transport lifetime. Sandbox lifecycle and process/filesystem convenience APIs belong to the SDK.

```text
AgentProtocol (setup, encoder, gates)
                 |
          Client<AgentProtocol>
            /          \
 native / encoded     raw / exact packets
                 |
       Unix socket / named pipe / WebSocket
```

## Installation and entry points

Install with `npm install @microsandbox/agent-client`. Node.js 22 or newer is required for native transports. The root entry is browser-safe. `@microsandbox/agent-client/node` imports Node's `net` module and accepts native endpoint paths verbatim, including Windows named-pipe names.

## Native messages

```ts
import { connectUnix } from "@microsandbox/agent-client/node";
import { typedMessage } from "@microsandbox/agent-client";

const client = await connectUnix("/tmp/msb-agent.sock", { setupTimeoutMs: 10_000 });
try {
  const response = await client.request(typedMessage("core.fs.request", {
    op: { Stat: { path: "/etc/os-release", follow_symlink: true } },
  }), { requestTimeoutMs: 5_000 });
  console.log(response.type, response.decodePayload());
  console.log(client.ready.agentVersion, client.ready.negotiatedVersion);
} finally {
  await client.close();
}
```

`typedMessage(name, value)` asks the agent codec to encode a native payload. `encodedMessage(name, bytes)` supplies only the application payload; it does not supply an envelope or framed packet. Both paths apply known message gates and flags. Names are open strings, so extensions remain accessible without editing an enum. These methods do not validate an application schema. `requestTyped()` accepts an optional checked request with its own result decoder and requires a terminal response.

The current TypeScript agent encoder continues to emit generation-five envelopes, including its existing CBOR map and byte-string representations. The ready generation controls feature gates. The supported pre-0.5 relay prologue selects generation-one envelopes and rejects unavailable filesystem/TCP operations before sending. The captured ready frame and unknown fields remain available through `client.ready.frame` and `client.ready.readyBytes`.

## Browser streams

```ts
import { AgentClient, WebSocketConnector, typedMessage } from "@microsandbox/agent-client";

const client = await AgentClient.connectConnector(
  new WebSocketConnector("wss://relay.example.com/agent"),
  { setupTimeoutMs: 10_000 },
);
try {
  const stream = await client.openStream(typedMessage("core.exec.request", {
    cmd: "sh", args: ["-lc", "echo hello"],
  }));
  try {
    for await (const frame of stream) {
      console.log(frame.type, frame.payload);
    }
  } finally {
    stream.close();
  }
} finally {
  await client.close();
}
```

The relay must forward the agent's binary byte stream, including its prologue. `WebSocketTransport` also wraps a caller-constructed socket for custom authentication. Its incoming queue defaults to 8 MiB and 4096 messages; overflow closes the connection because browser WebSockets cannot pause incoming messages. Outgoing writes wait for the browser's send queue to drain. The connector and handshake share one setup deadline.

## Raw and exact access

```ts
import { type AgentClient, TransportPacket } from "@microsandbox/agent-client";

async function exchangeOpaque(client: AgentClient, envelope: Uint8Array) {
  const stream = await client.openStreamRaw(0, envelope);
  const { sender, receiver } = stream.split();
  try {
    await sender.send(0, envelope);
    await client.sendRaw(sender.id, 0, envelope);
    return await receiver.next({ requestTimeoutMs: 5_000 });
  } finally {
    receiver.close();
    sender.close();
  }
}

async function forwardExactPacket(client: AgentClient, bytes: Uint8Array) {
  await client.writeUnchecked(TransportPacket.fromBytes(bytes));
}
```

Raw APIs leave envelope and payload bytes opaque. `requestRaw(flags, body)` returns the first raw reply. `openStreamRaw()` receives through the terminal reply. `sendRaw(id, flags, body)` requires an active ID owned by this connection. A split sender retains its original lease and cannot regain permission if the numeric ID is reused. `writeUnchecked(bytes)` can write even deliberately malformed transport bytes; `TransportPacket.fromBytes()` optionally validates a single packet first.

Native replies retain the complete original raw frame as `frame.raw`, including unknown envelope fields. `core.error` is an ordinary terminal agent response; interpreting it belongs to the caller or a checked request decoder.

## Ownership and failures

Streams own their send and receive halves. `split()` transfers those halves and invalidates the original stream's send/receive methods. Closing a receiver or leaving async iteration stops local delivery; it sends no remote cancel, signal, or EOF. An abandoned ID remains draining until its terminal frame arrives. A timed-out `next()` does not consume the next arriving frame.

`client.clone()` shares the connection. `client.close()` closes every shared handle and wakes pending operations. Explicitly close clients and streams: JavaScript garbage collection only offers best-effort cleanup. A request deadline covers writer admission and the local response wait; it does not cancel remote execution. `ClientError.delivery` is `not_sent` before admission and `unknown` afterward. Nothing automatically retries an admitted operation.

## Migration from the previous package API

| Previous surface | Shared-engine surface |
| --- | --- |
| Independent `AgentClient` class/router | `AgentClient = Client<AgentProtocol>` plus convenience constructors |
| `handshakeTimeoutMs` | `setupTimeoutMs`, covering dial and handshake together |
| `client.negotiatedVersion()` | `client.ready.negotiatedVersion` |
| Closed `MessageType` parameter | Open string names; `MessageType` still lists known names |
| Packet-oriented custom `AgentTransport` | Ordered `read(maxBytes)`, `write(bytes)`, `close()` byte transport |
| `InboundFrame.fromRawFrame(frame)` | `new AgentEnvelopeCodec().decode(frame)` |
| `new AgentStream(...)` | Obtain owned streams from `client.openStream()` or `openStreamRaw()` |
| Request, encoded payload, stream, exact packet methods | Retained on the generic client, with additional raw and split interfaces |

These are public source API changes. Existing agent wire behavior is preserved; source and byte tests do not replace the required historical runtime/SDK launch tests.

## Development

From the repository's `packages` directory, run `npm ci`, `npm run build`, `npm run typecheck`, and `npm test`. The private workspace links the shared package locally; published dependency metadata uses the release version. The README's TypeScript examples are checked with the public package declarations.
