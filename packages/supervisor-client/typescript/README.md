# @microsandbox/supervisor-client

Typed TypeScript client for the local microsandbox supervisor protocol.

The browser-safe root accepts caller-owned transports and connectors. Node endpoint dialing lives in `@microsandbox/supervisor-client/node`. The package performs only the configured `MSBS` and CBOR handshake; it does not start a supervisor process.

```ts
import { connectSupervisor } from "@microsandbox/supervisor-client/node";
import { GetSupervisorStatus } from "@microsandbox/supervisor-client";

const client = await connectSupervisor("/run/user/1000/microsandbox/supervisor.sock", {
  implementationVersion: "0.7.4",
  clientInstanceId: crypto.getRandomValues(new Uint8Array(16)),
  canonicalHomeDigest: new Uint8Array(32),
});
const status = await client.requestTyped(new GetSupervisorStatus());
```
