import { LocalConnector } from "@microsandbox/protocol-client/node";
import type { ConnectOptions } from "@microsandbox/protocol-client";
import { ControlClient } from "./client.js";
import { ControlConnection } from "./connection.js";
import { JsonControlClient } from "./json-client.js";

export * from "./index.js";
export { LocalConnector } from "@microsandbox/protocol-client/node";

/** Explicit framed hello on an existing Unix socket or Windows pipe path. */
export function connectFramedControl(path: string, options?: ConnectOptions): Promise<ControlClient> {
  return ControlClient.connectConnector(new LocalConnector(path), options);
}

/** Discover on the existing Unix socket or Windows pipe, then reuse that session. */
export function connectControl(path: string, options?: ConnectOptions): Promise<ControlConnection> {
  return ControlConnection.connectConnector(new LocalConnector(path), options);
}

/** Explicit legacy adapter; no connection is opened until an operation runs. */
export function jsonControl(path: string, options?: ConnectOptions): JsonControlClient {
  return JsonControlClient.fromConnector(new LocalConnector(path), options);
}
