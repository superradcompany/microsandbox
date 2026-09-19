import { LocalConnector } from "@microsandbox/protocol-client/node";
import { AgentClient, type ConnectOptions } from "./client.js";

export * from "./index.js";
export { UnixSocketTransport, LocalConnector } from "./transports/unix.js";

/** Connect to a native agent relay with one deadline covering dialing and setup. */
export function connectUnix(path: string, options: ConnectOptions = {}): Promise<AgentClient> {
  return AgentClient.connectConnector(new LocalConnector(path), options);
}
