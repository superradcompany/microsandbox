import { AgentClient, type ConnectOptions } from "./client.js";
import { UnixSocketTransport } from "./transports/unix.js";

export { AgentClient, type ConnectOptions } from "./client.js";
export { UnixSocketTransport } from "./transports/unix.js";
export * from "./index.js";

/**
 * Connect to a Node.js Unix domain socket agent relay and complete the client
 * handshake.
 *
 * Import from `@microsandbox/agent-client/node` for this helper. The default
 * package entry intentionally excludes Node builtins so front-end bundles can
 * use the WebSocket transport.
 */
export async function connectUnix(
  path: string,
  options: ConnectOptions = {},
): Promise<AgentClient> {
  const transport = await UnixSocketTransport.connect(path);
  return AgentClient.connectTransport(transport, options);
}
