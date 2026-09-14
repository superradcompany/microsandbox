import { Client, type ByteTransport, type Connector, type ConnectOptions } from "@microsandbox/protocol-client";
import { AgentProtocol } from "./protocol.js";

/** Agent specialization of the shared router; all low-level APIs remain available. */
export type AgentClient = Client<AgentProtocol>;
/** Convenience constructors select the agent protocol without introducing another router. */
export const AgentClient = {
  connectTransport(transport: ByteTransport, options?: ConnectOptions): Promise<AgentClient> {
    return Client.connectTransport(transport, new AgentProtocol(), options);
  },
  connectConnector(connector: Connector, options?: ConnectOptions): Promise<AgentClient> {
    return Client.connectConnector(connector, new AgentProtocol(), options);
  },
};
export type { ConnectOptions } from "@microsandbox/protocol-client";
