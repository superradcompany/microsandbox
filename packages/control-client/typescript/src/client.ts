import { Client, type ByteTransport, type Connector, type ConnectOptions } from "@microsandbox/protocol-client";
import { ControlProtocol } from "./protocol.js";

/** The full generic native/encoded/raw/stream/packet API, specialized for control. */
export type ControlClient = Client<ControlProtocol>;
export const ControlClient = {
  connectTransport(transport: ByteTransport, options?: ConnectOptions): Promise<ControlClient> {
    return Client.connectTransport(transport, new ControlProtocol(), options);
  },
  connectConnector(connector: Connector, options?: ConnectOptions): Promise<ControlClient> {
    return Client.connectConnector(connector, new ControlProtocol(), options);
  },
};
