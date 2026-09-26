import { LocalConnector } from "@microsandbox/protocol-client/node";
import type { ConnectOptions } from "@microsandbox/protocol-client";
import { SupervisorClient, type SupervisorClientConfig } from "./client.js";

export * from "./index.js";
export { LocalConnector } from "@microsandbox/protocol-client/node";

/** Connect an already-running supervisor at its resolved local endpoint. */
export function connectSupervisor(
  path: string,
  config: SupervisorClientConfig,
  options?: ConnectOptions,
): Promise<SupervisorClient> {
  return SupervisorClient.connectConnector(new LocalConnector(path), config, options);
}
