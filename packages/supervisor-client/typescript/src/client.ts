import { Client, type ByteTransport, type Connector, type ConnectOptions } from "@microsandbox/protocol-client";
import { SupervisorProtocol } from "./protocol.js";
import {
  DEFAULT_SUPERVISOR_FRAME_SIZE, DEFAULT_SUPERVISOR_MAX_IN_FLIGHT,
  DEFAULT_SUPERVISOR_MAX_WATCHES, DEFAULT_SUPERVISOR_SETUP_TIMEOUT_MS,
  MIN_SUPERVISOR_GENERATION, SUPERVISOR_GENERATION, SUPERVISOR_PROTOCOL,
  type ClientInstanceId, type HomeDigest, type SupervisorHello,
} from "./records.js";

export type SupervisorClientConfig = {
  implementationVersion: string; clientInstanceId: ClientInstanceId; canonicalHomeDigest: HomeDigest;
  resumeCatalogRevision?: bigint; maxWatches?: number;
};
export type SupervisorClient = Client<SupervisorProtocol>;

function protocol(config: SupervisorClientConfig, options: ConnectOptions): SupervisorProtocol {
  const maxInFlight = Math.min(options.limits?.maxInFlight ?? DEFAULT_SUPERVISOR_MAX_IN_FLIGHT, DEFAULT_SUPERVISOR_MAX_IN_FLIGHT);
  const maxWatches = config.maxWatches ?? DEFAULT_SUPERVISOR_MAX_WATCHES;
  const hello: SupervisorHello = {
    protocol: SUPERVISOR_PROTOCOL, min_generation: MIN_SUPERVISOR_GENERATION,
    max_generation: SUPERVISOR_GENERATION, implementation_version: config.implementationVersion,
    client_instance_id: Uint8Array.from(config.clientInstanceId),
    canonical_home_digest: Uint8Array.from(config.canonicalHomeDigest),
    requested_limits: {
      max_frame_size: Math.min(options.limits?.maxFrameSize ?? DEFAULT_SUPERVISOR_FRAME_SIZE, 1024 * 1024),
      max_in_flight: maxInFlight, max_watches: maxWatches,
    },
    ...(config.resumeCatalogRevision === undefined ? {} : { resume_catalog_revision: config.resumeCatalogRevision }),
  };
  return new SupervisorProtocol(hello);
}

/** Configured browser-safe connection entry points. */
export const SupervisorClient = {
  async connectTransport(transport: ByteTransport, config: SupervisorClientConfig, options: ConnectOptions = {}): Promise<SupervisorClient> {
    const applied = { ...options, setupTimeoutMs: options.setupTimeoutMs ?? DEFAULT_SUPERVISOR_SETUP_TIMEOUT_MS };
    let selected: SupervisorProtocol;
    try { selected = protocol(config, applied); }
    catch (error) { await transport.close().catch(() => undefined); throw error; }
    return Client.connectTransport(transport, selected, applied);
  },
  connectConnector(connector: Connector, config: SupervisorClientConfig, options: ConnectOptions = {}): Promise<SupervisorClient> {
    const applied = { ...options, setupTimeoutMs: options.setupTimeoutMs ?? DEFAULT_SUPERVISOR_SETUP_TIMEOUT_MS };
    return Client.connectConnector(connector, protocol(config, applied), applied);
  },
};
