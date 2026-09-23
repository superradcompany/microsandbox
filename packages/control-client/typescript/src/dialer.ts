import type { ConnectContext, Connector } from "@microsandbox/protocol-client";

/**
 * Backend-owned identity seam. connect must verify each connected peer against
 * the saved OS process birth token. verifySession must recheck the active run
 * and process before an operation; a PID or endpoint path alone is insufficient.
 * Both methods reject runtime replacement before returning an owned transport
 * or permitting operation admission, using ControlClientError/runtime_changed.
 */
export interface VerifiedControlConnector extends Connector {
  verifySession(context: ConnectContext): Promise<void>;
}

export type ControlDialer = { connector: Connector; verifier?: VerifiedControlConnector };
