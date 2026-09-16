/** Whether this attempt crossed writer admission; never a retry instruction. */
export type Delivery = "not_sent" | "unknown";
/** Transport/router errors, separate from application response errors. */
export type ErrorCode = "closed" | "peer_closed" | "truncated_frame" | "io" | "timeout" | "cancelled" | "invalid_data" | "invalid_options" | "capacity" | "ids_exhausted" | "stream_closed" | "unsupported_operation" | "encode" | "receiving" | "split";

const descriptions: Record<ErrorCode, string> = {
  closed: "client closed", peer_closed: "peer closed before terminal completion",
  truncated_frame: "transport closed inside a frame", io: "transport I/O failed",
  timeout: "local wait timed out", cancelled: "local wait cancelled",
  invalid_data: "invalid protocol data", invalid_options: "invalid client configuration",
  capacity: "client capacity exhausted", ids_exhausted: "correlation ID range exhausted",
  stream_closed: "stream is closed or not owned by this connection",
  unsupported_operation: "operation is unsupported by the peer", encode: "could not encode protocol message",
  receiving: "a receive is already pending", split: "stream ownership has already been split",
};

/** Sanitized diagnostics retain delivery state and never include payload values. */
export class ClientError extends Error {
  constructor(readonly code: ErrorCode, readonly delivery: Delivery = "not_sent") {
    super(`${descriptions[code]} (delivery: ${delivery})`);
    this.name = "ClientError";
  }
  withDelivery(delivery: Delivery): ClientError { return new ClientError(this.code, delivery); }
}

/** Preserve a known client error; arbitrary transport diagnostics are not safe. */
export function clientError(error: unknown): ClientError {
  return error instanceof ClientError ? error : new ClientError("io");
}
