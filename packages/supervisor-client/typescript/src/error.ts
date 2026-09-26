import type { InboundFrame } from "@microsandbox/protocol-client";
import type { SupervisorError } from "./records.js";

export type SupervisorClientErrorCode = "peer" | "invalid_response";

/** Checked-operation failure retaining the exact peer response. */
export class SupervisorClientError extends Error {
  constructor(
    readonly code: SupervisorClientErrorCode,
    readonly response: InboundFrame,
    readonly peerError?: SupervisorError,
  ) {
    super(code === "peer" ? "supervisor operation rejected by peer" : "invalid supervisor operation response");
    this.name = "SupervisorClientError";
  }
  readonly delivery = "unknown" as const;
  [Symbol.for("nodejs.util.inspect.custom")](): string { return "SupervisorClientError: " + this.message; }
}
