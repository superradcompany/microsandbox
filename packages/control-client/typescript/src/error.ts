import type { InboundFrame } from "@microsandbox/protocol-client";
import type { ControlError } from "./records.js";
import type { JsonReply } from "./json-reply.js";

export type ControlErrorCode = "peer" | "invalid_response" | "unsupported_mode" | "runtime_changed" | "legacy_remote" | "invalid_json_response";

const descriptions: Record<ControlErrorCode, string> = {
  peer: "control operation rejected by peer", invalid_response: "invalid control operation response",
  unsupported_mode: "operation requires framed control", runtime_changed: "runtime session changed",
  legacy_remote: "legacy control operation failed; batch progress is unknown", invalid_json_response: "invalid legacy control response",
};

/** Checked-operation failures retain the real response, without logging its data. */
export class ControlClientError extends Error {
  constructor(
    readonly code: ControlErrorCode,
    readonly response?: InboundFrame | JsonReply,
    readonly peerError?: ControlError,
  ) {
    super(descriptions[code]);
    this.name = "ControlClientError";
  }
  get delivery(): "not_sent" | "unknown" {
    return this.code === "unsupported_mode" || this.code === "runtime_changed" ? "not_sent" : "unknown";
  }
  [Symbol.for("nodejs.util.inspect.custom")](): string { return "ControlClientError: " + this.message; }
}
