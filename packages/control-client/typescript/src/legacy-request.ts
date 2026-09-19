import { ClientError, type OutboundMessage, type Request } from "@microsandbox/protocol-client";
import { ControlClientError } from "./error.js";
import type { JsonReply } from "./json-reply.js";
import { checkedUint, type SecretChange } from "./records.js";

/** Existing JSON operation spellings, independent of the CBOR envelope. */
export type LegacyControlRequest =
  | { op: "capabilities" | "memory_state" | "cpu_state" }
  | { op: "memory_target"; total_mib: bigint }
  | { op: "cpu_target"; online: number }
  | { op: "secrets_update"; changes: readonly SecretChange[] };

/** Prepared operations can decode either actual response representation. */
export interface CheckedControlRequest<T> extends Request<T> {
  jsonRequest(): LegacyControlRequest;
  decodeJson(reply: JsonReply): T;
}

export function nativeJsonRequest(message: OutboundMessage): LegacyControlRequest {
  if (message.kind !== "typed") throw new ControlClientError("unsupported_mode");
  const fields = record(message.payload);
  switch (message.type) {
    case "control.capabilities": return { op: "capabilities" };
    case "control.memory.state": return { op: "memory_state" };
    case "control.cpu.state": return { op: "cpu_state" };
    case "control.memory.target": return { op: "memory_target", total_mib: uint(fields.total_mib, 64) };
    case "control.cpu.target": return { op: "cpu_target", online: Number(uint(fields.online, 32)) };
    case "control.secrets.update": return { op: "secrets_update", changes: snapshotChanges(fields.changes) };
    default: throw new ControlClientError("unsupported_mode");
  }
}

/** Validate and snapshot without passing a large legacy batch through CBOR. */
export function snapshotChanges(value: unknown): readonly SecretChange[] {
  if (!Array.isArray(value)) throw new ClientError("invalid_data");
  checkedUint(value.length, 32);
  return value.map(value => {
    const fields = record(value), name = text(fields.name);
    switch (fields.change) {
      case "rotate": return { change: "rotate", name, value: text(fields.value) };
      case "remove": return { change: "remove", name };
      case "set_allowed_hosts":
        if (!Array.isArray(fields.hosts)) throw new ClientError("invalid_data");
        return { change: "set_allowed_hosts", name, hosts: fields.hosts.map(text) };
      default: throw new ClientError("invalid_data");
    }
  });
}

export function encodeJsonRequest(request: LegacyControlRequest): Uint8Array {
  let line: string;
  // Bigint memory targets are decimal JSON integer tokens, never quoted strings
  // or rounded Numbers. Other fields are validated before JSON serialization.
  switch (request.op) {
    case "capabilities": case "memory_state": case "cpu_state": line = JSON.stringify({ op: request.op }); break;
    case "memory_target": line = '{"op":"memory_target","total_mib":' + uint(request.total_mib, 64).toString() + "}"; break;
    case "cpu_target": line = JSON.stringify({ op: request.op, online: Number(uint(request.online, 32)) }); break;
    case "secrets_update": line = JSON.stringify({ op: request.op, changes: snapshotChanges(request.changes) }); break;
    default: throw new ClientError("invalid_data");
  }
  return new TextEncoder().encode(line + "\n");
}

function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new ClientError("invalid_data");
  return value as Record<string, unknown>;
}
function text(value: unknown): string {
  if (typeof value !== "string") throw new ClientError("invalid_data");
  // Reject isolated surrogates instead of sending strings Rust cannot decode.
  if (/[\uD800-\uDFFF]/u.test(value)) throw new ClientError("invalid_data");
  return value;
}
function uint(value: unknown, bits: 32 | 64): bigint {
  if (typeof value !== "number" && typeof value !== "bigint") throw new ClientError("invalid_data");
  return checkedUint(value, bits);
}
