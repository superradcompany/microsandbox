import { ClientError } from "@microsandbox/protocol-client";
import { ControlClientError } from "./error.js";
import { jsonObject, jsonUint, parseJson, type JsonObject, type JsonValue } from "./json-value.js";
import type { Capabilities, CpuState, MemoryState } from "./records.js";

export type ControlMode = "cbor" | "json";

/** Actual legacy bytes and an inspectable lossless object; no fabricated frame. */
export class JsonReply {
  readonly #raw: Uint8Array;
  readonly #value: JsonObject;
  constructor(raw: Uint8Array) {
    this.#raw = raw.slice();
    this.#value = jsonObject(parseJson(this.#raw));
  }
  get raw(): Uint8Array { return this.#raw; }
  get value(): JsonObject { return this.#value; }
  [Symbol.for("nodejs.util.inspect.custom")](): string { return "JsonReply { bytes: " + this.#raw.length + " }"; }

  /** Only a valid affirmative capabilities reply is evidence of a legacy peer. */
  discoveryMode(): ControlMode {
    if (this.value.get("ok") !== true || (this.value.has("error") && this.value.get("error") !== null)) throw new ClientError("invalid_data");
    jsonCapabilities(this.value.get("capabilities"));
    if (!this.value.has("control_protocols")) return "json";
    const protocols = this.value.get("control_protocols");
    if (!Array.isArray(protocols) || protocols.some(name => typeof name !== "string")) throw new ClientError("invalid_data");
    if (protocols.includes("cbor")) return "cbor";
    if (protocols.includes("json")) return "json";
    throw new ClientError("unsupported_operation");
  }

  /** Only checked helpers turn ok:false into an error; progress stays unknown. */
  checked<T>(decode: (value: JsonObject) => T): T {
    if (this.value.get("ok") === false) throw new ControlClientError("legacy_remote", this);
    if (this.value.get("ok") !== true) throw new ControlClientError("invalid_json_response", this);
    try { return decode(this.value); }
    catch { throw new ControlClientError("invalid_json_response", this); }
  }
}

export function jsonCapabilities(value: JsonValue | undefined): Capabilities {
  const fields = jsonObject(value);
  const boolean = (name: string): boolean => {
    const field = fields.get(name);
    if (typeof field !== "boolean") throw new ClientError("invalid_data");
    return field;
  };
  return { ...(fields.has("root_disk_grow") ? { root_disk_grow: boolean("root_disk_grow") } : {}), cpu_resize: boolean("cpu_resize"), memory_resize: boolean("memory_resize"), secrets_update: boolean("secrets_update") };
}
export function jsonMemory(value: JsonValue | undefined): MemoryState {
  const fields = jsonObject(value), uint = (name: string) => jsonUint(fields.get(name), 64);
  return { boot_mib: uint("boot_mib"), target_mib: uint("target_mib"), current_mib: uint("current_mib"), max_mib: uint("max_mib") };
}
export function jsonCpu(value: JsonValue | undefined): CpuState {
  const fields = jsonObject(value), uint = (name: string) => Number(jsonUint(fields.get(name), 32));
  return { possible: uint("possible"), requested_online: uint("requested_online"), actual_online: uint("actual_online"), enforced: uint("enforced") };
}
