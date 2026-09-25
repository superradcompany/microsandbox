import { ClientError } from "@microsandbox/protocol-client";
import { ControlClientError } from "./error.js";
import { jsonObject, jsonUint, parseJson, type JsonObject, type JsonValue } from "./json-value.js";
import type {
  BranchResult, Capabilities, CheckpointState, DiskCheckpointState, DiskCompactionResult,
  PauseState, RootDiskState, RuntimeCapabilities, CpuState, MemoryState,
} from "./records.js";

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
  return {
    ...(fields.has("root_disk_grow") ? { root_disk_grow: boolean("root_disk_grow") } : {}),
    cpu_resize: boolean("cpu_resize"), memory_resize: boolean("memory_resize"),
    secrets_update: boolean("secrets_update"),
  };
}
export function jsonRuntimeCapabilities(value: JsonValue | undefined): RuntimeCapabilities {
  const fields = jsonObject(value);
  const boolean = (name: string): boolean => {
    const field = fields.get(name);
    if (typeof field !== "boolean") throw new ClientError("invalid_data");
    return field;
  };
  const optional = (name: string): boolean => fields.has(name) ? boolean(name) : false;
  return {
    root_disk_grow: optional("root_disk_grow"), guest_flush_policy: optional("guest_flush_policy"),
    optional_disk_integrity: optional("optional_disk_integrity"), branch_create: optional("branch_create"),
    branch_memfd: optional("branch_memfd"), pause_resume: optional("pause_resume"),
    disk_compact: optional("disk_compact"), disk_compact_owned: optional("disk_compact_owned"),
    cpu_resize: boolean("cpu_resize"), memory_resize: boolean("memory_resize"),
    secrets_update: boolean("secrets_update"), checkpoint_create: optional("checkpoint_create"),
    disk_checkpoint_create: optional("disk_checkpoint_create"),
  };
}
export function jsonMemory(value: JsonValue | undefined): MemoryState {
  const fields = jsonObject(value), uint = (name: string) => jsonUint(fields.get(name), 64);
  return { boot_mib: uint("boot_mib"), target_mib: uint("target_mib"), current_mib: uint("current_mib"), max_mib: uint("max_mib") };
}
export function jsonCpu(value: JsonValue | undefined): CpuState {
  const fields = jsonObject(value), uint = (name: string) => Number(jsonUint(fields.get(name), 32));
  return { possible: uint("possible"), requested_online: uint("requested_online"), actual_online: uint("actual_online"), enforced: uint("enforced") };
}

export function jsonCheckpoint(value: JsonValue | undefined): CheckpointState {
  const fields = jsonObject(value), uint = (name: string) => jsonUint(fields.get(name), 64);
  return {
    checkpoint_id: jsonText(fields.get("checkpoint_id")), checkpoint_root: jsonText(fields.get("checkpoint_root")),
    path: jsonText(fields.get("path")), memory_mode: jsonText(fields.get("memory_mode")),
    memory_logical_bytes: uint("memory_logical_bytes"), memory_emitted_bytes: uint("memory_emitted_bytes"),
  };
}

export function jsonDiskCheckpoint(value: JsonValue | undefined): DiskCheckpointState {
  const fields = jsonObject(value);
  const owned = fields.get("owned_volumes");
  if (owned !== undefined && !Array.isArray(owned)) throw new ClientError("invalid_data");
  if (!fields.has("disk")) throw new ClientError("invalid_data");
  return {
    checkpoint_id: jsonText(fields.get("checkpoint_id")), path: jsonText(fields.get("path")),
    disk: fields.get("disk"), owned_volumes: owned ?? [],
  };
}

export function jsonBranch(value: JsonValue | undefined): BranchResult {
  return { path: jsonText(value) };
}

export function jsonPause(value: JsonValue | undefined): PauseState {
  const fields = jsonObject(value);
  const unavailable = fields.get("capture_unavailable");
  if (unavailable !== undefined && unavailable !== null && typeof unavailable !== "string") throw new ClientError("invalid_data");
  return {
    paused: jsonBool(fields.get("paused")), recovery_required: jsonBool(fields.get("recovery_required")),
    ...(typeof unavailable === "string" ? { capture_unavailable: unavailable } : {}),
  };
}

export function jsonRootDisk(value: JsonValue | undefined): RootDiskState {
  const fields = jsonObject(value), uint = (name: string) => jsonUint(fields.get(name), 64);
  return {
    filesystem_bytes: uint("filesystem_bytes"), device_bytes: uint("device_bytes"), total_us: uint("total_us"),
    pause_us: uint("pause_us"), guest_us: uint("guest_us"),
  };
}

export function jsonDiskCompaction(value: JsonValue | undefined): DiskCompactionResult {
  const fields = jsonObject(value), uint = (name: string) => jsonUint(fields.get(name), 64);
  const entries = fields.get("disks");
  if (!Array.isArray(entries)) throw new ClientError("invalid_data");
  const disks = entries.map(value => {
    const disk = jsonObject(value), diskUint = (name: string) => jsonUint(disk.get(name), 64);
    return {
      guest_path: jsonText(disk.get("guest_path")), input_layers: diskUint("input_layers"),
      selected_layers: diskUint("selected_layers"), output_layers: diskUint("output_layers"),
      materialized_bytes: diskUint("materialized_bytes"), total_us: diskUint("total_us"),
    };
  });
  return {
    dry_run: jsonBool(fields.get("dry_run")), input_layers: uint("input_layers"),
    selected_layers: uint("selected_layers"), output_layers: uint("output_layers"),
    materialized_bytes: uint("materialized_bytes"), total_us: uint("total_us"),
    pause_us: uint("pause_us"), disks,
  };
}

function jsonText(value: JsonValue | undefined): string {
  if (typeof value !== "string") throw new ClientError("invalid_data");
  return value;
}

function jsonBool(value: JsonValue | undefined): boolean {
  if (typeof value !== "boolean") throw new ClientError("invalid_data");
  return value;
}
