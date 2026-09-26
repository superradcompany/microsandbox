import {
  MAX_FRAME_SIZE, WireError, readArray, readBool, readBytes, readRecord, readText, readUint, required,
} from "@microsandbox/protocol-client";

export const SUPERVISOR_MAGIC = Uint8Array.of(0x4d, 0x53, 0x42, 0x53);
export const MIN_SUPERVISOR_GENERATION = 1;
export const SUPERVISOR_GENERATION = 1;
export const SUPERVISOR_HANDSHAKE_GENERATION = 1;
export const SUPERVISOR_PROTOCOL = "msb.supervisor";
export const MAX_SUPERVISOR_FRAME_SIZE = 1024 * 1024;
export const MAX_SUPERVISOR_HANDSHAKE_FRAME_SIZE = 16 * 1024;
export const DEFAULT_SUPERVISOR_FRAME_SIZE = 256 * 1024;
export const DEFAULT_SUPERVISOR_MAX_IN_FLIGHT = 32;
export const DEFAULT_SUPERVISOR_MAX_WATCHES = 8;
export const DEFAULT_SUPERVISOR_SETUP_TIMEOUT_MS = 5_000;
export const DEFAULT_SUPERVISOR_REQUEST_TIMEOUT_MS = 30_000;

export type ClientInstanceId = Uint8Array;
export type SupervisorInstanceId = Uint8Array;
export type SandboxLineageId = Uint8Array;
export type RuntimeBootId = Uint8Array;
export type SupervisorRequestId = Uint8Array;
export type OperationId = Uint8Array;
export type HomeDigest = Uint8Array;

export type SupervisorLimits = { max_frame_size: number; max_in_flight: number; max_watches: number };
export type LaunchProfile = "supervised" | "jailed_linux_v1";
export type SupervisorHello = {
  protocol: string; min_generation: number; max_generation: number; implementation_version: string;
  client_instance_id: ClientInstanceId; canonical_home_digest: HomeDigest;
  requested_limits: SupervisorLimits; resume_catalog_revision?: bigint;
};
export type SupervisorWelcome = {
  protocol: string; generation: number; implementation_version: string;
  supervisor_instance_id: SupervisorInstanceId; canonical_home_digest: HomeDigest;
  effective_limits: SupervisorLimits; current_catalog_revision: bigint;
  oldest_catalog_revision: bigint; launch_profile: LaunchProfile;
};
export type VersionedDocument = { schema_generation: number; cbor: Uint8Array };
export type SandboxLocator =
  | { kind: "lineage"; lineage_id: SandboxLineageId }
  | { kind: "name"; name: string };
export type Mutation<T> = { supervisor_request_id: SupervisorRequestId; expected_catalog_revision?: bigint; intent: T };
export type DesiredSandboxState = "stopped" | "running" | "removed";
export type ObservedSandboxState = "absent" | "creating" | "starting" | "running" | "stopping" | "stopped" | "failed" | "removing";
export type OperationState = "pending" | "running" | "succeeded" | "failed" | "cancelled";
export type RetryClass = "never" | "transient" | "after_correction";
export type SupervisorError = { code: string; message: string; retry_class: RetryClass; details?: Uint8Array };
export type SupervisorStatus = {
  supervisor_instance_id: SupervisorInstanceId; catalog_revision: bigint; sandbox_count: bigint;
  running_count: bigint; reconciled: boolean;
};
export type SupervisorCapabilities = { lifecycle_operations: boolean; watches: boolean; sandbox_modify: boolean; jailer: boolean };
export type SandboxRecord = {
  lineage_id: SandboxLineageId; name: string; desired_state: DesiredSandboxState;
  observed_state: ObservedSandboxState; runtime_boot_id?: RuntimeBootId; catalog_revision: bigint;
};
export type OperationRecord = {
  operation_id: OperationId; supervisor_request_id: SupervisorRequestId; state: OperationState;
  sandbox?: SandboxLineageId; error?: SupervisorError; catalog_revision: bigint;
};
export type RequestRecord = { supervisor_request_id: SupervisorRequestId; intent_fingerprint: Uint8Array; operation: OperationRecord };
export type OperationAccepted = { operation_id: OperationId; supervisor_request_id: SupervisorRequestId; catalog_revision: bigint; replayed: boolean };
export type CreateSandboxIntent = { name: string; spec: VersionedDocument; isolation_profile: string };
export type SandboxActionIntent = { sandbox: SandboxLocator };
export type ModifySandboxIntent = { sandbox: SandboxLocator; patch: VersionedDocument };
export type GetRequest = { supervisor_request_id: SupervisorRequestId };
export type InspectSandbox = { sandbox: SandboxLocator };
export type ListSandboxes = { limit: number; cursor?: Uint8Array };
export type SandboxList = { catalog_revision: bigint; sandboxes: readonly SandboxRecord[]; next_cursor?: Uint8Array };
export type OperationSelector = { operation_id: OperationId };
export type WatchCatalog = { from_revision: bigint };
export type CatalogEvent = { catalog_revision: bigint; sandbox?: SandboxRecord; operation?: OperationRecord };
export type WatchEnd = { reason: string; last_catalog_revision: bigint };

export const SupervisorMessageType = {
  Hello: "supervisor.hello", Welcome: "supervisor.welcome", Error: "supervisor.error",
  Status: "supervisor.status", StatusResult: "supervisor.status.result",
  Capabilities: "supervisor.capabilities", CapabilitiesResult: "supervisor.capabilities.result",
  Watch: "supervisor.watch", Event: "supervisor.event", WatchEnd: "supervisor.watch.end",
  RequestGet: "request.get", RequestGetResult: "request.get.result",
  SandboxCreate: "sandbox.create", SandboxStart: "sandbox.start", SandboxStop: "sandbox.stop",
  SandboxKill: "sandbox.kill", SandboxRestart: "sandbox.restart", SandboxRemove: "sandbox.remove",
  SandboxModify: "sandbox.modify", SandboxInspect: "sandbox.inspect",
  SandboxInspectResult: "sandbox.inspect.result", SandboxList: "sandbox.list",
  SandboxListResult: "sandbox.list.result", OperationAccepted: "operation.accepted",
  OperationGet: "operation.get", OperationGetResult: "operation.get.result",
  OperationWatch: "operation.watch", OperationEvent: "operation.event",
  OperationWatchEnd: "operation.watch.end", OperationCancel: "operation.cancel",
  OperationRetry: "operation.retry", OperationActionResult: "operation.action.result",
} as const;

const uint = (fields: Map<string, Uint8Array>, name: string, bits: 8 | 32 | 64): bigint => readUint(required(fields, name), bits);
const text = (fields: Map<string, Uint8Array>, name: string): string => readText(required(fields, name));
const bytes = (fields: Map<string, Uint8Array>, name: string, length: number): Uint8Array => {
  const value = readBytes(required(fields, name));
  if (value.length !== length) throw new WireError("invalid_record");
  return value;
};

export function checkedUint(value: number | bigint, bits: 8 | 32 | 64): bigint {
  if (typeof value !== "bigint" && (typeof value !== "number" || !Number.isSafeInteger(value))) throw new WireError("invalid_record");
  const integer = BigInt(value);
  if (integer < 0n || integer >= (1n << BigInt(bits))) throw new WireError("invalid_record");
  return integer;
}

export function validateLimits(limits: SupervisorLimits): void {
  checkedUint(limits.max_frame_size, 32); checkedUint(limits.max_in_flight, 32); checkedUint(limits.max_watches, 32);
  if (limits.max_frame_size < 5 || limits.max_frame_size > MAX_SUPERVISOR_FRAME_SIZE
      || limits.max_in_flight < 1 || limits.max_watches < 1 || limits.max_watches > limits.max_in_flight) throw new WireError("invalid_record");
}

export function validateHello(hello: SupervisorHello): void {
  validateLimits(hello.requested_limits);
  checkedUint(hello.min_generation, 8); checkedUint(hello.max_generation, 8);
  if (hello.protocol !== SUPERVISOR_PROTOCOL || hello.min_generation < 1
      || hello.min_generation > hello.max_generation
      || hello.implementation_version.length === 0 || hello.client_instance_id.length !== 16
      || hello.canonical_home_digest.length !== 32) throw new WireError("invalid_record");
}

export function decodeWelcome(payload: Uint8Array, hello: SupervisorHello): SupervisorWelcome {
  const fields = readRecord(payload);
  const limitsFields = readRecord(required(fields, "effective_limits"));
  const effective_limits = {
    max_frame_size: Number(uint(limitsFields, "max_frame_size", 32)),
    max_in_flight: Number(uint(limitsFields, "max_in_flight", 32)),
    max_watches: Number(uint(limitsFields, "max_watches", 32)),
  };
  const profile = text(fields, "launch_profile");
  if (profile !== "supervised" && profile !== "jailed_linux_v1") throw new WireError("invalid_record");
  const welcome: SupervisorWelcome = {
    protocol: text(fields, "protocol"), generation: Number(uint(fields, "generation", 8)),
    implementation_version: text(fields, "implementation_version"),
    supervisor_instance_id: bytes(fields, "supervisor_instance_id", 16),
    canonical_home_digest: bytes(fields, "canonical_home_digest", 32), effective_limits,
    current_catalog_revision: uint(fields, "current_catalog_revision", 64),
    oldest_catalog_revision: uint(fields, "oldest_catalog_revision", 64), launch_profile: profile,
  };
  validateLimits(welcome.effective_limits);
  if (welcome.protocol !== SUPERVISOR_PROTOCOL || welcome.generation < hello.min_generation
      || welcome.generation > hello.max_generation || welcome.implementation_version.length === 0
      || !welcome.canonical_home_digest.every((byte, index) => byte === hello.canonical_home_digest[index])
      || welcome.effective_limits.max_frame_size > hello.requested_limits.max_frame_size
      || welcome.effective_limits.max_in_flight > hello.requested_limits.max_in_flight
      || welcome.effective_limits.max_watches > hello.requested_limits.max_watches
      || welcome.oldest_catalog_revision > welcome.current_catalog_revision) throw new WireError("invalid_record");
  return welcome;
}

export function decodeSupervisorError(payload: Uint8Array): SupervisorError {
  const fields = readRecord(payload);
  const retry = text(fields, "retry_class");
  if (retry !== "never" && retry !== "transient" && retry !== "after_correction") throw new WireError("invalid_record");
  return {
    code: text(fields, "code"), message: text(fields, "message"), retry_class: retry,
    ...(fields.has("details") ? { details: readBytes(required(fields, "details")) } : {}),
  };
}

const optionalBytes = (fields: Map<string, Uint8Array>, name: string, length: number): Uint8Array | undefined =>
  fields.has(name) ? bytes(fields, name, length) : undefined;
const oneOf = <T extends string>(value: string, choices: readonly T[]): T => {
  if (!choices.includes(value as T)) throw new WireError("invalid_record");
  return value as T;
};

export function decodeSupervisorStatus(payload: Uint8Array): SupervisorStatus {
  const fields = readRecord(payload);
  return {
    supervisor_instance_id: bytes(fields, "supervisor_instance_id", 16),
    catalog_revision: uint(fields, "catalog_revision", 64), sandbox_count: uint(fields, "sandbox_count", 64),
    running_count: uint(fields, "running_count", 64), reconciled: readBool(required(fields, "reconciled")),
  };
}

export function decodeSupervisorCapabilities(payload: Uint8Array): SupervisorCapabilities {
  const fields = readRecord(payload);
  return {
    lifecycle_operations: readBool(required(fields, "lifecycle_operations")),
    watches: readBool(required(fields, "watches")), sandbox_modify: readBool(required(fields, "sandbox_modify")),
    jailer: readBool(required(fields, "jailer")),
  };
}

export function decodeSandboxRecord(payload: Uint8Array): SandboxRecord {
  const fields = readRecord(payload);
  return {
    lineage_id: bytes(fields, "lineage_id", 16), name: text(fields, "name"),
    desired_state: oneOf(text(fields, "desired_state"), ["stopped", "running", "removed"] as const),
    observed_state: oneOf(text(fields, "observed_state"), ["absent", "creating", "starting", "running", "stopping", "stopped", "failed", "removing"] as const),
    ...(fields.has("runtime_boot_id") ? { runtime_boot_id: optionalBytes(fields, "runtime_boot_id", 16) } : {}),
    catalog_revision: uint(fields, "catalog_revision", 64),
  };
}

export function decodeOperationRecord(payload: Uint8Array): OperationRecord {
  const fields = readRecord(payload);
  return {
    operation_id: bytes(fields, "operation_id", 16),
    supervisor_request_id: bytes(fields, "supervisor_request_id", 16),
    state: oneOf(text(fields, "state"), ["pending", "running", "succeeded", "failed", "cancelled"] as const),
    ...(fields.has("sandbox") ? { sandbox: optionalBytes(fields, "sandbox", 16) } : {}),
    ...(fields.has("error") ? { error: decodeSupervisorError(required(fields, "error")) } : {}),
    catalog_revision: uint(fields, "catalog_revision", 64),
  };
}

export function decodeRequestRecord(payload: Uint8Array): RequestRecord {
  const fields = readRecord(payload);
  return {
    supervisor_request_id: bytes(fields, "supervisor_request_id", 16),
    intent_fingerprint: readBytes(required(fields, "intent_fingerprint")),
    operation: decodeOperationRecord(required(fields, "operation")),
  };
}

export function decodeOperationAccepted(payload: Uint8Array): OperationAccepted {
  const fields = readRecord(payload);
  return {
    operation_id: bytes(fields, "operation_id", 16),
    supervisor_request_id: bytes(fields, "supervisor_request_id", 16),
    catalog_revision: uint(fields, "catalog_revision", 64), replayed: readBool(required(fields, "replayed")),
  };
}

export function decodeSandboxList(payload: Uint8Array): SandboxList {
  const fields = readRecord(payload);
  return {
    catalog_revision: uint(fields, "catalog_revision", 64),
    sandboxes: readArray(required(fields, "sandboxes")).map(decodeSandboxRecord),
    ...(fields.has("next_cursor") ? { next_cursor: readBytes(required(fields, "next_cursor")) } : {}),
  };
}

export function decodeCatalogEventPayload(payload: Uint8Array): CatalogEvent {
  const fields = readRecord(payload);
  return {
    catalog_revision: uint(fields, "catalog_revision", 64),
    ...(fields.has("sandbox") ? { sandbox: decodeSandboxRecord(required(fields, "sandbox")) } : {}),
    ...(fields.has("operation") ? { operation: decodeOperationRecord(required(fields, "operation")) } : {}),
  };
}

export function decodeWatchEndPayload(payload: Uint8Array): WatchEnd {
  const fields = readRecord(payload);
  return { reason: text(fields, "reason"), last_catalog_revision: uint(fields, "last_catalog_revision", 64) };
}

if (MAX_SUPERVISOR_FRAME_SIZE > MAX_FRAME_SIZE) throw new Error("supervisor frame ceiling exceeds shared framing ceiling");
