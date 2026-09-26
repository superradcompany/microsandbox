import {
  encodedMessage, encodeRecord, readRecord, WireError, type EncodedMessage, type InboundFrame, type Request,
} from "@microsandbox/protocol-client";
import { SupervisorClientError } from "./error.js";
import {
  decodeCatalogEventPayload, decodeOperationAccepted, decodeOperationRecord,
  decodeRequestRecord, decodeSandboxList, decodeSandboxRecord, decodeSupervisorCapabilities,
  decodeSupervisorError, decodeSupervisorStatus, decodeWatchEndPayload,
  type CatalogEvent, type CreateSandboxIntent, type GetRequest,
  type InspectSandbox, type ListSandboxes, type ModifySandboxIntent, type Mutation,
  type OperationAccepted, type OperationRecord, type OperationSelector, type RequestRecord,
  type SandboxActionIntent, type SandboxList, type SandboxRecord, type SupervisorCapabilities,
  type SupervisorStatus, type WatchCatalog, type WatchEnd,
} from "./records.js";

function checked<T>(frame: InboundFrame, name: string, decode: (payload: Uint8Array) => T, terminal = true): T {
  const invalid = () => new SupervisorClientError("invalid_response", frame);
  if (frame.protocolVersion !== 1 || frame.id === 0) throw invalid();
  if (frame.type === "supervisor.error") {
    if (!frame.isTerminal() || frame.flags !== 1) throw invalid();
    try { throw new SupervisorClientError("peer", frame, decodeSupervisorError(frame.payload)); }
    catch (error) { if (error instanceof SupervisorClientError) throw error; throw invalid(); }
  }
  if (frame.type !== name || frame.isTerminal() !== terminal || frame.flags !== (terminal ? 1 : 0)) throw invalid();
  try { readRecord(frame.payload); return decode(frame.payload); } catch { throw invalid(); }
}

abstract class Unary<T> implements Request<T> {
  readonly #payload: Uint8Array;
  constructor(
    readonly requestName: string, readonly responseName: string, payload: object,
    readonly decodePayload: (payload: Uint8Array) => T,
  ) { this.#payload = encodeRecord(payload); }
  message(): EncodedMessage { return encodedMessage(this.requestName, Uint8Array.from(this.#payload)); }
  decode(frame: InboundFrame): T { return checked(frame, this.responseName, this.decodePayload); }
}

function mutation<T>(value: Mutation<T>): Mutation<T> {
  const id = value.supervisor_request_id;
  if (id.length !== 16 || id[6]! >> 4 !== 7 || id[8]! >> 6 !== 2) throw new WireError("invalid_record");
  return value;
}

export class GetSupervisorStatus extends Unary<SupervisorStatus> {
  constructor() { super("supervisor.status", "supervisor.status.result", {}, decodeSupervisorStatus); }
}
export class GetSupervisorCapabilities extends Unary<SupervisorCapabilities> {
  constructor() { super("supervisor.capabilities", "supervisor.capabilities.result", {}, decodeSupervisorCapabilities); }
}
export class LookupRequest extends Unary<RequestRecord> {
  constructor(value: GetRequest) { super("request.get", "request.get.result", value, decodeRequestRecord); }
}
export class GetSandbox extends Unary<SandboxRecord> {
  constructor(value: InspectSandbox) { super("sandbox.inspect", "sandbox.inspect.result", value, decodeSandboxRecord); }
}
export class GetSandboxes extends Unary<SandboxList> {
  constructor(value: ListSandboxes) { super("sandbox.list", "sandbox.list.result", value, decodeSandboxList); }
}
export class CreateSandbox extends Unary<OperationAccepted> {
  constructor(value: Mutation<CreateSandboxIntent>) { super("sandbox.create", "operation.accepted", mutation(value), decodeOperationAccepted); }
}
export class StartSandbox extends Unary<OperationAccepted> {
  constructor(value: Mutation<SandboxActionIntent>) { super("sandbox.start", "operation.accepted", mutation(value), decodeOperationAccepted); }
}
export class StopSandbox extends Unary<OperationAccepted> {
  constructor(value: Mutation<SandboxActionIntent>) { super("sandbox.stop", "operation.accepted", mutation(value), decodeOperationAccepted); }
}
export class KillSandbox extends Unary<OperationAccepted> {
  constructor(value: Mutation<SandboxActionIntent>) { super("sandbox.kill", "operation.accepted", mutation(value), decodeOperationAccepted); }
}
export class RestartSandbox extends Unary<OperationAccepted> {
  constructor(value: Mutation<SandboxActionIntent>) { super("sandbox.restart", "operation.accepted", mutation(value), decodeOperationAccepted); }
}
export class RemoveSandbox extends Unary<OperationAccepted> {
  constructor(value: Mutation<SandboxActionIntent>) { super("sandbox.remove", "operation.accepted", mutation(value), decodeOperationAccepted); }
}
export class ModifySandbox extends Unary<OperationAccepted> {
  constructor(value: Mutation<ModifySandboxIntent>) { super("sandbox.modify", "operation.accepted", mutation(value), decodeOperationAccepted); }
}
export class GetOperation extends Unary<OperationRecord> {
  constructor(value: OperationSelector) { super("operation.get", "operation.get.result", value, decodeOperationRecord); }
}
export class CancelOperation extends Unary<OperationRecord> {
  constructor(value: Mutation<OperationSelector>) { super("operation.cancel", "operation.action.result", mutation(value), decodeOperationRecord); }
}
export class RetryOperation extends Unary<OperationRecord> {
  constructor(value: Mutation<OperationSelector>) { super("operation.retry", "operation.action.result", mutation(value), decodeOperationRecord); }
}

export class WatchSupervisor {
  constructor(readonly value: WatchCatalog) {}
  message(): EncodedMessage { return encodedMessage("supervisor.watch", encodeRecord(this.value)); }
}
export class WatchOperation {
  constructor(readonly value: OperationSelector) {}
  message(): EncodedMessage { return encodedMessage("operation.watch", encodeRecord(this.value)); }
}
export function decodeCatalogEvent(frame: InboundFrame): CatalogEvent { return checked(frame, "supervisor.event", decodeCatalogEventPayload, false); }
export function decodeOperationEvent(frame: InboundFrame): OperationRecord { return checked(frame, "operation.event", decodeOperationRecord, false); }
export function decodeCatalogWatchEnd(frame: InboundFrame): WatchEnd {
  return checked(frame, "supervisor.watch.end", decodeWatchEndPayload);
}
export function decodeOperationWatchEnd(frame: InboundFrame): WatchEnd {
  return checked(frame, "operation.watch.end", decodeWatchEndPayload);
}
