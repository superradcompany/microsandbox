import { decode, encode } from "cbor-x";
import {
  ClientError, InboundFrame, MAX_FRAME_SIZE, readExactly, readRawFrame, validateIds,
  type ByteTransport, type EnvelopeCodec, type EstablishContext, type Established,
  type Protocol, type RawFrame, type SendMetadata,
} from "@microsandbox/protocol-client";
import { PROTOCOL_VERSION, messageFlags, supports } from "./message.js";

/** Prologue-selected wire form, separate from operation-generation gates. */
export type AgentWireFormat = "current" | "legacy_v1";
/** Ready metadata keeps optional historical fields and full-width timestamps. */
export type ReadyPayload = {
  boot_time_ns?: number | bigint;
  init_time_ns?: number | bigint;
  ready_time_ns?: number | bigint;
  agent_version?: string;
  [field: string]: unknown;
};

/** Metadata captured once, retaining the original ready frame and unknown fields. */
export class AgentReady {
  readonly agent: ReadyPayload;
  readonly negotiatedVersion: number;
  constructor(readonly wireFormat: AgentWireFormat, readonly frame: InboundFrame) {
    this.agent = frame.decodePayload<ReadyPayload>();
    this.negotiatedVersion = Math.min(wireFormat === "legacy_v1" ? 1 : PROTOCOL_VERSION, frame.protocolVersion);
  }
  get agentVersion(): string { return typeof this.agent?.agent_version === "string" ? this.agent.agent_version : ""; }
  get readyBytes(): Uint8Array { return this.frame.raw.body; }
  supports(wireName: string): boolean { return supports(wireName, this.negotiatedVersion); }
}

/** Preserve the existing agent encoder, including its map and byte-tag choices. */
export class AgentEnvelopeCodec implements EnvelopeCodec {
  encodePayload(value: unknown): Uint8Array { return encode(value); }
  encode(generation: number, wireName: string, payload: Uint8Array): Uint8Array {
    // Copy the finished envelope before cbor-x reuses its output allocation.
    return Uint8Array.from(encode({ v: generation, t: wireName, p: payload }));
  }
  decode(frame: RawFrame): InboundFrame {
    try {
      const value = decode(frame.body) as { v?: unknown; t?: unknown; p?: unknown } | null;
      // Agent decoders historically accept cbor-x's tagged Uint8Array payloads.
      // The stricter control codec is independent and does not inherit that rule.
      if (!value || !Number.isInteger(value.v) || Number(value.v) < 0 || Number(value.v) > 255
          || typeof value.t !== "string" || !(value.p instanceof Uint8Array)) throw new Error();
      return new InboundFrame(frame.id, frame.flags, Number(value.v), value.t, value.p, frame);
    } catch { throw new ClientError("invalid_data", "unknown"); }
  }
}

/** Relay handshake and agent gates; correlation and transport ownership are generic. */
export class AgentProtocol implements Protocol<AgentReady> {
  readonly reuseIds = false;
  async establish(transport: ByteTransport, context: EstablishContext): Promise<Established<AgentReady>> {
    const prologue = await readExactly(transport, 8, context.signal);
    const view = new DataView(prologue.buffer, prologue.byteOffset, prologue.byteLength);
    const first = view.getUint32(0), second = view.getUint32(4);
    // This is the same disambiguation as the existing Rust legacy relay adapter.
    const legacy = second >= 5 && second <= MAX_FRAME_SIZE && (first === 0 || first >= second);
    const ids = legacy
      ? { start: Math.min(first + 1, 0xffffffff), endExclusive: Math.min(first + Math.floor(0xffffffff / 16), 0xffffffff) }
      : { start: Math.max(first, 1), endExclusive: second };
    validateIds(ids);
    let raw: RawFrame;
    if (legacy) {
      const header = await readExactly(transport, 5, context.signal);
      raw = {
        id: new DataView(header.buffer).getUint32(0), flags: header[4]!,
        body: await readExactly(transport, second - 5, context.signal),
      };
    } else {
      const queued = await readRawFrame(transport);
      if (!queued) throw new ClientError("peer_closed");
      raw = queued.frame;
    }
    const codec = new AgentEnvelopeCodec();
    const frame = codec.decode(raw);
    if (frame.type !== "core.ready") throw new ClientError("invalid_data");
    return { transport, codec, ids, ready: new AgentReady(legacy ? "legacy_v1" : "current", frame), limits: context.limits };
  }
  prepare(ready: AgentReady, wireName: string): SendMetadata {
    if (!ready.supports(wireName)) throw new ClientError("unsupported_operation");
    return { generation: ready.wireFormat === "legacy_v1" ? 1 : PROTOCOL_VERSION, flags: messageFlags(wireName) };
  }
}
