import { Decoder } from "cbor-x";
import { ClientError } from "./error.js";
import { decodeEnvelope, encodeEnvelope, encodeRecord, FLAG_TERMINAL, type RawFrame } from "./wire.js";

/** Explicit native payload; pairing a name and object is not schema validation. */
export type TypedMessage<T = unknown> = { kind: "typed"; type: string; payload: T };
/** Encoded application payload, separate from the outer envelope and frame. */
export type EncodedMessage = { kind: "encoded"; type: string; payload: Uint8Array };
/** Both named paths retain protocol gates; raw APIs bypass envelope semantics. */
export type OutboundMessage = TypedMessage | EncodedMessage;

export function typedMessage<T>(type: string, payload: T): TypedMessage<T> { return { kind: "typed", type, payload }; }
export function encodedMessage(type: string, payload: Uint8Array): EncodedMessage { return { kind: "encoded", type, payload }; }

const decoder = new Decoder({ useRecords: false, mapsAsObjects: true });

/** Inspectable message retaining the actual original frame and unknown envelope fields. */
export class InboundFrame {
  constructor(
    readonly id: number, readonly flags: number, readonly protocolVersion: number,
    readonly type: string, readonly payload: Uint8Array, readonly raw: RawFrame,
  ) {}
  isTerminal(): boolean { return (this.flags & FLAG_TERMINAL) !== 0; }
  decodePayload<T = unknown>(): T {
    try { return decoder.decode(this.payload) as T; }
    catch { throw new ClientError("invalid_data", "unknown"); }
  }
}

/** Chosen during setup; raw subscriptions never invoke it. */
export interface EnvelopeCodec {
  /** Serialize native values; permits preserving an existing agent encoder. */
  encodePayload(value: unknown): Uint8Array;
  encode(generation: number, wireName: string, payload: Uint8Array): Uint8Array;
  decode(frame: RawFrame): InboundFrame;
}

/** New records use shortest integers; supplied encoded payloads stay untouched. */
export class CborEnvelopeCodec implements EnvelopeCodec {
  encodePayload(value: unknown): Uint8Array { return encodeRecord(value); }
  encode(generation: number, wireName: string, payload: Uint8Array): Uint8Array {
    return encodeEnvelope({ v: generation, t: wireName, p: payload });
  }
  decode(frame: RawFrame): InboundFrame {
    const envelope = decodeEnvelope(frame.body);
    return new InboundFrame(frame.id, frame.flags, envelope.v, envelope.t, envelope.p, frame);
  }
}
