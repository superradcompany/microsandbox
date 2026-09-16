import { Decoder, Encoder } from "cbor-x";

/** Outer limit includes the ID and flags, excluding the length prefix. */
export const MAX_FRAME_SIZE = 4 * 1024 * 1024;
/** Bytes between the length prefix and envelope. */
export const FRAME_HEADER_SIZE = 5;
/** A terminal frame completes one routed exchange. */
export const FLAG_TERMINAL = 1;

/** Frame routing data with an opaque envelope body. */
export type RawFrame = { id: number; flags: number; body: Uint8Array };
/** Open message namespace, independent of an agent/control enum. */
export type Envelope = { v: number; t: string; p: Uint8Array };

/** Sanitized protocol error: never includes arbitrary CBOR values. */
export class WireError extends Error {
  constructor(readonly code: "invalid_cbor" | "invalid_record" | "duplicate_key" | "too_large" | "encode") {
    super(`protocol data: ${code}`);
    this.name = "WireError";
  }
}

const decoder = new Decoder({ useRecords: false, mapsAsObjects: false });
const encoder = new Encoder({ useRecords: false, variableMapSize: true, tagUint8Array: false, mapsAsObjects: false });
const utf8 = new TextDecoder("utf-8", { fatal: true });
type Header = { major: number; argument: bigint | null; end: number };

// The library decoder is intentionally permissive about duplicate keys and
// integer representations. Scan framing before decoding checked records so a
// duplicate or float-valued integer cannot be silently normalized away.
function header(bytes: Uint8Array, offset: number): Header {
  const first = bytes[offset];
  if (first === undefined) throw new WireError("invalid_cbor");
  const major = first >> 5;
  const info = first & 31;
  if (info < 24) return { major, argument: BigInt(info), end: offset + 1 };
  if (info === 31 && major >= 2 && major <= 5) return { major, argument: null, end: offset + 1 };
  if (info > 27) throw new WireError("invalid_cbor");
  const size = 1 << (info - 24);
  if (offset + 1 + size > bytes.length) throw new WireError("invalid_cbor");
  let argument = 0n;
  for (let i = offset + 1; i <= offset + size; i++) argument = (argument << 8n) | BigInt(bytes[i]!);
  return { major, argument, end: offset + 1 + size };
}

function itemEnd(bytes: Uint8Array, offset: number, depth = 0): number {
  if (depth > 128) throw new WireError("invalid_cbor");
  const h = header(bytes, offset);
  if (h.major <= 1 || h.major === 7) return h.end;
  if (h.major === 6) return itemEnd(bytes, h.end, depth + 1);
  let at = h.end;
  if (h.major === 2 || h.major === 3) {
    if (h.argument !== null) {
      if (h.argument > BigInt(bytes.length - at)) throw new WireError("invalid_cbor");
      const end = at + Number(h.argument);
      if (h.major === 3) {
        try { utf8.decode(bytes.subarray(at, end)); }
        catch { throw new WireError("invalid_cbor"); }
      }
      return end;
    }
    while (bytes[at] !== 0xff) {
      const chunk = header(bytes, at);
      if (chunk.major !== h.major || chunk.argument === null) throw new WireError("invalid_cbor");
      at = itemEnd(bytes, at, depth + 1);
    }
    return at + 1;
  }
  const pair = h.major === 5 ? 2 : 1;
  if (h.argument !== null) {
    const count = h.argument * BigInt(pair);
    // Every item occupies at least one byte. Check before converting or looping.
    if (count > BigInt(bytes.length - at)) throw new WireError("invalid_cbor");
    for (let i = 0; i < Number(count); i++) at = itemEnd(bytes, at, depth + 1);
  } else {
    while (bytes[at] !== 0xff) {
      for (let i = 0; i < pair; i++) at = itemEnd(bytes, at, depth + 1);
    }
    at++;
  }
  return at;
}

function checkedValue(bytes: Uint8Array): unknown {
  if (bytes.length > MAX_FRAME_SIZE) throw new WireError("too_large");
  if (itemEnd(bytes, 0) !== bytes.length) throw new WireError("invalid_cbor");
  try { return decoder.decode(bytes); }
  catch { throw new WireError("invalid_cbor"); }
}

/** Record fields remain exact encoded slices, including unknown fields. */
export function readRecord(bytes: Uint8Array): Map<string, Uint8Array> {
  if (bytes.length > MAX_FRAME_SIZE) throw new WireError("too_large");
  const h = header(bytes, 0);
  if (h.major !== 5) throw new WireError("invalid_record");
  if (itemEnd(bytes, 0) !== bytes.length) throw new WireError("invalid_cbor");
  const fields = new Map<string, Uint8Array>();
  let at = h.end;
  let left = h.argument;
  while (left === null ? bytes[at] !== 0xff : left > 0n) {
    const keyEnd = itemEnd(bytes, at);
    const key = readText(bytes.subarray(at, keyEnd));
    if (fields.has(key)) throw new WireError("duplicate_key");
    const end = itemEnd(bytes, keyEnd);
    fields.set(key, bytes.subarray(keyEnd, end));
    at = end;
    if (left !== null) left--;
  }
  return fields;
}

/** Require a field without exposing untrusted record contents. */
export function required(fields: Map<string, Uint8Array>, key: string): Uint8Array {
  const value = fields.get(key);
  if (!value) throw new WireError("invalid_record");
  return value;
}

/** Exact unsigned CBOR integer; floats and decimal strings are rejected. */
export function readUint(bytes: Uint8Array, bits: 8 | 32 | 64): bigint {
  const h = header(bytes, 0);
  if (h.major !== 0 || h.argument === null || h.end !== bytes.length || h.argument >= (1n << BigInt(bits))) {
    throw new WireError("invalid_record");
  }
  return h.argument;
}

/** Decode a CBOR text string, requiring its actual wire type. */
export function readText(bytes: Uint8Array): string {
  if (header(bytes, 0).major !== 3) throw new WireError("invalid_record");
  const value = checkedValue(bytes);
  if (typeof value !== "string") throw new WireError("invalid_record");
  return value;
}

/** Decode a byte string; integer arrays and tagged typed arrays are not equivalent. */
export function readBytes(bytes: Uint8Array): Uint8Array {
  if (header(bytes, 0).major !== 2) throw new WireError("invalid_record");
  const value = checkedValue(bytes);
  if (!(value instanceof Uint8Array)) throw new WireError("invalid_record");
  return Uint8Array.from(value);
}

/** Decode a CBOR boolean without truthiness coercions. */
export function readBool(bytes: Uint8Array): boolean {
  if (bytes.length !== 1 || (bytes[0] !== 0xf4 && bytes[0] !== 0xf5)) throw new WireError("invalid_record");
  return bytes[0] === 0xf5;
}

/** Encoded array entries for checking nested records without normalizing them. */
export function readArray(bytes: Uint8Array): Uint8Array[] {
  const h = header(bytes, 0);
  if (h.major !== 4) throw new WireError("invalid_record");
  if (bytes.length > MAX_FRAME_SIZE) throw new WireError("too_large");
  if (itemEnd(bytes, 0) !== bytes.length) throw new WireError("invalid_cbor");
  const values: Uint8Array[] = [];
  let at = h.end;
  let left = h.argument;
  while (left === null ? bytes[at] !== 0xff : left > 0n) {
    const end = itemEnd(bytes, at);
    values.push(bytes.subarray(at, end));
    at = end;
    if (left !== null) left--;
  }
  return values;
}

/** Decode an open envelope without parsing its application payload. */
export function decodeEnvelope(bytes: Uint8Array): Envelope {
  const fields = readRecord(bytes);
  return {
    v: Number(readUint(required(fields, "v"), 8)),
    t: readText(required(fields, "t")),
    p: readBytes(required(fields, "p")),
  };
}

/** Encode new control records using the same shortest integers as Rust. */
export function encodeRecord(value: unknown): Uint8Array {
  function normalize(value: unknown, depth: number, ancestors: Set<object>): unknown {
    if (depth > 128) throw new WireError("encode");
    if (typeof value === "bigint") {
      if (value < -0x10000000000000000n || value > 0xffffffffffffffffn) throw new WireError("encode");
      return value >= -0x100000000n && value <= 0xffffffffn ? Number(value) : value;
    }
    if (typeof value === "number" && Number.isInteger(value)) {
      if (!Number.isSafeInteger(value)) throw new WireError("encode");
      return value >= -0x100000000 && value <= 0xffffffff ? value : BigInt(value);
    }
    if (value === null || typeof value !== "object" || value instanceof Uint8Array) return value;
    if (ancestors.has(value)) throw new WireError("encode");
    ancestors.add(value);
    let result: unknown;
    if (Array.isArray(value)) result = value.map(item => normalize(item, depth + 1, ancestors));
    else if (value instanceof Map) result = new Map([...value].map(([k, v]) => [k, normalize(v, depth + 1, ancestors)]));
    else result = Object.fromEntries(Object.entries(value).map(([k, v]) => [k, normalize(v, depth + 1, ancestors)]));
    ancestors.delete(value);
    return result;
  }
  try {
    // Buffer.slice() aliases the encoder's reusable storage in Node. Always
    // copy into a plain Uint8Array, including when running outside Node.
    const result = Uint8Array.from(encoder.encode(normalize(value, 0, new Set())));
    if (result.length > MAX_FRAME_SIZE) throw new WireError("too_large");
    return result;
  } catch (error) {
    if (error instanceof WireError) throw error;
    throw new WireError("encode");
  }
}

/** Encode an envelope while leaving supplied payload bytes untouched. */
export function encodeEnvelope(envelope: Envelope): Uint8Array {
  if (!Number.isInteger(envelope.v) || envelope.v < 0 || envelope.v > 255 || typeof envelope.t !== "string" || !(envelope.p instanceof Uint8Array)) {
    throw new WireError("invalid_record");
  }
  return encodeRecord({ v: envelope.v, t: envelope.t, p: envelope.p });
}

/** Encode a raw frame without inspecting or re-encoding its envelope. */
export function encodeFrame(frame: RawFrame): Uint8Array {
  if (!Number.isInteger(frame.id) || frame.id < 0 || frame.id > 0xffffffff || !Number.isInteger(frame.flags) || frame.flags < 0 || frame.flags > 255) {
    throw new WireError("invalid_record");
  }
  if (frame.body.length + FRAME_HEADER_SIZE > MAX_FRAME_SIZE) throw new WireError("too_large");
  const bytes = new Uint8Array(frame.body.length + 9);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, frame.body.length + FRAME_HEADER_SIZE);
  view.setUint32(4, frame.id);
  bytes[8] = frame.flags;
  bytes.set(frame.body, 9);
  return bytes;
}

/** Decode exactly one framed packet; transport readers handle fragmentation. */
export function decodeFrame(bytes: Uint8Array): RawFrame {
  if (bytes.length < 9) throw new WireError("invalid_record");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const length = view.getUint32(0);
  if (length > MAX_FRAME_SIZE) throw new WireError("too_large");
  if (length < FRAME_HEADER_SIZE || length + 4 !== bytes.length) throw new WireError("invalid_record");
  return { id: view.getUint32(4), flags: bytes[8]!, body: bytes.subarray(9) };
}
