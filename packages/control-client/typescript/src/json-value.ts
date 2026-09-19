import { ClientError } from "@microsandbox/protocol-client";

/** Original JSON number token. Unknown fields need not fit any JavaScript number. */
export class JsonNumber {
  readonly #token: string;
  constructor(token: string) {
    if (!/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/.test(token)) throw invalid();
    this.#token = token;
  }
  get token(): string { return this.#token; }
  /** Integer wire fields reject negative zero, fractions, exponents, and overflow. */
  asUint(bits: 32 | 64): bigint {
    if (!/^(?:0|[1-9]\d*)$/.test(this.#token) || this.#token.length > 20) throw invalid();
    const value = BigInt(this.#token);
    if (value >= (1n << BigInt(bits))) throw invalid();
    return value;
  }
  [Symbol.for("nodejs.util.inspect.custom")](): string { return "JsonNumber { … }"; }
}

export type JsonObject = ReadonlyMap<string, JsonValue>;
export type JsonValue = null | boolean | string | JsonNumber | readonly JsonValue[] | JsonObject;

/**
 * Parse number tokens before any Number conversion. Objects are maps so unknown
 * keys, including "__proto__", cannot alter prototypes or erase duplicates.
 */
export function parseJson(bytes: Uint8Array): JsonValue {
  let source: string;
  try {
    source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes)
      .replace(/^\p{White_Space}+|\p{White_Space}+$/gu, "");
  } catch { throw invalid(); }
  let offset = 0;
  const space = () => { while (offset < source.length && /[ \t\r\n]/.test(source[offset]!)) offset++; };
  const string = (): string => {
    if (source[offset] !== '"') throw invalid();
    const start = offset++;
    for (;;) {
      if (offset >= source.length) throw invalid();
      const char = source[offset++];
      if (char === "\\") { offset++; continue; }
      if (char !== '"') continue;
      let value: string;
      // JSON.parse is used only for a string token, never for numeric data or
      // objects. Its escape validation cannot collapse duplicate object keys.
      try { value = JSON.parse(source.slice(start, offset)) as string; } catch { throw invalid(); }
      for (let index = 0; index < value.length; index++) {
        const unit = value.charCodeAt(index);
        if (unit >= 0xd800 && unit <= 0xdbff) {
          const low = value.charCodeAt(++index);
          if (!(low >= 0xdc00 && low <= 0xdfff)) throw invalid();
        } else if (unit >= 0xdc00 && unit <= 0xdfff) throw invalid();
      }
      return value;
    }
  };
  const value = (depth: number): JsonValue => {
    if (depth > 128) throw invalid();
    space();
    const char = source[offset];
    if (char === '"') return string();
    if (char === "{" || char === "[") {
      offset++; space();
      const object = char === "{", end = object ? "}" : "]";
      const fields = new Map<string, JsonValue>(), values: JsonValue[] = [];
      if (source[offset] === end) { offset++; return object ? fields : values; }
      for (;;) {
        if (object) {
          space(); const key = string(); space();
          if (source[offset++] !== ":" || fields.has(key)) throw invalid();
          fields.set(key, value(depth + 1));
        } else values.push(value(depth + 1));
        space();
        const next = source[offset++];
        if (next === end) return object ? fields : values;
        if (next !== ",") throw invalid();
      }
    }
    for (const [token, result] of [["true", true], ["false", false], ["null", null]] as const) {
      if (source.startsWith(token, offset)) { offset += token.length; return result; }
    }
    const number = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(source.slice(offset))?.[0];
    if (!number) throw invalid();
    offset += number.length;
    return new JsonNumber(number);
  };
  const parsed = value(0);
  space();
  if (offset !== source.length) throw invalid();
  return parsed;
}

export function jsonObject(value: JsonValue | undefined): JsonObject {
  if (!(value instanceof Map)) throw invalid();
  return value;
}
export function jsonUint(value: JsonValue | undefined, bits: 32 | 64): bigint {
  if (!(value instanceof JsonNumber)) throw invalid();
  return value.asUint(bits);
}
function invalid(): ClientError { return new ClientError("invalid_data"); }
