import { readFileSync } from "node:fs";
import { Decoder } from "cbor-x";
import { describe, expect, it } from "vitest";
import { decodeEnvelope, decodeFrame, encodeEnvelope, encodeFrame, encodeRecord, readRecord, readUint, required, WireError } from "../src/wire.js";

const decoder = new Decoder({ useRecords: false, mapsAsObjects: true });

it("owns encoded storage and emits untagged maps", () => {
  const saved = encodeRecord({ value: new Uint8Array(1000).fill(7) });
  const expected = Uint8Array.from(saved);
  // Force several rotations of cbor-x's internal reusable encoder storage.
  for (let i = 0; i < 200; i++) encodeRecord({ value: new Uint8Array(1000).fill(i) });
  expect(saved.constructor).toBe(Uint8Array);
  expect(saved).toEqual(expected);
  expect(readUint(required(readRecord(encodeRecord(new Map([["n", 7]]))), "n"), 32)).toBe(7n);
});
const fixtures = JSON.parse(readFileSync(new URL("../../../protocol-fixtures/control-v1.json", import.meta.url), "utf8")) as {
  cases: Array<{ name: string; frame_hex: string; envelope_hex: string; payload_hex: string; id: number; flags: number; generation: number; type: string }>;
};

describe("Rust/TypeScript control wire conformance", () => {
  for (const fixture of fixtures.cases) {
    it(fixture.name, () => {
      const packet = Buffer.from(fixture.frame_hex, "hex");
      const frame = decodeFrame(packet);
      const envelope = decodeEnvelope(frame.body);
      expect([frame.id, frame.flags, envelope.v, envelope.t]).toEqual([fixture.id, fixture.flags, fixture.generation, fixture.type]);
      expect(Buffer.from(envelope.p).toString("hex")).toBe(fixture.payload_hex);
      // Independently decode and re-encode native payloads, not just raw copies.
      const payload = decoder.decode(envelope.p);
      expect(Buffer.from(encodeRecord(payload)).toString("hex")).toBe(fixture.payload_hex);
      // Re-encode the complete native envelope so pinned extension fields
      // participate in interop instead of disappearing through the known view.
      expect(Buffer.from(encodeRecord(decoder.decode(frame.body))).toString("hex")).toBe(fixture.envelope_hex);
      if (readRecord(frame.body).size === 3) {
        expect(Buffer.from(encodeEnvelope(envelope)).toString("hex")).toBe(fixture.envelope_hex);
      }
      expect(encodeFrame(frame)).toEqual(new Uint8Array(packet));
    });
  }
});

it("retains all u64 bits and rejects floats, negatives, unsafe numbers and strings", () => {
  expect(readUint(encodeRecord(0xffffffffffffffffn), 64)).toBe(0xffffffffffffffffn);
  expect(readUint(encodeRecord(9007199254740993n), 64)).toBe(9007199254740993n);
  for (const hex of ["fb3ff0000000000000", "20", "6131", "f5"]) {
    expect(() => readUint(Buffer.from(hex, "hex"), 64)).toThrow(WireError);
  }
  expect(() => encodeRecord(9007199254740992)).toThrow(WireError);
  expect(() => readUint(encodeRecord(256), 8)).toThrow(WireError);
});

it("rejects duplicates, trailing data, invalid text and truncated/hostile lengths", () => {
  for (const hex of ["a2616100616101", "a10000", "a000", "a16161", "a161ff00", "bf616100616101ff", "bbffffffffffffffff"]) {
    expect(() => readRecord(Buffer.from(hex, "hex"))).toThrow(WireError);
  }
  const deep = Buffer.concat([Buffer.alloc(140, 0x81), Buffer.from([0])]);
  const body = Buffer.concat([Buffer.from("a16161", "hex"), deep]);
  expect(() => readRecord(body)).toThrow(WireError);
});

it("keeps unknown names/fields and opaque bytes but requires a byte-string payload", () => {
  const bytes = encodeRecord({ v: 1, t: "future.message", p: new Uint8Array([255, 0]), extra: "kept" });
  const decoded = decodeEnvelope(bytes);
  expect(decoded.t).toBe("future.message");
  expect(decoded.p).toEqual(new Uint8Array([255, 0]));
  expect(readRecord(bytes).has("extra")).toBe(true);
  expect(() => decodeEnvelope(encodeRecord({ v: 1, t: "future.message", p: [255, 0] }))).toThrow(WireError);
  expect(readUint(required(readRecord(encodeRecord({ total_mib: 2048n })), "total_mib"), 64)).toBe(2048n);
});
