import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  CborEnvelopeCodec, decodeEnvelope, decodeFrame, encodeEnvelope, encodeFrame, encodeRecord,
  type ByteTransport,
} from "@microsandbox/protocol-client";
import {
  CreateSandbox, SupervisorClient, SupervisorClientError, decodeCatalogEvent, decodeOperationAccepted, decodeWelcome,
  type SupervisorClientConfig, type SupervisorHello,
} from "../src/index.js";

const fixtures = JSON.parse(readFileSync(new URL("../../../protocol-fixtures/supervisor-v1.json", import.meta.url), "utf8")) as {
  preamble_hex: string;
  cases: Array<{ name: string; type: string; id: number; flags: number; generation: number; frame_hex: string }>;
};
const byName = (name: string) => fixtures.cases.find(value => value.name === name)!;
const raw = (name: string) => decodeFrame(Buffer.from(byName(name).frame_hex, "hex"));
const frame = (name: string) => new CborEnvelopeCodec().decode(raw(name));

const requestId = Uint8Array.from([0x01, 0x89, 0xab, 0xcd, 0xef, 0x70, 0x70, 0x01, 0x80, 2, 3, 4, 5, 6, 7, 8]);
const hello: SupervisorHello = {
  protocol: "msb.supervisor", min_generation: 1, max_generation: 1,
  implementation_version: "0.7.4", client_instance_id: new Uint8Array(16).fill(0x11),
  canonical_home_digest: new Uint8Array(32).fill(0x44),
  requested_limits: { max_frame_size: 256 * 1024, max_in_flight: 32, max_watches: 8 },
  resume_catalog_revision: 41n,
};

describe("generation-one Rust and TypeScript wire agreement", () => {
  it("pins MSBS plus the exact hello frame", () => {
    expect(fixtures.preamble_hex).toBe("4d534253");
    const encoded = encodeFrame({ id: 0, flags: 0, body: encodeEnvelope({
      v: 1, t: "supervisor.hello", p: encodeRecord(hello),
    }) });
    expect(Buffer.from(encoded).toString("hex")).toBe(byName("hello").frame_hex);
  });

  it("decodes the pinned welcome, accepted mutation, and watch event", () => {
    expect(decodeWelcome(frame("welcome").payload, hello)).toMatchObject({
      generation: 1, current_catalog_revision: 42n, oldest_catalog_revision: 7n,
      launch_profile: "jailed_linux_v1",
    });
    expect(decodeOperationAccepted(frame("operation_accepted").payload)).toMatchObject({
      catalog_revision: 43n, replayed: false,
    });
    expect(decodeCatalogEvent(frame("catalog_event"))).toMatchObject({
      catalog_revision: 44n, sandbox: { name: "demo", desired_state: "running", observed_state: "starting" },
    });
    const codec = new CborEnvelopeCodec();
    const error = codec.decode({ id: 19, flags: 1, body: encodeEnvelope({
      v: 1, t: "supervisor.error", p: encodeRecord({
        code: "catalog_compacted", message: "resume later", retry_class: "after_correction",
      }),
    }) });
    expect(() => decodeCatalogEvent(error)).toThrow(SupervisorClientError);
  });

  it("pins a portable create intent without JSON conversion", () => {
    const request = new CreateSandbox({
      supervisor_request_id: requestId, expected_catalog_revision: 42n,
      intent: { name: "demo", spec: { schema_generation: 1, cbor: Uint8Array.of(0xa0) }, isolation_profile: "linux-v1" },
    });
    const message = request.message();
    const encoded = encodeFrame({ id: 17, flags: 0, body: encodeEnvelope({ v: 1, t: message.type, p: message.payload }) });
    expect(Buffer.from(encoded).toString("hex")).toBe(byName("sandbox_create").frame_hex);
    expect(() => new CreateSandbox({
      supervisor_request_id: new Uint8Array(16),
      intent: { name: "invalid", spec: { schema_generation: 1, cbor: Uint8Array.of(0xa0) }, isolation_profile: "linux-v1" },
    })).toThrow();
  });
});

it("performs MSBS setup with caller identity and canonical-home binding", async () => {
  const welcome = raw("welcome");
  const bytes = encodeFrame(welcome);
  let offset = 0;
  const writes: Uint8Array[] = [];
  const transport: ByteTransport = {
    async read(maxBytes) {
      if (offset === bytes.length) return null;
      const chunk = bytes.subarray(offset, Math.min(bytes.length, offset + maxBytes));
      offset += chunk.length;
      return chunk;
    },
    async write(value) { writes.push(Uint8Array.from(value)); },
    async close() {},
  };
  const config: SupervisorClientConfig = {
    implementationVersion: "0.7.4", clientInstanceId: hello.client_instance_id,
    canonicalHomeDigest: hello.canonical_home_digest, resumeCatalogRevision: 41n,
  };
  const client = await SupervisorClient.connectTransport(transport, config);
  expect(Buffer.from(writes[0]!).toString("hex")).toBe(fixtures.preamble_hex);
  expect(Buffer.from(writes[1]!).toString("hex")).toBe(byName("hello").frame_hex);
  expect(client.ready.welcome.supervisor_instance_id).toEqual(new Uint8Array(16).fill(0x55));
  await client.close();
});
