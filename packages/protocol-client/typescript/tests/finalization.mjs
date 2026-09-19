import assert from "node:assert/strict";
import { setTimeout as pause } from "node:timers/promises";
import { Client, CborEnvelopeCodec, defaultLimits, encodeFrame } from "../dist/index.js";

// A separate process makes GC available without changing consumer requirements.
// This tests the finalizer wiring; applications still use explicit close.
class Transport {
  chunks = [];
  wake;
  closed = false;
  async read(max) {
    while (!this.chunks.length && !this.closed) await new Promise(resolve => { this.wake = resolve; });
    const chunk = this.chunks.shift();
    if (!chunk) return null;
    if (chunk.length > max) this.chunks.unshift(chunk.subarray(max));
    return chunk.subarray(0, max);
  }
  async write() {}
  async close() { this.closed = true; this.wake?.(); }
  push(bytes) { this.chunks.push(bytes); this.wake?.(); }
}
const protocol = {
  establish() { throw new Error("not used"); },
  prepare() { return { generation: 1, flags: 0 }; },
};
const transport = new Transport();
const client = await Client.fromEstablished(protocol, {
  transport, codec: new CborEnvelopeCodec(), ready: 1,
  ids: { start: 1, endExclusive: 2 }, limits: defaultLimits(),
});
async function abandonReceiver() {
  const stream = await client.openStreamRaw(0, new Uint8Array());
  const { sender, receiver } = stream.split();
  return { sender, reference: new WeakRef(receiver) };
}
const { sender, reference } = await abandonReceiver();
let collected = false;
for (let i = 0; i < 100; i++) {
  await pause(5);
  globalThis.gc();
  await pause(5);
  if (!reference.deref()) { collected = true; break; }
}
assert.ok(collected, "receiver must not be retained by router ownership records");
await pause(10);
await assert.rejects(sender.send(0, new Uint8Array()), { code: "stream_closed", delivery: "not_sent" });
await assert.rejects(client.openStreamRaw(0, new Uint8Array()), { code: "ids_exhausted" });
assert.equal(client.isClosed(), false);
transport.push(encodeFrame({ id: 1, flags: 1, body: new Uint8Array() }));
await pause(10);
const next = await client.openStreamRaw(0, new Uint8Array());
assert.equal(next.id, 1);
await assert.rejects(sender.send(0, new Uint8Array()), { code: "stream_closed" });
next.close(); sender.close(); await client.close();

const orphan = new Transport();
async function abandonLastOwner() {
  const last = await Client.fromEstablished(protocol, {
    transport: orphan, codec: new CborEnvelopeCodec(), ready: 1,
    ids: { start: 1, endExclusive: 2 }, limits: defaultLimits(),
  });
  return new WeakRef(last);
}
const last = await abandonLastOwner();
for (let i = 0; i < 100 && !orphan.closed; i++) {
  await pause(5); globalThis.gc(); await pause(5);
}
assert.equal(last.deref(), undefined);
assert.equal(orphan.closed, true, "last-owner finalization must close the byte transport");
console.log("GC ownership: receiver draining, stale sender rejection, and last-owner close passed.");
