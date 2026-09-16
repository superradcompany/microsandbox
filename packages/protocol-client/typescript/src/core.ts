import { ClientError, clientError, type Delivery } from "./error.js";
import type { OutboundMessage } from "./message.js";
import type { Established, Protocol, ReadyOf } from "./protocol.js";
import { Budget, FrameQueue } from "./queue.js";
import { checkSignal, wait } from "./timing.js";
import { readRawFrame } from "./transport.js";
import { encodeFrame, FLAG_TERMINAL, type RawFrame } from "./wire.js";

export type Lease = { id: number; active: boolean; admitted: boolean; terminal: boolean; draining: boolean; queue: FrameQueue };
type Write = { packet: Uint8Array; release(): void; resolve(): void; reject(error: ClientError): void };
const owners = new FinalizationRegistry<{ core: Core<Protocol>; receiver?: Lease }>(({ core, receiver }) => {
  // A collected receiver relinquishes delivery and send permission even when
  // another client/sender still owns the connection. Keep its ID draining.
  if (receiver) core.abandon(receiver);
  core.releaseOwner();
});

/** Router internals hold no client or stream objects, permitting best-effort finalization. */
export class Core<P extends Protocol> {
  readonly pending = new Map<number, Lease>();
  private nextId: number;
  private readonly bytes: Budget;
  private readonly slots: Budget;
  private readonly writes: Write[] = [];
  private writing?: Promise<void>;
  private reader?: Promise<void>;
  private closing?: Promise<void>;
  private ownerCount = 0;
  failure?: ClientError;

  constructor(readonly protocol: P, readonly established: Established<ReadyOf<P>>) {
    this.nextId = established.ids.start;
    this.bytes = new Budget(established.limits.bufferedBytes, established.limits.maxInFlight + 1);
    this.slots = new Budget(established.limits.queuedWrites, established.limits.maxInFlight);
  }

  start(): void { this.reader = this.readLoop(); }

  retain(target: object, receiver?: Lease): () => void {
    this.ownerCount++;
    const token = {};
    owners.register(target, { core: this as Core<Protocol>, receiver }, token);
    let released = false;
    return () => { if (!released) { released = true; owners.unregister(token); this.releaseOwner(); } };
  }

  releaseOwner(): void {
    if (--this.ownerCount === 0) this.fail(new ClientError("closed"));
  }

  async close(): Promise<void> {
    this.fail(new ClientError("closed"));
    await this.closing;
    await Promise.allSettled([this.reader, this.writing]);
  }

  prepare(message: OutboundMessage): { flags: number; body: Uint8Array } {
    if (this.failure) throw this.failure;
    const metadata = this.protocol.prepare(this.established.ready, message.type);
    try {
      const payload = message.kind === "encoded" ? message.payload : this.established.codec.encodePayload(message.payload);
      return { flags: metadata.flags, body: this.established.codec.encode(metadata.generation, message.type, payload) };
    } catch { throw new ClientError("encode"); }
  }

  reserve(): Lease {
    if (this.failure) throw this.failure;
    if (this.pending.size >= this.established.limits.maxInFlight) throw new ClientError("capacity");
    for (let attempt = 0; attempt <= this.pending.size; attempt++) {
      if (this.nextId >= this.established.ids.endExclusive) throw new ClientError("ids_exhausted");
      const id = this.nextId++;
      if (this.protocol.reuseIds !== false && this.nextId === this.established.ids.endExclusive) this.nextId = this.established.ids.start;
      if (this.pending.has(id)) continue;
      const lease: Lease = { id, active: true, admitted: false, terminal: false, draining: false, queue: new FrameQueue(this.established.limits.queuedResponses) };
      this.pending.set(id, lease);
      return lease;
    }
    throw new ClientError("ids_exhausted");
  }

  owned(id: number): Lease {
    if (this.failure) throw this.failure;
    const lease = this.pending.get(id);
    if (!lease?.active) throw new ClientError("stream_closed");
    return lease;
  }

  abandon(lease: Lease): void {
    lease.active = false;
    lease.draining = true;
    lease.queue.finish(undefined, true);
    if (!lease.admitted && this.pending.get(lease.id) === lease) this.pending.delete(lease.id);
  }

  closeStream(id: number): void { const lease = this.pending.get(id); if (lease) this.abandon(lease); }
  delivery(lease: Lease): Delivery { return lease.admitted ? "unknown" : "not_sent"; }

  async writeFrame(lease: Lease, flags: number, body: Uint8Array, signal?: AbortSignal): Promise<void> {
    if (body.length + 5 > this.established.limits.maxFrameSize) throw new ClientError("capacity");
    if (!Number.isInteger(flags) || flags < 0 || flags > 255) throw new ClientError("invalid_data");
    await this.write(body.length + 9, () => encodeFrame({ id: lease.id, flags, body }), lease, signal);
  }

  async writeExact(packet: Uint8Array, signal?: AbortSignal): Promise<void> {
    await this.write(packet.length, () => Uint8Array.from(packet), undefined, signal);
  }

  private async write(size: number, encode: () => Uint8Array, lease?: Lease, signal?: AbortSignal): Promise<void> {
    checkSignal(signal);
    if (this.failure) throw this.failure;
    const releaseBytes = await this.bytes.acquire(size, signal);
    let releaseSlot: (() => void) | undefined;
    let admitted = false;
    try {
      releaseSlot = await this.slots.acquire(1, signal);
      checkSignal(signal);
      if (this.failure) throw this.failure;
      if (lease && (this.pending.get(lease.id) !== lease || !lease.active)) throw new ClientError("stream_closed");
      const packet = encode();
      const release = () => { packet.fill(0); releaseBytes(); releaseSlot!(); };
      const written = new Promise<void>((resolve, reject) => {
        // This synchronous point is writer admission, before any external I/O.
        admitted = true;
        if (lease) lease.admitted = true;
        this.writes.push({ packet, release, resolve, reject });
      });
      this.kickWriter();
      await wait(written, signal);
    } catch (error) { throw clientError(error).withDelivery(admitted ? "unknown" : "not_sent"); }
    finally { if (!admitted) { releaseBytes(); releaseSlot?.(); } }
  }

  private kickWriter(): void {
    if (this.writing || this.failure) return;
    this.writing = (async () => {
      for (;;) {
        const command = this.writes.shift();
        if (!command) return;
        try { await this.established.transport.write(command.packet); command.resolve(); }
        catch (error) {
          const failure = clientError(error).withDelivery("unknown");
          command.reject(failure);
          this.fail(failure);
          return;
        } finally { command.release(); }
      }
    })().finally(() => { this.writing = undefined; if (this.writes.length) this.kickWriter(); });
  }

  private async readLoop(): Promise<void> {
    try {
      while (!this.failure) {
        const queued = await readRawFrame(this.established.transport, this.established.limits.maxFrameSize,
          this.established.limits.incompleteFrameTimeoutMs, (amount, signal) => this.bytes.acquire(amount, signal));
        if (!queued) throw new ClientError("peer_closed");
        const lease = this.pending.get(queued.frame.id);
        if (!lease) { queued.release(); continue; }
        const terminal = (queued.frame.flags & FLAG_TERMINAL) !== 0;
        if (terminal) lease.active = false;
        if (lease.draining) queued.release();
        else await lease.queue.push(queued);
        if (terminal) {
          lease.terminal = true;
          lease.queue.finish();
          if (this.pending.get(lease.id) === lease) this.pending.delete(lease.id);
        }
      }
    } catch (error) { this.fail(clientError(error)); }
  }

  private fail(error: ClientError): void {
    if (this.failure) return;
    this.failure = error.withDelivery("not_sent");
    this.bytes.close(this.failure);
    this.slots.close(this.failure);
    for (const lease of this.pending.values()) {
      lease.active = false;
      lease.queue.finish(error.withDelivery(this.delivery(lease)));
    }
    this.pending.clear();
    for (const command of this.writes.splice(0)) { command.reject(error.withDelivery("unknown")); command.release(); }
    this.closing = Promise.resolve().then(() => this.established.transport.close()).catch(() => undefined);
  }
}
