import { Core, type Lease } from "./core.js";
import { ClientError, clientError } from "./error.js";
import type { InboundFrame, OutboundMessage } from "./message.js";
import type { Protocol, RequestOptions } from "./protocol.js";
import { Attempt } from "./timing.js";
import { FLAG_TERMINAL, type RawFrame } from "./wire.js";

// Native wrappers need codec access, but public stream handles must not expose
// the mutable router, ownership records, or another stream's permissions.
const codecs = new WeakMap<object, {
  prepare(message: OutboundMessage): { flags: number; body: Uint8Array };
  decode(frame: RawFrame): InboundFrame;
}>();
function rememberCodec<P extends Protocol>(owner: object, core: Core<P>): void {
  codecs.set(owner, {
    prepare: message => core.prepare(message),
    decode: frame => core.established.codec.decode(frame),
  });
}

/** Cloneable send permission bound to a lease object, not just its numeric ID. */
export class RawStreamSender<P extends Protocol> {
  private readonly release: () => void;
  private closed = false;
  constructor(private readonly core: Core<P>, private readonly lease: Lease) {
    this.release = core.retain(this);
    rememberCodec(this, core);
  }
  get id(): number { return this.lease.id; }
  clone(): RawStreamSender<P> { if (this.closed) throw new ClientError("stream_closed"); return new RawStreamSender(this.core, this.lease); }
  async send(flags: number, body: Uint8Array, options: RequestOptions = {}): Promise<void> {
    if (this.closed) throw new ClientError("stream_closed");
    const attempt = new Attempt(options.requestTimeoutMs, options.signal);
    try { await this.core.writeFrame(this.lease, flags, body, attempt.signal); }
    finally { attempt.close(); }
  }
  close(): void { if (!this.closed) { this.closed = true; this.release(); } }
}

/** One consuming receiver. Abandoning it retains draining IDs until terminal. */
export class RawStreamReceiver<P extends Protocol> implements AsyncIterable<RawFrame> {
  private readonly release: () => void;
  private done = false;
  private receiving = false;
  constructor(private readonly core: Core<P>, private readonly lease: Lease) {
    this.release = core.retain(this, lease);
    rememberCodec(this, core);
  }
  get id(): number { return this.lease.id; }
  async next(options: RequestOptions | number = {}): Promise<RawFrame | null> {
    if (this.done) return null;
    if (this.receiving) throw new ClientError("receiving");
    const settings = typeof options === "number" ? { requestTimeoutMs: options } : options;
    const attempt = new Attempt(settings.requestTimeoutMs, settings.signal);
    this.receiving = true;
    try {
      const frame = await this.lease.queue.next(attempt.signal);
      if (frame === null || (frame.flags & FLAG_TERMINAL) !== 0) { this.done = true; this.release(); }
      return frame;
    } catch (error) {
      const failure = clientError(error).withDelivery(this.core.delivery(this.lease));
      if (failure.code !== "timeout" && failure.code !== "cancelled") { this.done = true; this.release(); }
      throw failure;
    } finally { this.receiving = false; attempt.close(); }
  }
  close(): void { this.core.abandon(this.lease); this.done = true; this.release(); }
  async *[Symbol.asyncIterator](): AsyncIterator<RawFrame> {
    try { for (;;) { const frame = await this.next(); if (!frame) return; yield frame; } }
    finally { this.close(); }
  }
}

/** Opaque stream. Splitting consumes this object's authority to send or receive. */
export class RawStream<P extends Protocol> implements AsyncIterable<RawFrame> {
  private parts?: { sender: RawStreamSender<P>; receiver: RawStreamReceiver<P> };
  constructor(core: Core<P>, lease: Lease) {
    this.parts = { sender: new RawStreamSender(core, lease), receiver: new RawStreamReceiver(core, lease) };
  }
  get id(): number { return this.owned().sender.id; }
  send(flags: number, body: Uint8Array, options?: RequestOptions): Promise<void> { return this.owned().sender.send(flags, body, options); }
  next(options?: RequestOptions | number): Promise<RawFrame | null> { return this.owned().receiver.next(options); }
  close(): void { if (this.parts) { this.parts.receiver.close(); this.parts.sender.close(); } }
  split(): { sender: RawStreamSender<P>; receiver: RawStreamReceiver<P> } {
    const parts = this.owned(); this.parts = undefined; return parts;
  }
  private owned() { if (!this.parts) throw new ClientError("split"); return this.parts; }
  async *[Symbol.asyncIterator](): AsyncIterator<RawFrame> {
    try { for (;;) { const frame = await this.next(); if (!frame) return; yield frame; } }
    finally { this.close(); }
  }
}

/** Native/encoded-payload sender using the selected protocol codec and gates. */
export class StreamSender<P extends Protocol> {
  constructor(private readonly raw: RawStreamSender<P>) {}
  get id(): number { return this.raw.id; }
  clone(): StreamSender<P> { return new StreamSender(this.raw.clone()); }
  async send(message: OutboundMessage, options?: RequestOptions): Promise<void> {
    const outbound = codecs.get(this.raw)!.prepare(message);
    await this.raw.send(outbound.flags, outbound.body, options);
  }
  close(): void { this.raw.close(); }
}

/** Native message receiver that decodes only when the consumer asks for a frame. */
export class StreamReceiver<P extends Protocol> implements AsyncIterable<InboundFrame> {
  constructor(private readonly raw: RawStreamReceiver<P>) {}
  get id(): number { return this.raw.id; }
  async next(options?: RequestOptions | number): Promise<InboundFrame | null> {
    const frame = await this.raw.next(options);
    if (!frame) return null;
    try { return codecs.get(this.raw)!.decode(frame); }
    catch { throw new ClientError("invalid_data", "unknown"); }
  }
  close(): void { this.raw.close(); }
  async *[Symbol.asyncIterator](): AsyncIterator<InboundFrame> {
    try { for (;;) { const frame = await this.next(); if (!frame) return; yield frame; } }
    finally { this.close(); }
  }
}

/** Message subscription with native sends and optional ownership-bearing split. */
export class Stream<P extends Protocol> implements AsyncIterable<InboundFrame> {
  private parts?: { sender: StreamSender<P>; receiver: StreamReceiver<P> };
  constructor(raw: RawStream<P>) {
    const parts = raw.split();
    this.parts = { sender: new StreamSender(parts.sender), receiver: new StreamReceiver(parts.receiver) };
  }
  get id(): number { return this.owned().sender.id; }
  send(message: OutboundMessage, options?: RequestOptions): Promise<void> { return this.owned().sender.send(message, options); }
  next(options?: RequestOptions | number): Promise<InboundFrame | null> { return this.owned().receiver.next(options); }
  close(): void { if (this.parts) { this.parts.receiver.close(); this.parts.sender.close(); } }
  split(): { sender: StreamSender<P>; receiver: StreamReceiver<P> } { const parts = this.owned(); this.parts = undefined; return parts; }
  private owned() { if (!this.parts) throw new ClientError("split"); return this.parts; }
  async *[Symbol.asyncIterator](): AsyncIterator<InboundFrame> {
    try { for (;;) { const frame = await this.next(); if (!frame) return; yield frame; } }
    finally { this.close(); }
  }
}
