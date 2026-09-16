import { Core } from "./core.js";
import { ClientError, clientError } from "./error.js";
import type { InboundFrame, OutboundMessage } from "./message.js";
import { defaultLimits, validateIds, type ConnectOptions, type Established, type Protocol, type ReadyOf, type Request, type RequestOptions } from "./protocol.js";
import { RawStream, Stream } from "./stream.js";
import { Attempt, checkSignal, wait } from "./timing.js";
import type { ByteTransport, Connector } from "./transport.js";
import type { RawFrame } from "./wire.js";

/** Generic framed connection; native, encoded, raw and packet APIs share one router. */
export class Client<P extends Protocol> {
  private readonly release: () => void;
  private constructor(private readonly core: Core<P>) { this.release = core.retain(this); }

  /** Establish a protocol on a caller-owned, authenticated transport. */
  static async connectTransport<P extends Protocol>(transport: ByteTransport, protocol: P, options: ConnectOptions = {}): Promise<Client<P>> {
    let handedOff = false;
    try {
      return await Client.connectConnector({ connect: async () => { handedOff = true; return transport; } }, protocol, options);
    } catch (error) {
      // Ownership transfers at invocation, including invalid/pre-aborted setup.
      if (!handedOff) await Promise.resolve().then(() => transport.close()).catch(() => undefined);
      throw error;
    }
  }

  /** One total setup deadline covers dialing and protocol establishment. */
  static async connectConnector<P extends Protocol>(connector: Connector, protocol: P, options: ConnectOptions = {}): Promise<Client<P>> {
    const limits = defaultLimits(options.limits);
    const timeoutMs = options.setupTimeoutMs ?? 10_000;
    const attempt = new Attempt(timeoutMs, options.signal);
    const context = { deadlineMs: performance.now() + timeoutMs, signal: attempt.signal, limits };
    let transport: ByteTransport | undefined;
    try {
      checkSignal(attempt.signal);
      const dialing = connector.connect(context).then(value => {
        // Close a transport that a connector resolves after cancellation.
        if (attempt.signal.aborted) { void value.close().catch(() => undefined); checkSignal(attempt.signal); }
        transport = value;
        return value;
      });
      transport = await wait(dialing, attempt.signal);
      const established = await wait(protocol.establish(transport, context), attempt.signal) as Established<ReadyOf<P>>;
      checkSignal(attempt.signal);
      return await Client.fromEstablished(protocol, established);
    } catch (error) {
      await transport?.close().catch(() => undefined);
      throw clientError(error).withDelivery("not_sent");
    } finally { attempt.close(); }
  }

  /** Start routing an externally established transport using public types. */
  static async fromEstablished<P extends Protocol>(protocol: P, established: Established<ReadyOf<P>>): Promise<Client<P>> {
    try {
      validateIds(established.ids);
      established.limits = defaultLimits(established.limits);
    } catch (error) {
      await Promise.resolve().then(() => established.transport.close()).catch(() => undefined);
      throw error;
    }
    const core = new Core(protocol, established);
    const client = new Client(core);
    core.start();
    return client;
  }

  get ready(): ReadyOf<P> { return this.core.established.ready; }
  clone(): Client<P> { return new Client(this.core); }
  isClosed(): boolean { return this.core.failure !== undefined; }
  /** Close every shared handle; no automatic reconnect follows. */
  async close(): Promise<void> { this.release(); await this.core.close(); }

  async request(message: OutboundMessage, options?: RequestOptions): Promise<InboundFrame> {
    const outbound = this.core.prepare(message);
    const frame = await this.requestRaw(outbound.flags, outbound.body, options);
    try { return this.core.established.codec.decode(frame); }
    catch { throw new ClientError("invalid_data", "unknown"); }
  }

  async requestTyped<T>(request: Request<T>, options?: RequestOptions): Promise<T> {
    const frame = await this.request(request.message(), options);
    if (!frame.isTerminal()) throw new ClientError("invalid_data", "unknown");
    return request.decode(frame);
  }

  async openStream(message: OutboundMessage, options?: RequestOptions): Promise<Stream<P>> {
    const outbound = this.core.prepare(message);
    return new Stream(await this.openStreamRaw(outbound.flags, outbound.body, options));
  }

  async requestRaw(flags: number, body: Uint8Array, options: RequestOptions = {}): Promise<RawFrame> {
    const attempt = new Attempt(options.requestTimeoutMs ?? this.core.established.limits.requestTimeoutMs, options.signal);
    let stream: RawStream<P> | undefined;
    try {
      checkSignal(attempt.signal);
      const lease = this.core.reserve();
      stream = new RawStream(this.core, lease);
      try {
        await this.core.writeFrame(lease, flags, body, attempt.signal);
        const frame = await stream.next({ signal: attempt.signal });
        if (!frame) throw new ClientError("peer_closed");
        return frame;
      } catch (error) { throw clientError(error).withDelivery(this.core.delivery(lease)); }
    } finally { stream?.close(); attempt.close(); }
  }

  async openStreamRaw(flags: number, body: Uint8Array, options: RequestOptions = {}): Promise<RawStream<P>> {
    const attempt = new Attempt(options.requestTimeoutMs ?? this.core.established.limits.requestTimeoutMs, options.signal);
    let stream: RawStream<P> | undefined;
    try {
      checkSignal(attempt.signal);
      const lease = this.core.reserve();
      stream = new RawStream(this.core, lease);
      try { await this.core.writeFrame(lease, flags, body, attempt.signal); }
      catch (error) { throw clientError(error).withDelivery(this.core.delivery(lease)); }
      return stream;
    } catch (error) { stream?.close(); throw error; }
    finally { attempt.close(); }
  }

  async sendOnStream(id: number, message: OutboundMessage, options?: RequestOptions): Promise<void> {
    const outbound = this.core.prepare(message);
    await this.sendRaw(id, outbound.flags, outbound.body, options);
  }

  async sendRaw(id: number, flags: number, body: Uint8Array, options: RequestOptions = {}): Promise<void> {
    const lease = this.core.owned(id);
    const attempt = new Attempt(options.requestTimeoutMs, options.signal);
    try { await this.core.writeFrame(lease, flags, body, attempt.signal); }
    finally { attempt.close(); }
  }

  async writeUnchecked(packet: Uint8Array | { bytes: Uint8Array }, options: RequestOptions = {}): Promise<void> {
    const attempt = new Attempt(options.requestTimeoutMs, options.signal);
    try { await this.core.writeExact(packet instanceof Uint8Array ? packet : packet.bytes, attempt.signal); }
    finally { attempt.close(); }
  }

  /** Local disposal sends no signal, EOF, or application cancellation. */
  closeStream(id: number): void { this.core.closeStream(id); }
}
