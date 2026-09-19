import { ClientError } from "./error.js";
import { checkSignal, signalError } from "./timing.js";
import type { ByteTransport, Connector, ConnectContext } from "./transport.js";

/** Standard browser WebSocket surface; custom authentication may construct it. */
export type WebSocketLike = Pick<WebSocket, "binaryType" | "readyState" | "bufferedAmount" | "send" | "close" | "addEventListener" | "removeEventListener">;
/** Browser sockets cannot pause incoming messages; overflow closes the connection. */
export type WebSocketOptions = { bufferedBytes?: number; bufferedMessages?: number };

/** Browser-safe connector. The client supplies one deadline for dial and handshake. */
export class WebSocketConnector implements Connector {
  constructor(readonly url: string, readonly protocols?: string | string[], readonly options?: WebSocketOptions) {}
  connect(context: ConnectContext): Promise<WebSocketTransport> {
    return WebSocketTransport.connect(this.url, this.protocols, context, this.options);
  }
}

/** Ordered byte stream over binary WebSocket messages, with bounded queues. */
export class WebSocketTransport implements ByteTransport {
  private readonly chunks: Uint8Array[] = [];
  private head = 0;
  private offset = 0;
  private buffered = 0;
  private closed = false;
  private reading = false;
  private error?: ClientError;
  private readonly waiters = new Set<() => void>();
  private readonly maxBytes: number;
  private readonly maxMessages: number;

  constructor(private readonly socket: WebSocketLike, options: WebSocketOptions = {}) {
    this.maxBytes = options.bufferedBytes ?? 8 * 1024 * 1024;
    this.maxMessages = options.bufferedMessages ?? 4096;
    for (const limit of [this.maxBytes, this.maxMessages]) {
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 0xffffffff) throw new ClientError("invalid_options");
    }
    socket.binaryType = "arraybuffer";
    socket.addEventListener("message", this.onMessage);
    socket.addEventListener("close", this.onClose);
    socket.addEventListener("error", this.onError);
    if (socket.readyState >= 2) this.finish();
  }

  static async connect(url: string, protocols?: string | string[], context?: ConnectContext, options?: WebSocketOptions): Promise<WebSocketTransport> {
    checkSignal(context?.signal);
    if (!globalThis.WebSocket) throw new ClientError("io");
    const socket = new globalThis.WebSocket(url, protocols);
    let transport: WebSocketTransport;
    try { transport = new WebSocketTransport(socket, options); }
    catch (error) { socket.close(); throw error; }
    try {
      await new Promise<void>((resolve, reject) => {
        const cleanup = () => {
          socket.removeEventListener("open", open);
          socket.removeEventListener("close", failed);
          socket.removeEventListener("error", failed);
          context?.signal.removeEventListener("abort", abort);
        };
        const open = () => { cleanup(); resolve(); };
        const failed = () => { cleanup(); reject(new ClientError("io")); };
        const abort = () => { cleanup(); reject(signalError(context!.signal)); };
        socket.addEventListener("open", open);
        socket.addEventListener("close", failed);
        socket.addEventListener("error", failed);
        context?.signal.addEventListener("abort", abort, { once: true });
        if (context?.signal.aborted) abort();
        else if (socket.readyState === 1) open();
        else if (socket.readyState >= 2) failed();
      });
      return transport;
    } catch (error) { await transport.close(); throw error; }
  }

  async read(maxBytes: number): Promise<Uint8Array | null> {
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new ClientError("invalid_options");
    if (this.reading) throw new ClientError("receiving");
    this.reading = true;
    try {
      for (;;) {
        if (this.error) throw this.error;
        const chunk = this.chunks[this.head];
        if (chunk) {
          const end = Math.min(chunk.length, this.offset + maxBytes);
          const result = chunk.subarray(this.offset, end);
          this.buffered -= result.length;
          this.offset = end;
          if (end === chunk.length) {
            this.head++;
            this.offset = 0;
            // Compact occasionally, avoiding both O(n) shifts and dead storage.
            if (this.head === this.chunks.length || this.head >= 128) {
              this.chunks.splice(0, this.head);
              this.head = 0;
            }
          }
          return result;
        }
        if (this.closed) return null;
        await this.changed();
      }
    } finally { this.reading = false; }
  }

  async write(bytes: Uint8Array): Promise<void> {
    if (bytes.length > this.maxBytes) throw new ClientError("capacity");
    // WebSocket.send() has no drain promise. Wait for its browser-owned queue
    // before admitting another packet, keeping the writer byte budget occupied.
    while (this.socket.bufferedAmount > 0) {
      this.checkWritable();
      await this.changed(4);
    }
    this.checkWritable();
    this.socket.send(bytes);
    while (this.socket.bufferedAmount > 0) {
      this.checkWritable();
      await this.changed(4);
    }
    this.checkWritable();
  }

  async close(): Promise<void> {
    this.chunks.length = 0;
    this.buffered = this.head = this.offset = 0;
    this.finish();
    if (this.socket.readyState < 2) this.socket.close();
  }

  private readonly onMessage = (event: MessageEvent): void => {
    if (this.closed) return;
    const data: unknown = event.data;
    const chunk = data instanceof ArrayBuffer ? new Uint8Array(data)
      : ArrayBuffer.isView(data) ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : undefined;
    if (!chunk) { this.fail(new ClientError("invalid_data")); return; }
    if (!chunk.length) return;
    if (chunk.length > this.maxBytes - this.buffered || this.chunks.length - this.head >= this.maxMessages) {
      this.fail(new ClientError("capacity")); return;
    }
    this.chunks.push(chunk);
    this.buffered += chunk.length;
    this.notify();
  };
  private readonly onClose = (): void => { this.finish(); };
  private readonly onError = (): void => { this.fail(new ClientError("io")); };
  private fail(error: ClientError): void { this.error = error; void this.close(); }
  private checkWritable(): void {
    if (this.error) throw this.error;
    if (this.closed || this.socket.readyState !== 1) throw new ClientError("closed");
  }
  private finish(): void {
    this.closed = true;
    this.socket.removeEventListener("message", this.onMessage);
    this.socket.removeEventListener("close", this.onClose);
    this.socket.removeEventListener("error", this.onError);
    this.notify();
  }
  private changed(pollMs?: number): Promise<void> {
    return new Promise(resolve => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const done = () => { if (timer) clearTimeout(timer); this.waiters.delete(done); resolve(); };
      this.waiters.add(done);
      if (pollMs !== undefined) timer = setTimeout(done, pollMs);
    });
  }
  private notify(): void { for (const waiter of [...this.waiters]) waiter(); }
}
