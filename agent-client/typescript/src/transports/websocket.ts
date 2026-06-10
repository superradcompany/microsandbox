import { MAX_FRAME_SIZE, TransportPacket } from "../packet.js";
import type { AgentTransport } from "../transport.js";

/**
 * Minimal browser-compatible WebSocket surface required by the transport.
 *
 * It matches the standard DOM `WebSocket` closely enough to support browser
 * sockets and compatible test doubles.
 */
export type WebSocketLike = {
  binaryType: BinaryType;
  readyState: number;
  send(data: Uint8Array): void;
  close(): void;
  addEventListener(
    type: "message",
    listener: (event: MessageEvent) => void,
  ): void;
  addEventListener(type: "close", listener: () => void): void;
  addEventListener(type: "error", listener: () => void): void;
};

/**
 * WebSocket transport for the agent protocol.
 *
 * The transport sends each protocol packet as one binary WebSocket message and
 * buffers incoming binary message bytes until complete packets are available.
 * It is safe to import from browser/front-end bundles.
 */
export class WebSocketTransport implements AgentTransport {
  private readonly chunks: Uint8Array[] = [];
  private bufferedBytes = 0;
  private headOffset = 0;
  private closed = false;
  private error: Error | null = null;
  private readonly waiters: Array<() => void> = [];

  /**
   * Wrap an already-open or opening WebSocket-like object.
   *
   * Use this when another layer owns WebSocket construction or authentication.
   * Use `WebSocketTransport.connect(...)` for the common browser case.
   */
  constructor(private readonly socket: WebSocketLike) {
    this.socket.binaryType = "arraybuffer";
    this.socket.addEventListener("message", (event) => {
      this.push(messageDataToBytes(event.data));
    });
    this.socket.addEventListener("close", () => this.finish());
    this.socket.addEventListener("error", () => {
      this.fail(new Error("websocket transport error"));
    });
  }

  /**
   * Create a browser WebSocket and resolve once it reaches `open`.
   */
  static connect(
    url: string,
    protocols?: string | string[],
  ): Promise<WebSocketTransport> {
    return new Promise((resolve, reject) => {
      const WebSocketCtor = globalThis.WebSocket;
      if (WebSocketCtor === undefined) {
        reject(new Error("WebSocket is not available in this environment"));
        return;
      }

      const socket = new WebSocketCtor(url, protocols);
      const transport = new WebSocketTransport(socket);
      socket.addEventListener("open", () => resolve(transport), { once: true });
      socket.addEventListener(
        "error",
        () => reject(new Error("websocket connect failed")),
        { once: true },
      );
    });
  }

  /**
   * Read exactly `length` bytes, buffering partial WebSocket messages as needed.
   */
  async readBytes(length: number): Promise<Uint8Array> {
    while (this.availableBytes() < length) {
      if (this.error !== null) {
        throw this.error;
      }
      if (this.closed) {
        throw new Error("transport closed before enough bytes were available");
      }
      await this.waitForData();
    }

    return this.consumeBytes(length);
  }

  /**
   * Read one length-prefixed protocol packet from buffered binary messages.
   *
   * Returns `null` after the socket closes with no buffered bytes remaining.
   */
  async readPacket(): Promise<TransportPacket | null> {
    let started = false;
    try {
      const lenBytes = await this.readBytes(4);
      started = true;
      const view = new DataView(
        lenBytes.buffer,
        lenBytes.byteOffset,
        lenBytes.byteLength,
      );
      const frameLength = view.getUint32(0, false);
      if (frameLength > MAX_FRAME_SIZE) {
        throw new Error(
          `transport frame is too large: ${frameLength} bytes (max ${MAX_FRAME_SIZE})`,
        );
      }

      const rest = await this.readBytes(frameLength);
      const packet = new Uint8Array(4 + frameLength);
      packet.set(lenBytes, 0);
      packet.set(rest, 4);
      return TransportPacket.fromBytes(packet);
    } catch (error) {
      if (!started && this.closed && this.bufferedBytes === 0) {
        return null;
      }
      throw error;
    }
  }

  /**
   * Send one complete protocol packet as a binary WebSocket message.
   */
  async writePacket(packet: TransportPacket): Promise<void> {
    this.socket.send(packet.bytes);
  }

  /**
   * Close the WebSocket.
   */
  async close(): Promise<void> {
    this.socket.close();
  }

  private push(chunk: Uint8Array): void {
    this.chunks.push(chunk);
    this.bufferedBytes += chunk.byteLength;
    this.notify();
  }

  private availableBytes(): number {
    return this.bufferedBytes;
  }

  private consumeBytes(length: number): Uint8Array {
    const bytes = new Uint8Array(length);
    let written = 0;

    while (written < length) {
      const chunk = this.chunks[0];
      if (chunk === undefined) {
        throw new Error("transport buffer underflow");
      }
      const available = chunk.byteLength - this.headOffset;
      const take = Math.min(length - written, available);
      bytes.set(chunk.subarray(this.headOffset, this.headOffset + take), written);
      written += take;
      this.headOffset += take;
      this.bufferedBytes -= take;

      if (this.headOffset === chunk.byteLength) {
        this.chunks.shift();
        this.headOffset = 0;
      }
    }

    return bytes;
  }

  private finish(): void {
    this.closed = true;
    this.notify();
  }

  private fail(error: Error): void {
    this.error = error;
    this.notify();
  }

  private waitForData(): Promise<void> {
    return new Promise((resolve) => {
      this.waiters.push(resolve);
    });
  }

  private notify(): void {
    const waiters = this.waiters.splice(0);
    for (const waiter of waiters) waiter();
  }
}

function messageDataToBytes(data: unknown): Uint8Array {
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data);
  }
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  throw new Error("websocket message is not binary");
}
