import net from "node:net";

import { MAX_FRAME_SIZE, TransportPacket } from "../packet.js";
import type { AgentTransport } from "../transport.js";

/**
 * Node.js Unix domain socket transport for the agent protocol.
 *
 * This adapter is intentionally exported only from the Node entry point because
 * it imports `node:net`. Browser and front-end code should use
 * `WebSocketTransport` instead.
 */
export class UnixSocketTransport implements AgentTransport {
  private readonly chunks: Uint8Array[] = [];
  private bufferedBytes = 0;
  private headOffset = 0;
  private ended = false;
  private error: Error | null = null;
  private readonly waiters: Array<() => void> = [];

  private constructor(private readonly socket: net.Socket) {}

  /**
   * Open a Unix domain socket connection to an agent relay.
   *
   * The returned transport is connected but not handshaken. Pass it to
   * `AgentClient.connectTransport(...)`, or use the `connectUnix(...)`
   * convenience function from `@microsandbox/agent-client/node`.
   */
  static connect(path: string): Promise<UnixSocketTransport> {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection(path);
      const transport = new UnixSocketTransport(socket);
      socket.on("data", (chunk: Buffer) => transport.push(chunk));
      socket.on("end", () => transport.finish());
      socket.on("close", () => transport.finish());
      socket.on("error", (error) => transport.fail(error));
      socket.once("connect", () => resolve(transport));
      socket.once("error", reject);
    });
  }

  /**
   * Read exactly `length` bytes, buffering partial socket chunks as needed.
   */
  async readBytes(length: number): Promise<Uint8Array> {
    while (this.availableBytes() < length) {
      if (this.error !== null) {
        throw this.error;
      }
      if (this.ended) {
        throw new Error("transport closed before enough bytes were available");
      }
      await this.waitForData();
    }

    return this.consumeBytes(length);
  }

  /**
   * Read one length-prefixed protocol packet from the socket.
   *
   * Returns `null` after an orderly close with no buffered bytes remaining.
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
      if (!started && this.ended && this.bufferedBytes === 0) {
        return null;
      }
      throw error;
    }
  }

  /**
   * Write one complete protocol packet to the socket.
   */
  async writePacket(packet: TransportPacket): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      this.socket.write(packet.bytes, (error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve();
      });
    });
  }

  /**
   * Close the socket's writable side.
   */
  async close(): Promise<void> {
    this.socket.end();
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
    this.ended = true;
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
