import net from "node:net";

import { ClientError } from "./error.js";
import { checkSignal, signalError } from "./timing.js";
import type { ByteTransport, Connector, ConnectContext } from "./transport.js";

/** Native Unix socket or Windows named-pipe connector, using the supplied endpoint verbatim. */
export class LocalConnector implements Connector {
  constructor(readonly path: string) {}
  connect(context: ConnectContext): Promise<NodeTransport> { return NodeTransport.connect(this.path, context); }
}

/** Paused-mode socket: no unbounded user-space data listener or packet queue. */
export class NodeTransport implements ByteTransport {
  private error?: Error;
  private constructor(private readonly socket: net.Socket) {
    socket.on("error", error => { this.error = error; });
  }

  static async connect(path: string, context?: ConnectContext): Promise<NodeTransport> {
    checkSignal(context?.signal);
    const socket = net.createConnection(path);
    const transport = new NodeTransport(socket);
    try {
      await new Promise<void>((resolve, reject) => {
        const abort = () => { cleanup(); socket.destroy(); reject(signalError(context!.signal)); };
        const done = () => { cleanup(); resolve(); };
        const fail = () => { cleanup(); reject(new ClientError("io")); };
        const cleanup = () => {
          socket.removeListener("connect", done);
          socket.removeListener("error", fail);
          context?.signal.removeEventListener("abort", abort);
        };
        socket.once("connect", done);
        socket.once("error", fail);
        context?.signal.addEventListener("abort", abort, { once: true });
        if (context?.signal.aborted) { cleanup(); abort(); }
      });
      return transport;
    } catch (error) { socket.destroy(); throw error; }
  }

  async read(maxBytes: number): Promise<Uint8Array | null> {
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new ClientError("invalid_options");
    for (;;) {
      // Read only currently buffered bytes. Asking Node for an entire large
      // frame would increase its high-water mark and duplicate frame buffering.
      if (this.socket.readableLength > 0) {
        const value = this.socket.read(Math.min(maxBytes, this.socket.readableLength)) as Buffer | null;
        if (value) return value;
      }
      if (this.error) throw new ClientError("io");
      if (this.socket.readableEnded || this.socket.destroyed) return null;
      await new Promise<void>(resolve => {
        const ready = () => {
          for (const event of ["readable", "end", "close", "error"]) this.socket.removeListener(event, ready);
          resolve();
        };
        for (const event of ["readable", "end", "close", "error"]) this.socket.once(event, ready);
      });
    }
  }

  async write(bytes: Uint8Array): Promise<void> {
    if (this.socket.destroyed) throw new ClientError("closed");
    await new Promise<void>((resolve, reject) => {
      this.socket.write(bytes, error => error ? reject(new ClientError("io")) : resolve());
    });
  }

  async close(): Promise<void> { this.socket.destroy(); }
}
