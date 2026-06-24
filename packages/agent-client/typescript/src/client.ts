import type { OutboundMessage } from "./message.js";
import { PROTOCOL_VERSION, encodeEnvelope } from "./message.js";
import type { TransportPacket } from "./packet.js";
import { TransportPacket as Packet } from "./packet.js";
import type { AgentTransport } from "./transport.js";
import { AgentStream } from "./stream.js";
import { InboundFrame } from "./frame.js";

export type ConnectOptions = {
  /**
   * Maximum time to wait for the relay handshake.
   *
   * The handshake reads the relay-assigned correlation ID range and the cached
   * `core.ready` frame. Defaults to 10 seconds.
   */
  handshakeTimeoutMs?: number;
};

type Pending = {
  push(frame: InboundFrame): void;
  close(error?: Error): void;
};

type FrameQueue = Pending & {
  next(timeoutMs?: number): Promise<InboundFrame | null>;
};

type Waiter = {
  active: boolean;
  resolve(frame: InboundFrame | null): void;
  reject(error: Error): void;
};

/**
 * Low-level client for the microsandbox agent protocol.
 *
 * `AgentClient` owns the relay handshake, correlation ID allocation,
 * request/stream routing, protocol-version gating, and packet writes. It is
 * transport agnostic: callers provide an `AgentTransport`, while Node and
 * browser packages provide UDS/WebSocket adapters.
 */
export class AgentClient {
  private nextId: number;
  private readonly idMin: number;
  private readonly idMax: number;
  private readonly protocolVersion = PROTOCOL_VERSION;
  private readonly negotiatedProtocolVersion: number;
  private readonly pending = new Map<number, Pending>();
  private closed = false;
  private readonly readerTask: Promise<void>;

  private constructor(
    private readonly transport: AgentTransport,
    idMin: number,
    idMax: number,
    ready: InboundFrame,
  ) {
    this.idMin = idMin;
    this.idMax = idMax;
    this.nextId = Math.max(1, idMin);
    this.negotiatedProtocolVersion = Math.min(
      this.protocolVersion,
      ready.protocolVersion,
    );
    this.readerTask = this.readerLoop();
  }

  /**
   * Complete the agent relay handshake over an already-connected transport.
   *
   * The transport must yield the relay handshake bytes first:
   * `[id_min: u32 BE][id_max: u32 BE]`, followed by a `core.ready` packet.
   */
  static async connectTransport(
    transport: AgentTransport,
    options: ConnectOptions = {},
  ): Promise<AgentClient> {
    const timeoutMs = options.handshakeTimeoutMs ?? 10_000;
    const range = await withTimeout(
      transport.readBytes(8),
      timeoutMs,
      "agent handshake timed out reading id range",
    );
    const view = new DataView(range.buffer, range.byteOffset, range.byteLength);
    const idMin = view.getUint32(0, false);
    const idMax = view.getUint32(4, false);
    if (idMin >= idMax) {
      throw new Error(`invalid relay id range: start=${idMin}, end=${idMax}`);
    }
    if (usableIdCount(idMin, idMax) === 0) {
      throw new Error(
        `relay id range contains no usable nonzero ids: start=${idMin}, end=${idMax}`,
      );
    }

    const readyPacket = await withTimeout(
      transport.readPacket(),
      timeoutMs,
      "agent handshake timed out reading ready frame",
    );
    if (readyPacket === null) {
      throw new Error("agent handshake closed before ready frame");
    }

    const ready = InboundFrame.fromRawFrame(readyPacket.rawFrame());
    if (ready.type !== "core.ready") {
      throw new Error(`expected core.ready frame, got ${ready.type}`);
    }

    return new AgentClient(transport, idMin, idMax, ready);
  }

  /**
   * Send one message and wait for the first response frame with the same
   * correlation ID.
   *
   * The response may be a domain response such as `core.fs.response`, or a
   * terminal `core.error` if the peer reports a recoverable protocol error.
   */
  async request(message: OutboundMessage): Promise<InboundFrame> {
    const queue = createFrameQueue();
    const id = this.reserveId(queue);
    this.pending.set(id, queue);
    try {
      await this.writeMessage(id, message);
      const frame = await queue.next();
      if (frame === null) {
        throw new Error(`reader closed before response for id=${id}`);
      }
      return frame;
    } catch (error) {
      this.pending.delete(id);
      throw error;
    }
  }

  /**
   * Open a streaming session with a session-start message.
   *
   * The returned stream receives every frame routed to the assigned correlation
   * ID until a terminal frame is delivered, the stream is closed, or the
   * transport closes.
   */
  async openStream(message: OutboundMessage): Promise<AgentStream> {
    const queue = createFrameQueue();
    const id = this.reserveId(queue);
    this.pending.set(id, queue);
    try {
      await this.writeMessage(id, message);
      return new AgentStream(id, this, queue);
    } catch (error) {
      this.pending.delete(id);
      throw error;
    }
  }

  /**
   * Write exact transport bytes without semantic validation.
   *
   * Prefer `request`, `openStream`, and `AgentStream.send` unless you are
   * building a relay, test harness, or protocol tool.
   */
  async writeUnchecked(packet: TransportPacket): Promise<void> {
    await this.transport.writePacket(packet);
  }

  /**
   * Negotiated protocol generation for this connection.
   *
   * This is `min(client protocol version, peer ready-frame version)` and drives
   * local feature gating before sends.
   */
  negotiatedVersion(): number {
    return this.negotiatedProtocolVersion;
  }

  /**
   * Close the transport and wake all pending requests/streams.
   */
  async close(): Promise<void> {
    this.closed = true;
    for (const pending of this.pending.values()) {
      pending.close(new Error("client closed"));
    }
    this.pending.clear();
    await this.transport.close();
    await this.readerTask.catch(() => undefined);
  }

  /**
   * Send a follow-up message on an already-open stream correlation ID.
   *
   * This is public for `AgentStream`; most callers should use
   * `stream.send(...)` instead.
   */
  async sendOnStream(id: number, message: OutboundMessage): Promise<void> {
    await this.writeMessage(id, message);
  }

  /**
   * Stop routing frames for a stream correlation ID.
   *
   * This does not send a protocol close message by itself.
   */
  closeStream(id: number): void {
    const pending = this.pending.get(id);
    if (pending !== undefined) {
      pending.close();
      this.pending.delete(id);
    }
  }

  private async writeMessage(
    id: number,
    message: OutboundMessage,
  ): Promise<void> {
    const outbound = encodeEnvelope(
      message,
      this.protocolVersion,
      this.negotiatedProtocolVersion,
    );
    await this.transport.writePacket(
      Packet.fromFrame({ id, flags: outbound.flags, body: outbound.body }),
    );
  }

  private async readerLoop(): Promise<void> {
    try {
      while (!this.closed) {
        const packet = await this.transport.readPacket();
        if (packet === null) break;
        const frame = InboundFrame.fromRawFrame(packet.rawFrame());
        const pending = this.pending.get(frame.id);
        if (pending === undefined) continue;
        pending.push(frame);
        if (frame.isTerminal()) {
          this.pending.delete(frame.id);
          pending.close();
        }
      }
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      for (const pending of this.pending.values()) pending.close(err);
      this.pending.clear();
      return;
    }

    for (const pending of this.pending.values()) pending.close();
    this.pending.clear();
  }

  private reserveId(queue: Pending): number {
    const attempts = usableIdCount(this.idMin, this.idMax);
    for (let i = 0; i < attempts; i += 1) {
      const id = this.nextId;
      this.nextId += 1;
      if (this.nextId >= this.idMax) this.nextId = Math.max(1, this.idMin);
      if (
        id !== 0 &&
        id >= this.idMin &&
        id < this.idMax &&
        !this.pending.has(id)
      ) {
        return id;
      }
    }
    queue.close(new Error("agent correlation id range exhausted"));
    throw new Error("agent correlation id range exhausted");
  }
}

function createFrameQueue(): FrameQueue {
  const frames: InboundFrame[] = [];
  let frameHead = 0;
  const waiters: Waiter[] = [];
  let waiterHead = 0;
  let closed = false;
  let closeError: Error | null = null;

  return {
    push(frame: InboundFrame) {
      const waiter = nextActiveWaiter(waiters, () => waiterHead, (head) => {
        waiterHead = head;
      });
      if (waiter !== undefined) {
        waiter.active = false;
        waiter.resolve(frame);
        return;
      }
      frames.push(frame);
    },
    close(error?: Error) {
      closed = true;
      closeError = error ?? null;
      for (let i = waiterHead; i < waiters.length; i += 1) {
        const waiter = waiters[i];
        if (waiter === undefined) continue;
        if (!waiter.active) continue;
        waiter.active = false;
        if (closeError !== null) waiter.reject(closeError);
        else waiter.resolve(null);
      }
      waiters.length = 0;
      waiterHead = 0;
    },
    next(timeoutMs?: number): Promise<InboundFrame | null> {
      if (frameHead < frames.length) {
        const frame = frames[frameHead];
        frameHead += 1;
        if (frameHead === frames.length) {
          frames.length = 0;
          frameHead = 0;
        }
        return Promise.resolve(frame ?? null);
      }
      if (closed) {
        if (closeError !== null) return Promise.reject(closeError);
        return Promise.resolve(null);
      }

      let waiter: Waiter | undefined;
      const nextFrame = new Promise<InboundFrame | null>((resolve, reject) => {
        waiter = { active: true, resolve, reject };
        waiters.push(waiter);
      });
      if (timeoutMs === undefined) return nextFrame;
      return withTimeoutAndCancel(
        nextFrame,
        timeoutMs,
        "agent stream read timed out",
        () => {
          if (waiter !== undefined) waiter.active = false;
        },
      );
    },
  };
}

function nextActiveWaiter(
  waiters: Waiter[],
  getHead: () => number,
  setHead: (head: number) => void,
): Waiter | undefined {
  let head = getHead();
  while (head < waiters.length) {
    const waiter = waiters[head];
    head += 1;
    if (waiter === undefined) continue;
    if (waiter.active) {
      setHead(head);
      return waiter;
    }
  }
  waiters.length = 0;
  setHead(0);
  return undefined;
}

function usableIdCount(idMin: number, idMax: number): number {
  return Math.max(0, idMax - Math.max(1, idMin));
}

async function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  message: string,
): Promise<T> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const timer = new Promise<never>((_, reject) => {
    timeout = setTimeout(() => reject(new Error(message)), timeoutMs);
  });
  try {
    return await Promise.race([promise, timer]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

async function withTimeoutAndCancel<T>(
  promise: Promise<T>,
  timeoutMs: number,
  message: string,
  cancel: () => void,
): Promise<T> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const timer = new Promise<never>((_, reject) => {
    timeout = setTimeout(() => {
      cancel();
      reject(new Error(message));
    }, timeoutMs);
  });
  try {
    return await Promise.race([promise, timer]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}
