import type { OutboundMessage } from "./message.js";
import type { AgentClient } from "./client.js";
import type { InboundFrame } from "./frame.js";

type FrameQueue = {
  next(timeoutMs?: number): Promise<InboundFrame | null>;
};

/**
 * Handle for an open agent protocol stream.
 *
 * Streams are identified by one correlation ID. They receive frames until a
 * terminal frame arrives, the stream is closed, or the client transport closes.
 */
export class AgentStream {
  constructor(
    /** Correlation ID assigned by the relay/client. */
    readonly id: number,
    private readonly client: AgentClient,
    private readonly queue: FrameQueue,
  ) {}

  /**
   * Send a follow-up message on this stream's correlation ID.
   */
  async send(message: OutboundMessage): Promise<void> {
    await this.client.sendOnStream(this.id, message);
  }

  /**
   * Read the next frame for this stream.
   *
   * Returns `null` after a terminal frame has been consumed or the stream is
   * otherwise closed. If `timeoutMs` is provided, rejects when no frame arrives
   * before that deadline.
   */
  async next(timeoutMs?: number): Promise<InboundFrame | null> {
    return await this.queue.next(timeoutMs);
  }

  /**
   * Stop routing additional frames for this stream.
   *
   * This is a local cleanup operation; it does not send a protocol close frame.
   */
  async close(): Promise<void> {
    this.client.closeStream(this.id);
  }

  /**
   * Iterate frames until the stream ends.
   */
  async *[Symbol.asyncIterator](): AsyncIterator<InboundFrame> {
    while (true) {
      const frame = await this.next();
      if (frame === null) return;
      yield frame;
    }
  }
}
