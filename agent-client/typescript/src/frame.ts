import { decode } from "cbor-x";

import type { EncodedEnvelope, MessageType } from "./message.js";
import type { RawFrame } from "./packet.js";

/**
 * Decoded inbound agent frame.
 *
 * `payload` contains the still-CBOR-encoded payload bytes for `type`; call
 * `decodePayload()` when you want a JavaScript object.
 */
export class InboundFrame {
  constructor(
    /** Correlation ID from the binary frame header. */
    readonly id: number,
    /** Frame flags from the binary frame header. */
    readonly flags: number,
    /** Protocol generation from the CBOR message envelope. */
    readonly protocolVersion: number,
    /** Message type from the CBOR message envelope. */
    readonly type: MessageType,
    /** CBOR-encoded payload bytes from the message envelope. */
    readonly payload: Uint8Array,
  ) {}

  /**
   * Decode the frame payload as CBOR.
   */
  decodePayload<T = unknown>(): T {
    return decode(this.payload) as T;
  }

  /**
   * Return whether this frame terminates its correlation ID.
   */
  isTerminal(): boolean {
    return (this.flags & 0b0000_0001) !== 0;
  }

  /**
   * Decode an inbound raw frame into an `InboundFrame`.
   */
  static fromRawFrame(frame: RawFrame): InboundFrame {
    const envelope = decode(frame.body) as EncodedEnvelope;
    return new InboundFrame(
      frame.id,
      frame.flags,
      envelope.v,
      envelope.t,
      envelope.p,
    );
  }
}
