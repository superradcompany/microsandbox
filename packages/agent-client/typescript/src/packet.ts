import { decodeFrame, encodeFrame, type RawFrame } from "@microsandbox/protocol-client";
export { MAX_FRAME_SIZE, FRAME_HEADER_SIZE, type RawFrame } from "@microsandbox/protocol-client";

/** Exact transport packet, including its length prefix. */
export class TransportPacket {
  private constructor(readonly bytes: Uint8Array) {}
  /** Validate exactly one frame while retaining its byte representation. */
  static fromBytes(bytes: Uint8Array): TransportPacket {
    decodeFrame(bytes);
    return new TransportPacket(Uint8Array.from(bytes));
  }
  /** Encode routing fields without inspecting the opaque body. */
  static fromFrame(frame: RawFrame): TransportPacket { return new TransportPacket(encodeFrame(frame)); }
  rawFrame(): RawFrame { return decodeFrame(this.bytes); }
}
