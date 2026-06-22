/**
 * Exact bytes sent over an agent transport.
 *
 * A packet includes the 4-byte length prefix, 5-byte binary frame header, and
 * CBOR message envelope body.
 */
export class TransportPacket {
  private constructor(readonly bytes: Uint8Array) {}

  /**
   * Validate and wrap exact transport bytes.
   */
  static fromBytes(bytes: Uint8Array): TransportPacket {
    validateSinglePacket(bytes);
    return new TransportPacket(bytes);
  }

  /**
   * Encode a structured raw frame into exact transport bytes.
   */
  static fromFrame(frame: RawFrame): TransportPacket {
    const frameLength = 5 + frame.body.byteLength;
    if (frameLength > MAX_FRAME_SIZE) {
      throw new Error(
        `transport frame is too large: ${frameLength} bytes (max ${MAX_FRAME_SIZE})`,
      );
    }

    const bytes = new Uint8Array(4 + frameLength);
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    view.setUint32(0, frameLength, false);
    view.setUint32(4, frame.id, false);
    view.setUint8(8, frame.flags);
    bytes.set(frame.body, 9);
    return new TransportPacket(bytes);
  }

  /**
   * Decode this packet into a structured raw frame.
   */
  rawFrame(): RawFrame {
    const view = new DataView(
      this.bytes.buffer,
      this.bytes.byteOffset,
      this.bytes.byteLength,
    );
    const frameLength = view.getUint32(0, false);
    return {
      id: view.getUint32(4, false),
      flags: view.getUint8(8),
      body: this.bytes.slice(9, 4 + frameLength),
    };
  }
}

/**
 * Structured frame with the binary header parsed and CBOR body left opaque.
 */
export type RawFrame = {
  /** Correlation ID. */
  id: number;
  /** Frame flags. */
  flags: number;
  /** CBOR message envelope body bytes. */
  body: Uint8Array;
};

/** Size in bytes of `[id: u32 BE][flags: u8]`. */
export const FRAME_HEADER_SIZE = 5;
/** Maximum frame size after the length prefix. */
export const MAX_FRAME_SIZE = 4 * 1024 * 1024;

function validateSinglePacket(bytes: Uint8Array): void {
  if (bytes.byteLength < 9) {
    throw new Error("transport packet is too short");
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const frameLength = view.getUint32(0, false);
  const totalLength = 4 + frameLength;

  if (frameLength > MAX_FRAME_SIZE) {
    throw new Error(
      `transport frame is too large: ${frameLength} bytes (max ${MAX_FRAME_SIZE})`,
    );
  }
  if (frameLength < FRAME_HEADER_SIZE) {
    throw new Error("transport frame is too short");
  }
  if (totalLength !== bytes.byteLength) {
    throw new Error("transport packet must contain exactly one frame");
  }
}
