import { ClientError } from "./error.js";
import { Attempt, wait } from "./timing.js";
import { MAX_FRAME_SIZE, type RawFrame } from "./wire.js";

/** Exclusive byte transport. The reader and serialized writer progress independently. */
export interface ByteTransport {
  /** Return 1..maxBytes ordered bytes, or null on clean EOF; only one read at a time. */
  read(maxBytes: number): Promise<Uint8Array | null>;
  /** Complete a write or reject; partial failure has an uncertain outcome. */
  write(bytes: Uint8Array): Promise<void>;
  /** Close both directions and wake outstanding reads/writes. */
  close(): Promise<void>;
}

/** Remaining setup deadline and cancellation supplied to external connectors. */
export type ConnectContext = { deadlineMs: number; signal: AbortSignal };
/** Repeatable dialer; it performs no JSON discovery or protocol negotiation. */
export interface Connector { connect(context: ConnectContext): Promise<ByteTransport>; }

/** Read an exact bounded section without consuming bytes belonging to the next frame. */
export async function readExactly(transport: ByteTransport, length: number, signal?: AbortSignal): Promise<Uint8Array> {
  if (!Number.isSafeInteger(length) || length < 0 || length > MAX_FRAME_SIZE) throw new ClientError("invalid_data");
  const bytes = new Uint8Array(length);
  let offset = 0;
  while (offset < length) {
    const chunk = await wait(transport.read(length - offset), signal);
    if (chunk === null) throw new ClientError("truncated_frame");
    if (chunk.length === 0 || chunk.length > length - offset) throw new ClientError("invalid_data");
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return bytes;
}

/** Reserve the body budget before allocation; idle has no incomplete-frame deadline. */
export async function readRawFrame(
  transport: ByteTransport,
  maxFrameSize = MAX_FRAME_SIZE,
  incompleteFrameTimeoutMs?: number,
  reserve?: (bytes: number, signal: AbortSignal) => Promise<() => void>,
): Promise<{ frame: RawFrame; release: () => void } | null> {
  const first = await transport.read(1);
  if (first === null) return null;
  if (first.length !== 1) throw new ClientError("invalid_data");
  const attempt = new Attempt(incompleteFrameTimeoutMs);
  let release = () => {};
  try {
    const tail = await readExactly(transport, 3, attempt.signal);
    const length = first[0]! * 0x1000000 + tail[0]! * 0x10000 + tail[1]! * 0x100 + tail[2]!;
    if (length < 5 || length > maxFrameSize) throw new ClientError("invalid_data");
    release = await reserve?.(length + 4, attempt.signal) ?? release;
    const header = await readExactly(transport, 5, attempt.signal);
    const body = await readExactly(transport, length - 5, attempt.signal);
    const id = new DataView(header.buffer, header.byteOffset, header.byteLength).getUint32(0);
    return { frame: { id, flags: header[4]!, body }, release };
  } catch (error) {
    release();
    throw error;
  } finally { attempt.close(); }
}
