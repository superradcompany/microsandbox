import type { EnvelopeCodec, EncodedMessage, InboundFrame } from "./message.js";
import type { ByteTransport, ConnectContext } from "./transport.js";
import { ClientError } from "./error.js";
import { MAX_FRAME_SIZE } from "./wire.js";

/** All byte counts exclude caller-owned prepared inputs and OS socket buffers. */
export type ClientLimits = {
  maxFrameSize: number; maxInFlight: number; queuedWrites: number; queuedResponses: number;
  bufferedBytes: number; incompleteFrameTimeoutMs?: number; requestTimeoutMs?: number;
};
export type ConnectOptions = { setupTimeoutMs?: number; signal?: AbortSignal; limits?: Partial<ClientLimits> };
export type RequestOptions = { requestTimeoutMs?: number; signal?: AbortSignal };
export type IdRange = { start: number; endExclusive: number };
export type SendMetadata = { generation: number; flags: number };
export type EstablishContext = ConnectContext & { limits: ClientLimits };
export type Established<R> = { transport: ByteTransport; codec: EnvelopeCodec; ids: IdRange; ready: R; limits: ClientLimits };

/** Inert protocol implementation; the generic engine owns IDs and subscriptions. */
export interface Protocol<R = unknown> {
  /** Whether completed correlations may be reused on this connection. */
  readonly reuseIds?: boolean;
  establish(transport: ByteTransport, context: EstablishContext): Promise<Established<R>>;
  prepare(ready: R, wireName: string): SendMetadata;
}
export type ReadyOf<P> = P extends Protocol<infer R> ? R : never;

/** Optional checked unary request. Domain errors belong to its decoder. */
export interface Request<T> { message(): EncodedMessage; decode(frame: InboundFrame): T; }

export function defaultLimits(options: Partial<ClientLimits> = {}): ClientLimits {
  const limits: ClientLimits = {
    maxFrameSize: MAX_FRAME_SIZE, maxInFlight: 1024, queuedWrites: 256, queuedResponses: 1024,
    bufferedBytes: 8 * 1024 * 1024, ...options,
  };
  for (const value of [limits.maxFrameSize, limits.maxInFlight, limits.queuedWrites, limits.queuedResponses, limits.bufferedBytes]) {
    if (!Number.isSafeInteger(value) || value < 1 || value > 0xffffffff) throw new ClientError("invalid_options");
  }
  if (limits.maxFrameSize < 5 || limits.maxFrameSize > MAX_FRAME_SIZE || limits.bufferedBytes < limits.maxFrameSize + 4) throw new ClientError("invalid_options");
  for (const timeout of [limits.incompleteFrameTimeoutMs, limits.requestTimeoutMs]) {
    if (timeout !== undefined && (!Number.isFinite(timeout) || timeout < 0 || timeout > 0x7fffffff)) throw new ClientError("invalid_options");
  }
  return limits;
}

export function validateIds(ids: IdRange): void {
  if (!Number.isSafeInteger(ids.start) || !Number.isSafeInteger(ids.endExclusive)
      || ids.start < 1 || ids.start >= ids.endExclusive || ids.endExclusive > 0x100000000) throw new ClientError("invalid_options");
}
