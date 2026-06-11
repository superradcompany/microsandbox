import { mapNapiError } from "./internal/error-mapping.js";
import {
  napi,
  type NapiAgentClient,
  type NapiRawFrame,
} from "./internal/napi.js";

/** Frame flag: this is the last message for the given correlation id. */
export const FLAG_TERMINAL = 0b0000_0001;
/** Frame flag: this is the first message of a new session. */
export const FLAG_SESSION_START = 0b0000_0010;
/** Frame flag: this message requests sandbox shutdown. */
export const FLAG_SHUTDOWN = 0b0000_0100;

/**
 * A raw protocol frame.
 *
 * The `body` is the CBOR-encoded `Message` body (`v`, `t`, `p`) as it
 * appeared on the wire — decode with a CBOR library such as `cbor-x`.
 */
export interface RawFrame {
  /** Correlation ID from the frame header. */
  readonly id: number;
  /** Frame flags (`FLAG_TERMINAL`, `FLAG_SESSION_START`, ...). */
  readonly flags: number;
  /** Raw CBOR-encoded body bytes. */
  readonly body: Buffer;
}

/** Options for connecting to an agent relay. */
export interface AgentConnectOptions {
  /** Handshake timeout in milliseconds. Defaults to 10_000. */
  readonly timeoutMs?: number;
}

/**
 * Low-level client for talking to agentd through the sandbox relay socket.
 *
 * All bodies are raw CBOR bytes — encode and decode in your code with a
 * library like `cbor-x`. Build typed convenience methods on top of this
 * class.
 *
 * ```ts
 * import { encode, decode } from "cbor-x";
 * const client = await AgentClient.connectSandbox("dev");
 * const body = encode({ v: 1, t: "core.fs.request", p: encode({ op: { Stat: { path: "/etc" } } }) });
 * const frame = await client.request(FLAG_SESSION_START, body);
 * console.log(decode(frame.body));
 * await client.close();
 * ```
 */
export class AgentClient {
  private constructor(private readonly native: NapiAgentClient) {}

  /**
   * Connect to a running sandbox by name.
   * Names are limited to 128 UTF-8 bytes.
   */
  static async connectSandbox(
    name: string,
    opts?: AgentConnectOptions,
  ): Promise<AgentClient> {
    try {
      const inner = await napi.AgentClient.connectSandbox(name, opts);
      return new AgentClient(inner);
    } catch (e) {
      throw mapNapiError(e);
    }
  }

  /** Connect to an agentd relay socket by path. */
  static async connect(
    path: string,
    opts?: AgentConnectOptions,
  ): Promise<AgentClient> {
    try {
      const inner = await napi.AgentClient.connect(path, opts);
      return new AgentClient(inner);
    } catch (e) {
      throw mapNapiError(e);
    }
  }

  /**
   * Resolve a sandbox's agentd relay socket path without connecting.
   *
   * Returns the same path {@link connectSandbox} would dial, so callers can
   * talk to agentd over a raw byte transport instead of this frame client.
   * The sandbox need not be running. Names are limited to 128 UTF-8 bytes.
   */
  static socketPath(name: string): string {
    try {
      return napi.AgentClient.socketPath(name);
    } catch (e) {
      throw mapNapiError(e);
    }
  }

  /**
   * Send one frame and await a single response frame.
   *
   * Use for request/response RPCs that produce exactly one terminal
   * response (e.g. `FsRequest` → `FsResponse`).
   */
  async request(flags: number, body: Buffer): Promise<RawFrame> {
    try {
      return frameFromNapi(await this.native.request(flags, body));
    } catch (e) {
      throw mapNapiError(e);
    }
  }

  /**
   * Open a streaming session. The returned stream carries the protocol
   * correlation `id` (pass to `send()` for follow-up frames) and is also an
   * async iterator of raw frames.
   */
  async stream(flags: number, body: Buffer): Promise<AgentStream> {
    try {
      const { id, handle } = await this.native.streamOpen(flags, body);
      return new AgentStream(this.native, id, handle);
    } catch (e) {
      throw mapNapiError(e);
    }
  }

  /**
   * Send a follow-up frame on an existing correlation id (e.g. stdin,
   * signal, resize, or data chunks on an open session).
   */
  async send(id: number, flags: number, body: Buffer): Promise<void> {
    try {
      await this.native.send(id, flags, body);
    } catch (e) {
      throw mapNapiError(e);
    }
  }

  /** The cached handshake `core.ready` frame body bytes (CBOR-encoded). */
  readyBytes(): Buffer {
    try {
      return this.native.readyBytes();
    } catch (e) {
      throw mapNapiError(e);
    }
  }

  /** Close the connection. Idempotent. */
  async close(): Promise<void> {
    try {
      await this.native.close();
    } catch (e) {
      throw mapNapiError(e);
    }
  }
}

/** An open raw agent stream. */
export class AgentStream implements AsyncIterableIterator<RawFrame> {
  private closed = false;

  constructor(
    private readonly native: NapiAgentClient,
    /** Protocol correlation id. Pass to `AgentClient.send()` for follow-up frames. */
    readonly id: number,
    private readonly handle: bigint,
  ) {}

  async next(): Promise<IteratorResult<RawFrame>> {
    if (this.closed) return { done: true, value: undefined };

    try {
      const next = await this.native.streamNext(this.handle);
      if (next === null) {
        this.closed = true;
        return { done: true, value: undefined };
      }

      if ((next.flags & FLAG_TERMINAL) !== 0) {
        this.closed = true;
      }

      return { done: false, value: frameFromNapi(next) };
    } catch (e) {
      throw mapNapiError(e);
    }
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    try {
      await this.native.streamClose(this.handle);
    } catch (e) {
      throw mapNapiError(e);
    }
  }

  async return(): Promise<IteratorResult<RawFrame>> {
    await this.close();
    return { done: true, value: undefined };
  }

  [Symbol.asyncIterator](): AsyncIterableIterator<RawFrame> {
    return this;
  }
}

function frameFromNapi(f: NapiRawFrame): RawFrame {
  return { id: f.id, flags: f.flags, body: f.body };
}
