import { ClientError, defaultLimits, type ByteTransport, type ConnectOptions, type RequestOptions } from "@microsandbox/protocol-client";
import { closeTransport, ControlAttempt, controlError, validateTimeout } from "./attempt.js";
import type { ControlDialer } from "./dialer.js";
import { ControlClientError } from "./error.js";
import { JsonReply, jsonCapabilities, type ControlMode } from "./json-reply.js";
import { encodeJsonRequest, type LegacyControlRequest } from "./legacy-request.js";
import { DEFAULT_REQUEST_TIMEOUT_MS, DEFAULT_SETUP_TIMEOUT_MS, type Capabilities } from "./records.js";

/** Shared internal owner used by the explicit adapter and automatic connection. */
export class JsonSession {
  readonly #closed = new AbortController();
  readonly #transports = new Set<ByteTransport>();
  readonly options: ConnectOptions;
  constructor(readonly dialer: ControlDialer, options: ConnectOptions, readonly rediscover: boolean) {
    this.options = { ...options, limits: defaultLimits(options.limits) };
    validateTimeout(options.setupTimeoutMs ?? DEFAULT_SETUP_TIMEOUT_MS);
  }
  isClosed(): boolean { return this.#closed.signal.aborted; }
  async close(): Promise<void> {
    this.#closed.abort(new ClientError("closed"));
    await Promise.all([...this.#transports].map(closeTransport));
  }
  async discover(attempt: ControlAttempt): Promise<{ mode: ControlMode; capabilities: Capabilities }> {
    const reply = await this.exchange(encodeJsonRequest({ op: "capabilities" }), attempt, attempt, 64 * 1024);
    const mode = reply.discoveryMode();
    return { mode, capabilities: jsonCapabilities(reply.value.get("capabilities")) };
  }
  async operation(request: LegacyControlRequest, options: RequestOptions = {}): Promise<JsonReply> {
    // Validate and serialize before discovery so unsupported/invalid native
    // requests cannot cause network I/O. Legacy batches have no framed-size cap.
    const line = encodeJsonRequest(request);
    const attempt = new ControlAttempt(options.requestTimeoutMs ?? this.options.limits?.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS, [options.signal, this.#closed.signal]);
    let setup: ControlAttempt | undefined;
    try {
      setup = new ControlAttempt(Math.min(attempt.remaining(), this.options.setupTimeoutMs ?? DEFAULT_SETUP_TIMEOUT_MS), [attempt.signal]);
      if (this.rediscover && !this.dialer.verifier) {
        let mode: ControlMode;
        try { mode = (await this.discover(setup)).mode; }
        catch (error) {
          // Discovery is read-only. Its lost reply says nothing about admission
          // of the prepared mutation, which has not been written.
          const failure = controlError(error);
          throw failure instanceof ClientError ? failure.withDelivery("not_sent") : failure;
        }
        if (mode !== "json") throw new ControlClientError("runtime_changed");
      }
      return await this.exchange(line, attempt, setup);
    } catch (error) {
      await this.close();
      throw controlError(error);
    } finally { line.fill(0); setup?.dispose(); attempt.dispose(); }
  }
  private async exchange(line: Uint8Array, attempt: ControlAttempt, setup: ControlAttempt, maxReply?: number): Promise<JsonReply> {
    let transport: ByteTransport | undefined, admitted = false;
    const chunks: Uint8Array[] = [];
    try {
      if (this.isClosed()) throw new ClientError("closed");
      transport = await setup.connect(this.dialer.connector);
      this.#transports.add(transport);
      if (this.dialer.verifier) await setup.run(() => this.dialer.verifier!.verifySession(setup.context));
      attempt.check(); setup.check();
      if (this.isClosed()) throw new ClientError("closed");
      const owned = transport;
      await attempt.run(() => {
        admitted = true; // A rejected/partial write may already have reached the peer.
        return owned.write(line);
      });
      let total = 0;
      for (;;) {
        const chunk = await attempt.run(() => owned.read(8192));
        if (chunk === null) {
          if (total === 0) throw new ClientError("peer_closed");
          break; // The historical protocol also permits a nonempty EOF delimiter.
        }
        if (chunk.length === 0 || chunk.length > 8192) throw new ClientError("invalid_data");
        const newline = chunk.indexOf(10), count = newline < 0 ? chunk.length : newline + 1;
        total += count;
        if (maxReply !== undefined && total > maxReply) throw new ClientError("invalid_data");
        chunks.push(chunk.slice(0, count));
        if (newline >= 0) break;
      }
      const raw = new Uint8Array(total);
      let offset = 0;
      for (const chunk of chunks) { raw.set(chunk, offset); offset += chunk.length; }
      try { return new JsonReply(raw); } finally { raw.fill(0); }
    } catch (error) {
      const failure = controlError(error);
      throw failure instanceof ClientError ? failure.withDelivery(admitted ? "unknown" : "not_sent") : failure;
    } finally {
      for (const chunk of chunks) chunk.fill(0);
      if (transport) { this.#transports.delete(transport); await closeTransport(transport); }
    }
  }
}
