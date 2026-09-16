import { Client, ClientError, defaultLimits, type ByteTransport, type ConnectOptions, type Connector, type InboundFrame, type OutboundMessage, type RequestOptions } from "@microsandbox/protocol-client";
import { closeTransport, ControlAttempt, controlError } from "./attempt.js";
import type { ControlClient } from "./client.js";
import type { ControlDialer, VerifiedControlConnector } from "./dialer.js";
import { ControlClientError } from "./error.js";
import { JsonSession } from "./json-session.js";
import type { ControlMode, JsonReply } from "./json-reply.js";
import { nativeJsonRequest, type CheckedControlRequest } from "./legacy-request.js";
import { DEFAULT_REQUEST_TIMEOUT_MS, DEFAULT_SETUP_TIMEOUT_MS, type Capabilities } from "./records.js";
import { ControlProtocol } from "./protocol.js";

export type ControlReply = { kind: "cbor"; frame: InboundFrame } | { kind: "json"; reply: JsonReply };
type Session = { dialer: ControlDialer; options: ConnectOptions; json: JsonSession; framed?: ControlClient; closed: AbortController; capabilities: Readonly<Capabilities> };

/** Shared automatic discovery; JSON and CBOR keep their actual reply formats. */
export class ControlConnection {
  private constructor(private readonly session: Session) {}
  static connectConnector(connector: Connector, options: ConnectOptions = {}): Promise<ControlConnection> {
    return this.establish({ connector }, options);
  }
  static connectVerifiedConnector(connector: VerifiedControlConnector, options: ConnectOptions = {}): Promise<ControlConnection> {
    return this.establish({ connector, verifier: connector }, options);
  }
  private static async establish(dialer: ControlDialer, options: ConnectOptions): Promise<ControlConnection> {
    const json = new JsonSession(dialer, options, true);
    const attempt = new ControlAttempt(options.setupTimeoutMs ?? DEFAULT_SETUP_TIMEOUT_MS, [options.signal]);
    let framed: ControlClient | undefined;
    let transport: ByteTransport | undefined;
    try {
      const { mode, capabilities } = await json.discover(attempt);
      if (mode === "cbor") {
        // Discovery finishes and closes its JSON stream. Positive advertisement
        // requires a fresh framed handshake; failures must never downgrade.
        transport = await attempt.connect(dialer.connector);
        if (dialer.verifier) await attempt.run(() => dialer.verifier!.verifySession(attempt.context));
        const protocol = new ControlProtocol(), owned = transport;
        const established = await attempt.run(() => protocol.establish(owned, { ...attempt.context, limits: defaultLimits(json.options.limits) }));
        attempt.check();
        framed = await Client.fromEstablished(protocol, established);
        transport = undefined; // The generic reader/writer now own the stream.
      }
      attempt.check();
      return new ControlConnection({ dialer, options: json.options, json, framed, closed: new AbortController(), capabilities: Object.freeze(capabilities) });
    } catch (error) {
      if (transport) await closeTransport(transport);
      await framed?.close(); await json.close();
      const failure = controlError(error);
      throw failure instanceof ClientError ? failure.withDelivery("not_sent") : failure;
    } finally { attempt.dispose(); }
  }
  clone(): ControlConnection { return new ControlConnection(this.session); }
  get mode(): ControlMode { return this.session.framed ? "cbor" : "json"; }
  /** Validated discovery snapshot; GetCapabilities explicitly requests a fresh observation. */
  get capabilities(): Readonly<Capabilities> { return this.session.capabilities; }
  isClosed(): boolean { return this.session.json.isClosed() || (this.session.framed?.isClosed() ?? false); }
  framed(): ControlClient {
    if (!this.session.framed) throw new ControlClientError("unsupported_mode");
    return this.session.framed;
  }
  async close(): Promise<void> {
    this.session.closed.abort(new ClientError("closed"));
    await Promise.all([this.session.json.close(), this.session.framed?.close()]);
  }
  async request(message: OutboundMessage, options: RequestOptions = {}): Promise<ControlReply> {
    if (!this.session.framed) return { kind: "json", reply: await this.session.json.operation(nativeJsonRequest(message), options) };
    return { kind: "cbor", frame: await this.framedOperation(options, remaining => this.session.framed!.request(message, remaining)) };
  }
  async requestTyped<T>(request: CheckedControlRequest<T>, options: RequestOptions = {}): Promise<T> {
    if (!this.session.framed) return request.decodeJson(await this.session.json.operation(request.jsonRequest(), options));
    return this.framedOperation(options, remaining => this.session.framed!.requestTyped(request, remaining));
  }
  private async framedOperation<T>(options: RequestOptions, operation: (options: RequestOptions) => Promise<T>): Promise<T> {
    if (this.isClosed()) throw new ClientError("closed");
    const attempt = new ControlAttempt(options.requestTimeoutMs ?? this.session.options.limits?.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS, [options.signal, this.session.closed.signal]);
    try {
      try {
        const verifier = this.session.dialer.verifier;
        if (verifier) await attempt.run(() => verifier.verifySession(attempt.context));
        attempt.check();
        if (this.isClosed()) throw new ClientError("closed");
      } catch (error) {
        await this.close();
        const failure = controlError(error);
        throw failure instanceof ClientError ? failure.withDelivery("not_sent") : failure;
      }
      return await operation({ ...options, signal: attempt.signal, requestTimeoutMs: attempt.remaining() });
    } finally { attempt.dispose(); }
  }
}
