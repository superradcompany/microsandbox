import type { ConnectOptions, Connector, OutboundMessage, RequestOptions } from "@microsandbox/protocol-client";
import { JsonSession } from "./json-session.js";
import { nativeJsonRequest, type CheckedControlRequest } from "./legacy-request.js";
import type { JsonReply } from "./json-reply.js";

/** Explicit JSON unary adapter. Construction is inert and never probes. */
export class JsonControlClient {
  private constructor(private readonly session: JsonSession) {}
  static fromConnector(connector: Connector, options: ConnectOptions = {}): JsonControlClient {
    return new JsonControlClient(new JsonSession({ connector }, options, false));
  }
  clone(): JsonControlClient { return new JsonControlClient(this.session); }
  isClosed(): boolean { return this.session.isClosed(); }
  close(): Promise<void> { return this.session.close(); }
  async request(message: OutboundMessage, options?: RequestOptions): Promise<JsonReply> {
    return this.session.operation(nativeJsonRequest(message), options);
  }
  async requestTyped<T>(request: CheckedControlRequest<T>, options?: RequestOptions): Promise<T> {
    return request.decodeJson(await this.session.operation(request.jsonRequest(), options));
  }
}
