import type { RawStream, Stream } from "@microsandbox/protocol-client";
import type { AgentProtocol } from "./protocol.js";

/** Owned agent message subscription, with native sends and optional split ownership. */
export type AgentStream = Stream<AgentProtocol>;
/** Owned opaque agent frame subscription. */
export type RawAgentStream = RawStream<AgentProtocol>;
export { Stream, RawStream, StreamSender, StreamReceiver, RawStreamSender, RawStreamReceiver } from "@microsandbox/protocol-client";
