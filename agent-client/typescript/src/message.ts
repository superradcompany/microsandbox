import { encode } from "cbor-x";

/** Current microsandbox agent protocol generation. */
export const PROTOCOL_VERSION = 5;
/** Frame flag marking the final frame for a correlation ID. */
export const FLAG_TERMINAL = 0b0000_0001;
/** Frame flag marking the first frame of a new session. */
export const FLAG_SESSION_START = 0b0000_0010;
/** Frame flag requesting sandbox shutdown. */
export const FLAG_SHUTDOWN = 0b0000_0100;

/**
 * Known microsandbox agent protocol message type wire strings.
 */
export type MessageType =
  | "core.ready"
  | "core.init.resolved"
  | "core.init.ack"
  | "core.shutdown"
  | "core.relay.client.disconnected"
  | "core.clock.sync"
  | "core.error"
  | "core.exec.request"
  | "core.exec.started"
  | "core.exec.stdin"
  | "core.exec.stdin.error"
  | "core.exec.stdout"
  | "core.exec.stderr"
  | "core.exec.exited"
  | "core.exec.failed"
  | "core.exec.resize"
  | "core.exec.signal"
  | "core.fs.request"
  | "core.fs.response"
  | "core.fs.data"
  | "core.tcp.connect"
  | "core.tcp.connected"
  | "core.tcp.data"
  | "core.tcp.eof"
  | "core.tcp.close"
  | "core.tcp.closed"
  | "core.tcp.failed";

/**
 * Outbound message whose payload should be CBOR-encoded by this package.
 */
export type TypedMessage<T = unknown> = {
  /** Discriminant for `OutboundMessage`. */
  kind: "typed";
  /** Protocol message type. */
  type: MessageType;
  /** Native payload object to CBOR-encode into the message envelope. */
  payload: T;
};

/**
 * Outbound message whose payload is already CBOR-encoded.
 */
export type EncodedMessage = {
  /** Discriminant for `OutboundMessage`. */
  kind: "encoded";
  /** Protocol message type. */
  type: MessageType;
  /** CBOR-encoded payload bytes for this message type. */
  payload: Uint8Array;
};

/** Message accepted by `AgentClient` send/request APIs. */
export type OutboundMessage = TypedMessage | EncodedMessage;

/** Decoded CBOR protocol envelope carried inside a transport frame. */
export type EncodedEnvelope = {
  /** Protocol generation. */
  v: number;
  /** Wire message type. */
  t: MessageType;
  /** CBOR-encoded message payload bytes. */
  p: Uint8Array;
};

/**
 * Build a typed outbound message.
 *
 * Use this when the agent-client package should CBOR-encode the payload.
 */
export function typedMessage<T>(
  type: MessageType,
  payload: T,
): TypedMessage<T> {
  return { kind: "typed", type, payload };
}

/**
 * Build an encoded outbound message.
 *
 * Use this when another layer already produced CBOR payload bytes.
 */
export function encodedMessage(
  type: MessageType,
  payload: Uint8Array,
): EncodedMessage {
  return { kind: "encoded", type, payload };
}

/**
 * Return the CBOR payload bytes for a typed or encoded outbound message.
 */
export function encodePayload(message: OutboundMessage): Uint8Array {
  if (message.kind === "encoded") {
    return message.payload;
  }
  return encode(message.payload);
}

/**
 * Encode an outbound message into a CBOR protocol envelope body.
 *
 * The returned `body` is the bytes that belong after the binary frame header.
 * The caller is still responsible for assigning a correlation ID.
 */
export function encodeEnvelope(
  message: OutboundMessage,
  protocolVersion = PROTOCOL_VERSION,
  negotiatedVersion = PROTOCOL_VERSION,
): { type: MessageType; flags: number; body: Uint8Array } {
  if (!supports(message.type, negotiatedVersion)) {
    throw new Error(
      `the sandbox runtime is too old for '${message.type}' ` +
        `(needs protocol generation ${minProtocolVersion(message.type)}, ` +
        `the sandbox speaks ${negotiatedVersion})`,
    );
  }

  const flags = messageFlags(message.type);
  const envelope: EncodedEnvelope = {
    v: protocolVersion,
    t: message.type,
    p: encodePayload(message),
  };
  return {
    type: message.type,
    flags,
    body: encode(envelope),
  };
}

/**
 * Return the frame flags required for a message type.
 */
export function messageFlags(type: MessageType): number {
  switch (type) {
    case "core.error":
    case "core.exec.exited":
    case "core.exec.failed":
    case "core.fs.response":
    case "core.tcp.closed":
    case "core.tcp.failed":
      return FLAG_TERMINAL;
    case "core.exec.request":
    case "core.fs.request":
    case "core.tcp.connect":
      return FLAG_SESSION_START;
    case "core.shutdown":
      return FLAG_SHUTDOWN;
    default:
      return 0;
  }
}

/**
 * Return the protocol generation that introduced a message type.
 */
export function minProtocolVersion(type: MessageType): number {
  switch (type) {
    case "core.fs.request":
    case "core.fs.response":
    case "core.fs.data":
      return 2;
    case "core.tcp.connect":
    case "core.tcp.connected":
    case "core.tcp.data":
    case "core.tcp.eof":
    case "core.tcp.close":
    case "core.tcp.closed":
    case "core.tcp.failed":
      return 4;
    case "core.error":
      return 5;
    default:
      return 1;
  }
}

/**
 * Return whether a peer generation supports a message type.
 */
export function supports(type: MessageType, peerGeneration: number): boolean {
  return minProtocolVersion(type) <= peerGeneration;
}
