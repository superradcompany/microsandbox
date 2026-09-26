/** Browser-safe supervisor protocol; native endpoint dialing lives in /node. */
export * from "./client.js";
export * from "./protocol.js";
export * from "./records.js";
export * from "./request.js";
export * from "./error.js";
export {
  Client, ClientError, InboundFrame, typedMessage, encodedMessage,
  type ByteTransport, type Connector, type ConnectOptions, type RequestOptions,
  type RawFrame, type TypedMessage, type EncodedMessage, type Request,
} from "@microsandbox/protocol-client";
