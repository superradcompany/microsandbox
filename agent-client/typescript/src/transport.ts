import type { TransportPacket } from "./packet.js";

/**
 * Bidirectional byte/packet transport for the agent protocol.
 *
 * Implementations may be byte streams, message-oriented transports, or test
 * harnesses. The client uses `readBytes` for the initial relay handshake and
 * `readPacket`/`writePacket` after the handshake completes.
 */
export interface AgentTransport {
  /**
   * Read exactly `length` bytes or reject if the transport closes first.
   */
  readBytes(length: number): Promise<Uint8Array>;
  /**
   * Read the next complete transport packet.
   *
   * Return `null` when the transport reaches a clean EOF.
   */
  readPacket(): Promise<TransportPacket | null>;
  /**
   * Write one complete transport packet.
   */
  writePacket(packet: TransportPacket): Promise<void>;
  /**
   * Close the underlying transport.
   */
  close(): Promise<void>;
}
