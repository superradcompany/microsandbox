import {
  CborEnvelopeCodec, ClientError, encodeEnvelope, encodeFrame, encodeRecord, readExactly,
  type ByteTransport, type EstablishContext, type Established, type InboundFrame, type Protocol,
  type RawFrame, type SendMetadata,
} from "@microsandbox/protocol-client";
import {
  DEFAULT_SUPERVISOR_REQUEST_TIMEOUT_MS, DEFAULT_SUPERVISOR_SETUP_TIMEOUT_MS,
  MAX_SUPERVISOR_HANDSHAKE_FRAME_SIZE, SUPERVISOR_HANDSHAKE_GENERATION, SUPERVISOR_MAGIC,
  decodeSupervisorError, decodeWelcome, validateHello, type SupervisorHello, type SupervisorWelcome,
} from "./records.js";

export type SupervisorReady = { welcome: SupervisorWelcome; frame: InboundFrame };

/** Configured MSBS setup followed by the common framed router. */
export class SupervisorProtocol implements Protocol<SupervisorReady> {
  constructor(readonly hello: SupervisorHello) { validateHello(hello); }

  async establish(transport: ByteTransport, context: EstablishContext): Promise<Established<SupervisorReady>> {
    const opening = encodeFrame({ id: 0, flags: 0, body: encodeEnvelope({
      v: SUPERVISOR_HANDSHAKE_GENERATION, t: "supervisor.hello", p: encodeRecord(this.hello),
    }) });
    if (opening.length - 4 > MAX_SUPERVISOR_HANDSHAKE_FRAME_SIZE) throw new ClientError("invalid_options");
    await transport.write(SUPERVISOR_MAGIC);
    await transport.write(opening);
    const prefix = await readExactly(transport, 4, context.signal);
    const length = new DataView(prefix.buffer, prefix.byteOffset, prefix.byteLength).getUint32(0);
    if (length < 5 || length > MAX_SUPERVISOR_HANDSHAKE_FRAME_SIZE) throw new ClientError("invalid_data");
    const header = await readExactly(transport, 5, context.signal);
    const body = await readExactly(transport, length - 5, context.signal);
    const raw: RawFrame = {
      id: new DataView(header.buffer, header.byteOffset, header.byteLength).getUint32(0),
      flags: header[4]!, body,
    };
    const codec = new CborEnvelopeCodec();
    const frame = codec.decode(raw);
    if (frame.id !== 0 || frame.flags !== 1 || frame.protocolVersion !== SUPERVISOR_HANDSHAKE_GENERATION) throw new ClientError("invalid_data");
    if (frame.type === "supervisor.error") {
      const refusal = decodeSupervisorError(frame.payload);
      throw new ClientError(refusal.code === "unsupported_generation" ? "unsupported_operation" : "invalid_data");
    }
    if (frame.type !== "supervisor.welcome") throw new ClientError("invalid_data");
    const welcome = decodeWelcome(frame.payload, this.hello);
    return {
      transport, codec, ids: { start: 1, endExclusive: 0x100000000 }, ready: { welcome, frame },
      limits: {
        ...context.limits, maxFrameSize: welcome.effective_limits.max_frame_size,
        maxInFlight: welcome.effective_limits.max_in_flight,
        incompleteFrameTimeoutMs: context.limits.incompleteFrameTimeoutMs ?? DEFAULT_SUPERVISOR_SETUP_TIMEOUT_MS,
        requestTimeoutMs: context.limits.requestTimeoutMs ?? DEFAULT_SUPERVISOR_REQUEST_TIMEOUT_MS,
      },
    };
  }

  prepare(ready: SupervisorReady, wireName: string): SendMetadata {
    if (wireName === "supervisor.hello" || wireName === "supervisor.welcome") throw new ClientError("unsupported_operation");
    return { generation: ready.welcome.generation, flags: 0 };
  }
}
