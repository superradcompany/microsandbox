import {
  CborEnvelopeCodec, ClientError, encodeEnvelope, encodeFrame, encodeRecord, readExactly,
  type ByteTransport, type EstablishContext, type Established, type InboundFrame, type Protocol,
  type SendMetadata, type RawFrame,
} from "@microsandbox/protocol-client";
import {
  CONTROL_GENERATION, CONTROL_PROTOCOL, DEFAULT_MAX_IN_FLIGHT, DEFAULT_REQUEST_TIMEOUT_MS,
  DEFAULT_SETUP_TIMEOUT_MS, MAX_HANDSHAKE_FRAME_SIZE, decodeControlError, decodeWelcome,
  validateHello, type ControlHello, type ControlWelcome,
} from "./records.js";

/** Setup metadata retains the original welcome envelope and all unknown fields. */
export type ControlReady = { welcome: ControlWelcome; frame: InboundFrame };

/** Explicit framed setup; discovery and JSON adaptation belong outside this engine. */
export class ControlProtocol implements Protocol<ControlReady> {
  async establish(transport: ByteTransport, context: EstablishContext): Promise<Established<ControlReady>> {
    const hello: ControlHello = {
      protocol: CONTROL_PROTOCOL, min_generation: CONTROL_GENERATION, max_generation: CONTROL_GENERATION,
      max_frame_size: context.limits.maxFrameSize,
      max_in_flight: Math.min(context.limits.maxInFlight, DEFAULT_MAX_IN_FLIGHT),
    };
    try { validateHello(hello); } catch { throw new ClientError("invalid_options"); }
    await transport.write(encodeFrame({ id: 0, flags: 0, body: encodeEnvelope({
      v: CONTROL_GENERATION, t: "control.hello", p: encodeRecord(hello),
    }) }));
    const prefix = await readExactly(transport, 4, context.signal);
    const length = new DataView(prefix.buffer, prefix.byteOffset, prefix.byteLength).getUint32(0);
    // Reject hostile opening lengths before allocating or waiting for the body.
    if (length < 5 || length > MAX_HANDSHAKE_FRAME_SIZE) throw new ClientError("invalid_data");
    const header = await readExactly(transport, 5, context.signal);
    const body = await readExactly(transport, length - 5, context.signal);
    const codec = new CborEnvelopeCodec();
    const { frame, welcome } = decodeOpening(codec, { id: new DataView(header.buffer).getUint32(0), flags: header[4]!, body }, hello);
    return {
      transport, codec, ids: { start: 1, endExclusive: 0x100000000 }, ready: { welcome, frame },
      limits: {
        ...context.limits, maxFrameSize: welcome.max_frame_size, maxInFlight: welcome.max_in_flight,
        incompleteFrameTimeoutMs: context.limits.incompleteFrameTimeoutMs ?? DEFAULT_SETUP_TIMEOUT_MS,
        requestTimeoutMs: context.limits.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS,
      },
    };
  }
  prepare(ready: ControlReady, wireName: string): SendMetadata {
    if (wireName === "control.hello" || wireName === "control.welcome") throw new ClientError("unsupported_operation");
    return { generation: ready.welcome.generation, flags: 0 };
  }
}

function decodeOpening(codec: CborEnvelopeCodec, raw: RawFrame, hello: ControlHello): ControlReady {
  try {
    const frame = codec.decode(raw);
    if (frame.id !== 0 || frame.flags !== 1 || frame.protocolVersion !== CONTROL_GENERATION) throw new ClientError("invalid_data");
    if (frame.type === "control.error") {
      const refusal = decodeControlError(frame.payload);
      throw new ClientError(refusal.code === "unsupported_generation" ? "unsupported_operation" : "invalid_data");
    }
    if (frame.type !== "control.welcome") throw new ClientError("invalid_data");
    return { frame, welcome: decodeWelcome(frame.payload, hello) };
  } catch (error) {
    // Decoder failures describe peer data, not socket I/O. Keep diagnostics
    // sanitized and preserve an explicit unsupported-generation refusal.
    if (error instanceof ClientError) throw error;
    throw new ClientError("invalid_data");
  }
}
