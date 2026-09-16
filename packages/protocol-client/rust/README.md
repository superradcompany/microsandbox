# Generic framed client

`Client<P>` owns one byte connection, its correlation IDs, and all routed subscriptions. `P: Protocol` establishes the transport and selects message metadata and an `EnvelopeCodec`. Protocol consumers can implement both traits outside this crate. `tests/engine.rs` exercises external protocol setup and routing, while `tests/external_codec.rs` supplies an external connector and a non-CBOR envelope codec across native, encoded, raw, checked, stream, explicit-ID, and exact-packet calls. Rust native payload serialization remains CBOR; the custom codec controls its enclosing envelope, and encoded/raw paths retain caller-supplied bytes.

```text
native payload ---- TypedMessage ---+
encoded payload --- EncodedMessage -+--> codec --> shared writer
raw envelope -----------------------+-----------> shared writer
exact packet -----------------------------------> shared writer

shared reader --> ID routing --> RawStream --> Stream (decode on recv)
```

`request` returns the first response. If it is not terminal, the router retains the ID and discards later replies until terminal completion. `request_typed` additionally requires a terminal response and invokes a borrowed `Request<P>` implementation's checked decoder. Application errors remain that implementation's responsibility; the generic engine does not equate a terminal response with success.

`stream` and `stream_raw` return owned subscriptions. `into_parts()` moves them into a cloneable sender and one receiver. Both retain the connection. Dropping or closing the receiver disables sends and drains any admitted operation until terminal completion; it does not send a process signal, file EOF, TCP close, or cancellation packet. Old sender handles cannot gain permission when an ID is reused.

`send` and `send_raw` support explicit IDs owned by the connection. `write_unchecked` serializes caller-owned packet bytes without creating an ID or response subscription. Native and encoded-payload paths apply protocol availability gates; raw paths preserve opaque bytes. A decoded `Message` retains its original `RawFrame`, including unknown envelope fields.

Connections are shared handles. Explicit `close(&self)` closes every handle and wakes waiters. `closed().await` observes closure, including idle peer disconnection, without polling; canceling that wait leaves the connection alone. Last-owner drop closes the transport; the reader and writer do not keep the owner alive. A stream remains an owner after a temporary client handle is dropped.

Queues have item and combined byte limits. A retained slow receiver can backpressure the whole connection; fair per-stream flow control is not provided by the wire protocol. Dropping that receiver releases its queued frames and wakes blocked routing. Active and draining IDs both consume in-flight capacity.

`ClientError.delivery` distinguishes `NotSent` before writer admission from `Unknown` afterward. Timeouts and dropped futures stop local waiting, without retrying or undoing peer work. An EOF before terminal completion is an error; truncation inside a frame is reported separately. Optional incomplete-frame deadlines start at the first byte and do not expire idle connections.

The `uds` and `named-pipe` features enable `LocalConnector` on their platforms. It uses the endpoint supplied by the caller without inventing names. A custom `Connector` receives an absolute setup deadline and returns an exclusively owned byte stream. `connect_stream` accepts a transport that the caller has already dialed and authenticated.

Validation: `cargo test -p microsandbox-protocol-client --all-features --locked`. The Unix connector test binds a temporary socket and therefore needs an execution environment that permits local socket creation.

Protocols choose whether completed correlation IDs may be reused. Agent connections retire IDs for the lifetime of the connection, matching the relay; control connections may reuse an ID after its terminal response. Exhaustion is a local error and does not reconnect or replay a request.
