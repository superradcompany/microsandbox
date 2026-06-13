package microsandbox

import (
	"context"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// Raw frame flags used by the agent protocol.
const (
	FlagTerminal     uint8 = 0b0000_0001
	FlagSessionStart uint8 = 0b0000_0010
	FlagShutdown     uint8 = 0b0000_0100
)

// Cross-SDK aliases matching the TypeScript and Python constant spellings.
const (
	FLAG_TERMINAL      = FlagTerminal
	FLAG_SESSION_START = FlagSessionStart
	FLAG_SHUTDOWN      = FlagShutdown
)

// RawFrame is a raw agent protocol frame.
//
// Body is the CBOR-encoded Message body as it appeared on the wire. Decode it
// in user code with a CBOR library such as fxamacker/cbor.
type RawFrame struct {
	ID    uint32
	Flags uint8
	Body  []byte
}

// AgentClient is a low-level raw client for talking to agentd through the
// sandbox relay socket.
type AgentClient struct {
	inner *ffi.AgentClient
}

// AgentStream is an open raw streaming session.
type AgentStream struct {
	id    uint32
	inner *ffi.AgentStreamHandle
}

// ConnectAgentSandbox connects to a running sandbox by name.
// Sandbox names are limited to 128 UTF-8 bytes.
// Use context.WithTimeout to override the default 10s handshake timeout.
func ConnectAgentSandbox(ctx context.Context, name string) (*AgentClient, error) {
	inner, err := ffi.OpenAgentSandbox(ctx, name)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &AgentClient{inner: inner}, nil
}

// ConnectAgentPath connects to an agentd relay socket by path.
// Use context.WithTimeout to override the default 10s handshake timeout.
func ConnectAgentPath(ctx context.Context, path string) (*AgentClient, error) {
	inner, err := ffi.OpenAgentPath(ctx, path)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &AgentClient{inner: inner}, nil
}

// AgentSocketPath returns the host-side filesystem path of a sandbox's agentd
// relay socket, resolved the same way ConnectAgentSandbox dials it internally
// (preferring the hashed path, falling back to the legacy name-derived path).
//
// Use this when you need to talk to agentd over a raw byte transport — for
// example a transparent relay that splices bytes between a WebSocket and the
// socket — rather than the frame-protocol AgentClient that Connect* returns.
// The sandbox need not be running; the path is derived from the name and the
// configured home directory.
func AgentSocketPath(name string) (string, error) {
	path, err := ffi.AgentSocketPath(name)
	if err != nil {
		return "", wrapFFI(err)
	}
	return path, nil
}

// Request sends one raw frame and awaits one response frame.
func (c *AgentClient) Request(ctx context.Context, flags uint8, body []byte) (*RawFrame, error) {
	frame, err := c.inner.Request(ctx, flags, body)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return frameFromFFI(frame), nil
}

// Stream opens a raw streaming session.
func (c *AgentClient) Stream(ctx context.Context, flags uint8, body []byte) (*AgentStream, error) {
	id, stream, err := c.inner.StreamOpen(ctx, flags, body)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &AgentStream{id: id, inner: stream}, nil
}

// Next pulls the next frame from the stream. It returns nil, nil at EOF.
func (s *AgentStream) Next(ctx context.Context) (*RawFrame, error) {
	frame, err := s.inner.StreamNext(ctx)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return frameFromFFI(frame), nil
}

// ID returns the protocol correlation id for this stream. Pass it to
// AgentClient.Send for follow-up frames in the session.
func (s *AgentStream) ID() uint32 {
	return s.id
}

// Close releases the stream handle.
func (s *AgentStream) Close(ctx context.Context) error {
	return wrapFFI(s.inner.Close(ctx))
}

// Send sends a follow-up frame on an existing correlation id.
func (c *AgentClient) Send(ctx context.Context, id uint32, flags uint8, body []byte) error {
	return wrapFFI(c.inner.Send(ctx, id, flags, body))
}

// ReadyBytes returns the cached handshake core.ready CBOR body.
func (c *AgentClient) ReadyBytes() ([]byte, error) {
	body, err := c.inner.ReadyBytes()
	if err != nil {
		return nil, wrapFFI(err)
	}
	return body, nil
}

// Close releases the client handle. It is safe to call more than once.
func (c *AgentClient) Close() error {
	return wrapFFI(c.inner.Close())
}

// CloseCtx is Close with a caller-controlled context.
func (c *AgentClient) CloseCtx(ctx context.Context) error {
	return wrapFFI(c.inner.CloseCtx(ctx))
}

func frameFromFFI(frame *ffi.AgentFrame) *RawFrame {
	if frame == nil {
		return nil
	}
	return &RawFrame{
		ID:    frame.ID,
		Flags: frame.Flags,
		Body:  frame.Body,
	}
}
