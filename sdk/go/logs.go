package microsandbox

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// LogSource identifies where a persisted sandbox log entry came from.
type LogSource string

const (
	LogSourceStdout LogSource = "stdout"
	LogSourceStderr LogSource = "stderr"
	LogSourceOutput LogSource = "output"
	LogSourceSystem LogSource = "system"
)

// LogOptions filters persisted sandbox logs. Zero values read the default
// stdout and stderr sources.
type LogOptions struct {
	Tail    uint64
	Since   time.Time
	Until   time.Time
	Sources []LogSource
}

// LogEntry is one persisted sandbox log entry.
type LogEntry struct {
	Source    LogSource
	SessionID *uint64
	Timestamp time.Time
	Data      []byte
	// Cursor is an opaque resume token. Pass to LogStreamOptions.FromCursor
	// to resume a stream strictly after this entry.
	Cursor string
}

// Text returns the log payload as a string.
func (e LogEntry) Text() string { return string(e.Data) }

// LogStreamOptions configures a live log stream. The zero value reads the
// default stdout+stderr+output sources from the beginning, with follow off.
//
// Since and FromCursor are mutually exclusive — passing both rejects at the
// boundary.
type LogStreamOptions struct {
	// Sources to include. Empty means the default set
	// (stdout + stderr + output). Add LogSourceSystem for
	// runtime/kernel diagnostics.
	Sources []LogSource
	// Start at the first entry whose timestamp is >= Since.
	// Mutually exclusive with FromCursor.
	Since time.Time
	// Resume strictly after the entry whose Cursor matches this value.
	// Mutually exclusive with Since.
	FromCursor string
	// Stop emitting at the first entry whose timestamp is >= Until.
	Until time.Time
	// When true, keep the stream open past current EOF and yield new
	// entries as they are written.
	Follow bool
}

func logOptionsToFFI(opts LogOptions) ffi.LogOptions {
	out := ffi.LogOptions{
		Tail:    opts.Tail,
		Sources: make([]string, 0, len(opts.Sources)),
	}
	if !opts.Since.IsZero() {
		ms := opts.Since.UnixMilli()
		out.SinceMs = &ms
	}
	if !opts.Until.IsZero() {
		ms := opts.Until.UnixMilli()
		out.UntilMs = &ms
	}
	for _, source := range opts.Sources {
		out.Sources = append(out.Sources, string(source))
	}
	return out
}

func logEntryFromFFI(entry ffi.LogEntry) (LogEntry, error) {
	data, err := base64.StdEncoding.DecodeString(entry.DataB64)
	if err != nil {
		return LogEntry{}, err
	}
	return LogEntry{
		Source:    LogSource(entry.Source),
		SessionID: entry.SessionID,
		Timestamp: time.UnixMilli(entry.TimestampMs),
		Data:      data,
		Cursor:    entry.Cursor,
	}, nil
}

func logEntriesFromFFI(entries []ffi.LogEntry) ([]LogEntry, error) {
	out := make([]LogEntry, 0, len(entries))
	for _, entry := range entries {
		e, err := logEntryFromFFI(entry)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

func logStreamOptionsToFFI(opts LogStreamOptions) ffi.LogStreamOptions {
	out := ffi.LogStreamOptions{
		Sources: make([]string, 0, len(opts.Sources)),
		Follow:  opts.Follow,
	}
	if !opts.Since.IsZero() {
		ms := opts.Since.UnixMilli()
		out.SinceMs = &ms
	}
	if opts.FromCursor != "" {
		s := opts.FromCursor
		out.FromCursor = &s
	}
	if !opts.Until.IsZero() {
		ms := opts.Until.UnixMilli()
		out.UntilMs = &ms
	}
	for _, source := range opts.Sources {
		out.Sources = append(out.Sources, string(source))
	}
	return out
}

// Logs reads persisted output for this live sandbox. It works for running and
// stopped sandboxes and does not require guest-agent protocol traffic.
func (s *Sandbox) Logs(ctx context.Context, opts LogOptions) ([]LogEntry, error) {
	entries, err := s.inner.SandboxLogs(ctx, logOptionsToFFI(opts))
	if err != nil {
		return nil, wrapFFI(err)
	}
	return logEntriesFromFFI(entries)
}

// Logs reads persisted output for this sandbox handle. It works without
// starting or connecting to the sandbox.
func (h *SandboxHandle) Logs(ctx context.Context, opts LogOptions) ([]LogEntry, error) {
	entries, err := ffi.SandboxHandleLogs(ctx, h.name, logOptionsToFFI(opts))
	if err != nil {
		return nil, wrapFFI(err)
	}
	return logEntriesFromFFI(entries)
}

// LogStreamHandle is a live log subscription. Obtain via
// Sandbox.LogStream or SandboxHandle.LogStream. Call Close to release
// Rust-side resources.
type LogStreamHandle struct {
	inner *ffi.LogStreamHandle
}

// Recv blocks until the next log entry arrives or ctx is cancelled.
// Returns nil, nil when the stream has ended (snapshot drained, Until
// reached, or a fatal stream error has already been surfaced).
func (h *LogStreamHandle) Recv(ctx context.Context) (*LogEntry, error) {
	raw, err := h.inner.Recv(ctx)
	if err != nil {
		return nil, wrapFFI(err)
	}
	if raw == nil {
		return nil, nil
	}
	entry, err := logEntryFromFFI(*raw)
	if err != nil {
		return nil, err
	}
	return &entry, nil
}

// Close stops the stream and releases Rust-side resources.
func (h *LogStreamHandle) Close() error {
	return wrapFFI(h.inner.Close())
}

// LogStream starts a streaming log subscription against a live sandbox.
// Pass LogStreamOptions{Follow: true} to keep the stream open past
// current EOF and pick up new entries as they are written. Close the
// returned handle when done.
func (s *Sandbox) LogStream(ctx context.Context, opts LogStreamOptions) (*LogStreamHandle, error) {
	h, err := s.inner.LogStream(ctx, logStreamOptionsToFFI(opts))
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &LogStreamHandle{inner: h}, nil
}

// LogStream starts a streaming log subscription for this sandbox handle.
// Works without starting or connecting to the sandbox; with
// LogStreamOptions{Follow: true}, the stream picks up new entries the
// moment they land in exec.log.
func (h *SandboxHandle) LogStream(
	ctx context.Context,
	opts LogStreamOptions,
) (*LogStreamHandle, error) {
	inner, err := ffi.SandboxHandleLogStream(ctx, h.name, logStreamOptionsToFFI(opts))
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &LogStreamHandle{inner: inner}, nil
}
