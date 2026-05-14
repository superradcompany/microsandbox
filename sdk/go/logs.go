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
}

// Text returns the log payload as a string.
func (e LogEntry) Text() string { return string(e.Data) }

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

func logEntriesFromFFI(entries []ffi.LogEntry) ([]LogEntry, error) {
	out := make([]LogEntry, 0, len(entries))
	for _, entry := range entries {
		data, err := base64.StdEncoding.DecodeString(entry.DataB64)
		if err != nil {
			return nil, err
		}
		out = append(out, LogEntry{
			Source:    LogSource(entry.Source),
			SessionID: entry.SessionID,
			Timestamp: time.UnixMilli(entry.TimestampMs),
			Data:      data,
		})
	}
	return out, nil
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
