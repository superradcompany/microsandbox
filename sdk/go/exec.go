package microsandbox

import (
	"context"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// timeoutSecsCeil rounds a Duration up to whole seconds. The FFI boundary
// carries timeouts as uint64 seconds, so any positive sub-second Duration
// must round to at least 1 — truncation would drop it to 0, which the Rust
// side interprets as "no timeout" (the opposite of the caller's intent).
func timeoutSecsCeil(d time.Duration) uint64 {
	if d <= 0 {
		return 0
	}
	return uint64((d + time.Second - 1) / time.Second)
}

// ExecOutput is the collected result of a command execution.
//
// A non-zero ExitCode is NOT treated as a Go error — callers inspect
// Success or ExitCode explicitly, matching how os/exec.Cmd.Output works
// against a script that exits non-zero.
type ExecOutput struct {
	stdout   []byte
	stderr   []byte
	exitCode int
}

// Stdout returns captured standard output as a string.
func (e *ExecOutput) Stdout() string { return string(e.stdout) }

// StdoutBytes returns captured standard output as bytes.
func (e *ExecOutput) StdoutBytes() []byte { return e.stdout }

// Stderr returns captured standard error as a string.
func (e *ExecOutput) Stderr() string { return string(e.stderr) }

// StderrBytes returns captured standard error as bytes.
func (e *ExecOutput) StderrBytes() []byte { return e.stderr }

// ExitCode returns the process's exit code, or -1 if the guest did not
// report one (e.g. the process was killed by a signal).
func (e *ExecOutput) ExitCode() int { return e.exitCode }

// Success reports whether the command exited with code 0.
func (e *ExecOutput) Success() bool { return e.exitCode == 0 }

// Exec runs a command in the sandbox and returns its collected output.
// The returned error is non-nil only on transport/runtime failures; a
// non-zero exit code is reported via ExecOutput.ExitCode, not as an error.
func (s *Sandbox) Exec(ctx context.Context, cmd string, args []string, opts ...ExecOption) (*ExecOutput, error) {
	o := ExecConfig{}
	for _, opt := range opts {
		opt(&o)
	}

	ffiOpts := ffi.ExecOptions{Args: args, Cwd: o.Cwd}
	if o.Timeout > 0 {
		ffiOpts.TimeoutSecs = timeoutSecsCeil(o.Timeout)
	}

	res, err := s.inner.Exec(ctx, cmd, ffiOpts)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &ExecOutput{
		stdout:   []byte(res.Stdout),
		stderr:   []byte(res.Stderr),
		exitCode: res.ExitCode,
	}, nil
}

// Shell runs `/bin/sh -c command` in the sandbox.
func (s *Sandbox) Shell(ctx context.Context, command string, opts ...ExecOption) (*ExecOutput, error) {
	return s.Exec(ctx, "/bin/sh", []string{"-c", command}, opts...)
}

// ExecEventKind identifies what an ExecEvent carries.
type ExecEventKind = ffi.ExecEventKind

const (
	// ExecEventStarted is sent once when the guest process starts.
	ExecEventStarted ExecEventKind = ffi.ExecEventStarted
	// ExecEventStdout carries a chunk of standard output.
	ExecEventStdout ExecEventKind = ffi.ExecEventStdout
	// ExecEventStderr carries a chunk of standard error.
	ExecEventStderr ExecEventKind = ffi.ExecEventStderr
	// ExecEventExited is sent when the process exits. ExitCode is valid.
	ExecEventExited ExecEventKind = ffi.ExecEventExited
	// ExecEventDone signals that all events have been consumed.
	ExecEventDone ExecEventKind = ffi.ExecEventDone
)

// ExecEvent is one event from a streaming exec session.
type ExecEvent struct {
	// Kind identifies which fields are populated.
	Kind ExecEventKind

	// PID is the guest process ID. Populated on ExecEventStarted.
	PID uint32

	// Data is a chunk of stdout or stderr bytes. Populated on ExecEventStdout
	// and ExecEventStderr.
	Data []byte

	// ExitCode is the process exit code. Populated on ExecEventExited.
	ExitCode int
}

// ExecSink is a write-only pipe to a running process's stdin. Obtain via
// ExecHandle.TakeStdin. Implements io.WriteCloser.
type ExecSink = ffi.ExecSink

// ExecHandle is a live streaming exec session. Obtain via Sandbox.ExecStream.
// Call Close when done to release Rust-side resources.
//
// ExecHandle is NOT safe for concurrent use from multiple goroutines.
type ExecHandle struct {
	inner *ffi.ExecStreamHandle
}

// ID returns the unique identifier for this exec session, assigned by the
// guest agent. Useful for correlating log entries or referencing the session
// from external tooling.
func (h *ExecHandle) ID() (string, error) {
	id, err := h.inner.ID()
	return id, wrapFFI(err)
}

// TakeStdin returns the stdin sink for this exec session. Only valid when
// started with WithExecStdinPipe. Returns nil if stdin was not piped.
// The caller is responsible for closing the sink when done writing.
func (h *ExecHandle) TakeStdin() *ExecSink {
	return h.inner.TakeStdin()
}

// Recv blocks until the next event arrives or the stream ends. Returns an
// event with Kind==ExecEventDone when all events have been consumed.
//
// ctx controls the wait; cancellation causes Recv to return ctx.Err()
// immediately. The underlying Rust call may continue to completion in the
// background (same semantics as all blocking FFI calls).
func (h *ExecHandle) Recv(ctx context.Context) (*ExecEvent, error) {
	ev, err := h.inner.Recv(ctx)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &ExecEvent{
		Kind:     ev.Kind,
		PID:      ev.PID,
		Data:     ev.Data,
		ExitCode: ev.ExitCode,
	}, nil
}

// Collect drains the stream, accumulates all output, and returns it as
// ExecOutput. Equivalent to calling Recv in a loop and assembling the result.
// The handle should be closed after Collect returns.
func (h *ExecHandle) Collect(ctx context.Context) (*ExecOutput, error) {
	res, err := h.inner.Collect(ctx)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &ExecOutput{
		stdout:   []byte(res.Stdout),
		stderr:   []byte(res.Stderr),
		exitCode: res.ExitCode,
	}, nil
}

// Wait blocks until the process exits and returns its exit code. Unlike
// Collect, stdout and stderr are discarded. The handle should be closed after
// Wait returns.
func (h *ExecHandle) Wait(ctx context.Context) (int, error) {
	code, err := h.inner.Wait(ctx)
	return code, wrapFFI(err)
}

// Kill sends SIGKILL to the running process.
func (h *ExecHandle) Kill(ctx context.Context) error {
	return wrapFFI(h.inner.Kill(ctx))
}

// Signal sends a Unix signal to the running process (e.g. syscall.SIGTERM).
func (h *ExecHandle) Signal(ctx context.Context, signal int) error {
	return wrapFFI(h.inner.Signal(ctx, signal))
}

// Close releases the Rust-side exec handle. Does not kill the running process;
// call Signal(ctx, 9) first if you need to terminate it. Safe to call after
// ExecEventDone has been received.
func (h *ExecHandle) Close() error {
	return wrapFFI(h.inner.Close())
}

// ExecStream starts a streaming exec session and returns an ExecHandle.
// The handle MUST be closed with Close when the stream is no longer needed.
//
// ctx controls only the start handshake; individual Recv calls take their
// own ctx. Non-zero exit codes are NOT errors — inspect ExecEventExited.
func (s *Sandbox) ExecStream(ctx context.Context, cmd string, args []string, opts ...ExecOption) (*ExecHandle, error) {
	o := ExecConfig{}
	for _, opt := range opts {
		opt(&o)
	}
	ffiOpts := ffi.ExecOptions{Args: args, Cwd: o.Cwd, StdinPipe: o.StdinPipe}
	if o.Timeout > 0 {
		ffiOpts.TimeoutSecs = timeoutSecsCeil(o.Timeout)
	}
	h, err := s.inner.ExecStream(ctx, cmd, ffiOpts)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &ExecHandle{inner: h}, nil
}

// ShellStream runs `/bin/sh -c command` with streaming output.
func (s *Sandbox) ShellStream(ctx context.Context, command string, opts ...ExecOption) (*ExecHandle, error) {
	return s.ExecStream(ctx, "/bin/sh", []string{"-c", command}, opts...)
}
