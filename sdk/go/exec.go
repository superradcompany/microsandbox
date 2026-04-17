package microsandbox

import (
	"context"
	"strings"

	"github.com/Khrees2412/microsandbox/sdk/go/internal/ffi"
)

// ExecOutput holds the result of a command execution.
type ExecOutput struct {
	stdout   []byte
	stderr   []byte
	exitCode int
}

// Stdout returns the captured standard output as a string.
func (e *ExecOutput) Stdout() string {
	return string(e.stdout)
}

// StdoutBytes returns the captured standard output as bytes.
func (e *ExecOutput) StdoutBytes() []byte {
	return e.stdout
}

// Stderr returns the captured standard error as a string.
func (e *ExecOutput) Stderr() string {
	return string(e.stderr)
}

// StderrBytes returns the captured standard error as bytes.
func (e *ExecOutput) StderrBytes() []byte {
	return e.stderr
}

// ExitCode returns the exit code of the command.
func (e *ExecOutput) ExitCode() int {
	return e.exitCode
}

// Success returns true if the command exited with code 0.
func (e *ExecOutput) Success() bool {
	return e.exitCode == 0
}

// String returns a human-readable representation of the output.
func (e *ExecOutput) String() string {
	var b strings.Builder
	if len(e.stdout) > 0 {
		b.Write(e.stdout)
	}
	if len(e.stderr) > 0 {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.Write(e.stderr)
	}
	return b.String()
}

// ExecHandle manages a streaming execution session.
type ExecHandle struct {
	events <-chan ExecEvent
}

// Events returns the channel of exec events.
// The channel is closed when the process exits.
func (h *ExecHandle) Events() <-chan ExecEvent {
	return h.events
}

// ExecEvent represents an event from a streaming execution.
type ExecEvent interface {
	isExecEvent()
}

// StdoutEvent is emitted when stdout data is received during streaming exec.
type StdoutEvent struct {
	Data []byte
}

func (StdoutEvent) isExecEvent() {}

// StderrEvent is emitted when stderr data is received during streaming exec.
type StderrEvent struct {
	Data []byte
}

func (StderrEvent) isExecEvent() {}

// ExitedEvent is emitted when the process exits during streaming exec.
type ExitedEvent struct {
	Code int
}

func (ExitedEvent) isExecEvent() {}

// Exec runs a command in the sandbox and returns the captured output.
func (s *Sandbox) Exec(ctx context.Context, cmd string, args []string, opts ...ExecOption) (*ExecOutput, error) {
	options := &ExecOptions{}
	for _, opt := range opts {
		opt(options)
	}

	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	result, err := s.ffi.SandboxExec(ctx, s.handle, cmd, args)
	if err != nil {
		return nil, WrapErrorf(ErrExecFailed, err, "command %q failed", cmd)
	}

	output := &ExecOutput{
		stdout:   []byte(result.Stdout),
		stderr:   []byte(result.Stderr),
		exitCode: result.ExitCode,
	}

	if result.ExitCode != 0 {
		return output, NewErrorf(ErrExecFailed, "command exited with code %d", result.ExitCode)
	}

	return output, nil
}

// Shell runs a shell command string via /bin/sh -c.
func (s *Sandbox) Shell(ctx context.Context, command string, opts ...ExecOption) (*ExecOutput, error) {
	return s.Exec(ctx, "/bin/sh", []string{"-c", command}, opts...)
}

// ExecStream runs a command and returns a handle for streaming output via channel.
func (s *Sandbox) ExecStream(ctx context.Context, cmd string, args []string, opts ...ExecOption) (*ExecHandle, error) {
	options := &ExecOptions{}
	for _, opt := range opts {
		opt(options)
	}

	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	eventChan, err := s.ffi.SandboxExecStream(ctx, s.handle, cmd, args)
	if err != nil {
		return nil, WrapErrorf(ErrExecFailed, err, "streaming command %q failed", cmd)
	}

	publicChan := make(chan ExecEvent, cap(eventChan))
	go func() {
		defer close(publicChan)
		for event := range eventChan {
			switch e := event.(type) {
			case ffi.StdoutEvent:
				publicChan <- StdoutEvent{Data: e.Data}
			case ffi.StderrEvent:
				publicChan <- StderrEvent{Data: e.Data}
			case ffi.ExitedEvent:
				publicChan <- ExitedEvent{Code: e.Code}
			}
		}
	}()

	return &ExecHandle{events: publicChan}, nil
}

// ShellCommand constructs a shell invocation for the given command string.
func ShellCommand(command string) (cmd string, args []string) {
	return "/bin/sh", []string{"-c", command}
}
