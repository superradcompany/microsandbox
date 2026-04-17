package microsandbox

import (
	"context"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

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
	o := ExecOptions{}
	for _, opt := range opts {
		opt(&o)
	}

	ffiOpts := ffi.ExecOptions{Args: args, Cwd: o.Cwd}
	if o.Timeout > 0 {
		ffiOpts.TimeoutSecs = uint64(o.Timeout.Seconds())
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
