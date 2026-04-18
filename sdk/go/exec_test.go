package microsandbox

import "testing"

func newOutput(stdout, stderr string, code int) *ExecOutput {
	return &ExecOutput{
		stdout:   []byte(stdout),
		stderr:   []byte(stderr),
		exitCode: code,
	}
}

func TestExecOutputStdout(t *testing.T) {
	o := newOutput("hello\n", "", 0)
	if o.Stdout() != "hello\n" {
		t.Errorf("got %q", o.Stdout())
	}
	if string(o.StdoutBytes()) != "hello\n" {
		t.Errorf("StdoutBytes mismatch")
	}
}

func TestExecOutputStderr(t *testing.T) {
	o := newOutput("", "oops\n", 1)
	if o.Stderr() != "oops\n" {
		t.Errorf("got %q", o.Stderr())
	}
	if string(o.StderrBytes()) != "oops\n" {
		t.Errorf("StderrBytes mismatch")
	}
}

func TestExecOutputExitCode(t *testing.T) {
	cases := []struct {
		code    int
		success bool
	}{
		{0, true},
		{1, false},
		{127, false},
		{-1, false},
	}
	for _, c := range cases {
		o := newOutput("", "", c.code)
		if o.ExitCode() != c.code {
			t.Errorf("ExitCode: got %d, want %d", o.ExitCode(), c.code)
		}
		if o.Success() != c.success {
			t.Errorf("Success: got %v for exit %d", o.Success(), c.code)
		}
	}
}

func TestExecOutputEmptyOutput(t *testing.T) {
	o := newOutput("", "", 0)
	if o.Stdout() != "" {
		t.Error("Stdout should be empty string, not nil conversion artifact")
	}
	if o.Stderr() != "" {
		t.Error("Stderr should be empty string")
	}
}
