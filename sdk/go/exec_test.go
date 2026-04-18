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

func TestExecEventKindConstants(t *testing.T) {
	// Verify the constants are distinct — a renumbering would silently break
	// the event dispatch switch in callers.
	kinds := []ExecEventKind{
		ExecEventStarted,
		ExecEventStdout,
		ExecEventStderr,
		ExecEventExited,
		ExecEventDone,
	}
	seen := make(map[ExecEventKind]bool, len(kinds))
	for _, k := range kinds {
		if seen[k] {
			t.Errorf("duplicate ExecEventKind value %d", int(k))
		}
		seen[k] = true
	}
}

func TestExecEventFields(t *testing.T) {
	started := ExecEvent{Kind: ExecEventStarted, PID: 42}
	if started.PID != 42 {
		t.Errorf("PID: got %d, want 42", started.PID)
	}

	stdout := ExecEvent{Kind: ExecEventStdout, Data: []byte("hello")}
	if string(stdout.Data) != "hello" {
		t.Errorf("Data: got %q", stdout.Data)
	}

	exited := ExecEvent{Kind: ExecEventExited, ExitCode: 1}
	if exited.ExitCode != 1 {
		t.Errorf("ExitCode: got %d, want 1", exited.ExitCode)
	}

	done := ExecEvent{Kind: ExecEventDone}
	if done.Kind != ExecEventDone {
		t.Errorf("Kind: got %d, want ExecEventDone", done.Kind)
	}
}
