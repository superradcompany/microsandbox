//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

// TestExecHandleTakeStdinReturnsNilWhenNotPiped verifies the contract added
// in this change set: TakeStdin must return nil when the session was not
// started with WithExecStdinPipe.
func TestExecHandleTakeStdinReturnsNilWhenNotPiped(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)

	h, err := sb.ExecStream(ctx, "echo", []string{"hi"})
	if err != nil {
		t.Fatalf("ExecStream: %v", err)
	}
	defer h.Close()

	if sink := h.TakeStdin(); sink != nil {
		t.Errorf("TakeStdin without WithExecStdinPipe: got %v, want nil", sink)
	}
}

// TestExecHandleTakeStdinSingleTake verifies that subsequent TakeStdin
// calls return nil after the first one (single-take semantics).
func TestExecHandleTakeStdinSingleTake(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)

	h, err := sb.ShellStream(ctx, "cat", microsandbox.WithExecStdinPipe())
	if err != nil {
		t.Fatalf("ShellStream: %v", err)
	}
	defer h.Close()

	first := h.TakeStdin()
	if first == nil {
		t.Fatal("first TakeStdin: got nil with stdin pipe enabled")
	}
	second := h.TakeStdin()
	if second != nil {
		t.Errorf("second TakeStdin: got %v, want nil", second)
	}
}

// TestExecHandleStdinPipeRoundtrip writes data to a long-running cat
// process, closes stdin, and verifies the bytes echo back via stdout.
func TestExecHandleStdinPipeRoundtrip(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)

	h, err := sb.ShellStream(ctx, "cat", microsandbox.WithExecStdinPipe())
	if err != nil {
		t.Fatalf("ShellStream: %v", err)
	}
	defer h.Close()

	sink := h.TakeStdin()
	if sink == nil {
		t.Fatal("TakeStdin: got nil with stdin pipe enabled")
	}

	const payload = "hello-via-stdin\n"
	if _, err := sink.Write([]byte(payload)); err != nil {
		t.Fatalf("stdin Write: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("stdin Close: %v", err)
	}

	var stdout strings.Builder
	deadline := time.After(15 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatalf("did not receive stdout within 15s; got %q", stdout.String())
		default:
		}
		ev, err := h.Recv(ctx)
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		switch ev.Kind {
		case microsandbox.ExecEventStdout:
			stdout.Write(ev.Data)
		case microsandbox.ExecEventDone:
			goto done
		}
	}
done:
	if !strings.Contains(stdout.String(), "hello-via-stdin") {
		t.Errorf("stdin echo: got %q want it to contain payload", stdout.String())
	}
}

// TestExecHandleWaitReturnsExitCode verifies Wait blocks until the process
// exits and returns the right code.
func TestExecHandleWaitReturnsExitCode(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)

	h, err := sb.ShellStream(ctx, "exit 13")
	if err != nil {
		t.Fatalf("ShellStream: %v", err)
	}
	defer h.Close()

	code, err := h.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if code != 13 {
		t.Errorf("Wait: got %d, want 13", code)
	}
}

// TestExecHandleKill sends SIGKILL to a running process via the dedicated
// helper and verifies the stream ends.
func TestExecHandleKill(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)

	h, err := sb.ShellStream(ctx, "sleep 60")
	if err != nil {
		t.Fatalf("ShellStream: %v", err)
	}
	defer h.Close()

	// Wait for the process to actually be running.
	for {
		ev, err := h.Recv(ctx)
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		if ev.Kind == microsandbox.ExecEventStarted {
			break
		}
	}
	if err := h.Kill(ctx); err != nil {
		t.Fatalf("Kill: %v", err)
	}

	deadline := time.After(10 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("stream did not end within 10s after Kill")
		default:
		}
		ev, err := h.Recv(ctx)
		if err != nil {
			t.Fatalf("Recv after Kill: %v", err)
		}
		if ev.Kind == microsandbox.ExecEventDone {
			return
		}
	}
}

// TestExecHandleID verifies that ID returns a non-empty correlation token
// for the exec session.
func TestExecHandleID(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)

	h, err := sb.ShellStream(ctx, "echo go-sdk-id-test")
	if err != nil {
		t.Fatalf("ShellStream: %v", err)
	}
	defer h.Close()

	id, err := h.ID()
	if err != nil {
		t.Fatalf("ID: %v", err)
	}
	if id == "" {
		t.Error("ID: empty")
	}
}

// TestExecStreamFailedEventOnMissingBinary verifies that running a binary
// that doesn't exist surfaces an ExecEventFailed (not Started + Exited).
//
// Some runtime versions deliver ExecEventFailed; others map the missing
// binary to a non-zero Exited from the shell wrapper. Both are acceptable;
// we only assert that we either see a Failed event or no Started event,
// matching how the Node SDK validates this surface.
func TestExecStreamFailedEventOnMissingBinary(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)

	h, err := sb.ExecStream(ctx, "/no/such/binary-go-sdk", nil)
	if err != nil {
		// Some runtimes reject the start synchronously; that's also fine.
		t.Logf("ExecStream synchronous error (acceptable): %v", err)
		return
	}
	defer h.Close()

	var sawStarted, sawFailed bool
	deadline := time.After(15 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("stream did not end within 15s for missing-binary exec")
		default:
		}
		ev, err := h.Recv(ctx)
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		switch ev.Kind {
		case microsandbox.ExecEventStarted:
			sawStarted = true
		case microsandbox.ExecEventFailed:
			sawFailed = true
			if ev.Failure == nil {
				t.Error("Failed event with nil Failure")
			} else if ev.Failure.Message == "" {
				t.Error("Failed.Message: empty")
			}
		case microsandbox.ExecEventDone:
			goto done
		}
	}
done:
	if sawStarted && !sawFailed {
		t.Error("missing binary should not produce Started without a Failed afterwards")
	}
}

// TestExecWithExecUserOverride verifies that WithExecUser overrides the
// per-command user (independent of the sandbox-level WithUser).
func TestExecWithExecUserOverride(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-execuser-" + t.Name()

	sb, err := microsandbox.CreateSandbox(ctx, name, microsandbox.WithImage("alpine:3.19"))
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})

	out, err := sb.Exec(ctx, "whoami", nil, microsandbox.WithExecUser("nobody"))
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if !strings.Contains(out.Stdout(), "nobody") {
		t.Errorf("whoami: got %q want it to contain 'nobody'", out.Stdout())
	}
}

// TestExecWithExecEnvOverlay verifies WithExecEnv overlays the
// sandbox-level env.
func TestExecWithExecEnvOverlay(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-execenv-" + t.Name()

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithEnv(map[string]string{"BASE_VAR": "from-sandbox"}),
	)
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})

	out, err := sb.Shell(ctx, "echo $BASE_VAR:$EXEC_VAR",
		microsandbox.WithExecEnv(map[string]string{"EXEC_VAR": "from-exec"}),
	)
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	if !strings.Contains(out.Stdout(), "from-sandbox:from-exec") {
		t.Errorf("env overlay: got %q", out.Stdout())
	}
}

// TestExecOutputBytesAccessor verifies that StdoutBytes/StderrBytes return
// raw byte slices alongside the string view.
func TestExecOutputBytesAccessor(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)

	out, err := sb.Shell(ctx, "printf 'A\\x00B'")
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	b := out.StdoutBytes()
	if len(b) != 3 || b[0] != 'A' || b[1] != 0 || b[2] != 'B' {
		t.Errorf("StdoutBytes: got %v want [65 0 66]", b)
	}
}

// TestShellStream verifies that ShellStream wraps /bin/sh -c and emits
// stream events end-to-end.
func TestShellStream(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)

	h, err := sb.ShellStream(ctx, "for i in 1 2 3; do echo line-$i; done")
	if err != nil {
		t.Fatalf("ShellStream: %v", err)
	}
	defer h.Close()

	var stdout strings.Builder
	for {
		ev, err := h.Recv(ctx)
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		if ev.Kind == microsandbox.ExecEventStdout {
			stdout.Write(ev.Data)
		}
		if ev.Kind == microsandbox.ExecEventDone {
			break
		}
	}
	for i := 1; i <= 3; i++ {
		want := "line-" + string(rune('0'+i))
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("missing %q in stream stdout: %q", want, stdout.String())
		}
	}
}
