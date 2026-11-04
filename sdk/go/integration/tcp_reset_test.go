//go:build integration && microsandbox_ffi_path

package integration

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

func guestResetLine(t *testing.T, ctx context.Context, process *microsandbox.ExecHandle) string {
	t.Helper()
	var output strings.Builder
	for {
		event, err := process.Recv(ctx)
		if err != nil {
			t.Fatal(err)
		}
		switch event.Kind {
		case microsandbox.ExecEventStdout:
			output.Write(event.Data)
			if strings.HasSuffix(output.String(), "\n") {
				return strings.TrimSuffix(output.String(), "\n")
			}
		case microsandbox.ExecEventStderr, microsandbox.ExecEventDone:
			t.Fatalf("guest reset fixture ended unexpectedly: %+v", event)
		}
	}
}

func guestSocketResetFixture(t *testing.T) (context.Context, *microsandbox.Sandbox, *microsandbox.ExecHandle, *microsandbox.TCPConn) {
	t.Helper()
	ctx := integrationCtx(t)
	fixture := filepath.Join(t.TempDir(), "tcp-reset")
	build := exec.CommandContext(ctx, "go", "build", "-o", fixture, "./testdata/tcp-reset")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH, "GOFLAGS=")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build guest fixture: %v\n%s", err, output)
	}
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	name := "go-sdk-reset-" + strings.ToLower(t.Name())
	sb, err := microsandbox.CreateSandbox(ctx, name, microsandbox.WithImage(goIntegrationImage), microsandbox.WithMemory(256))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := sb.Stop(cleanup); err != nil {
			t.Error(err)
			return
		}
		if err := microsandbox.RemoveSandbox(cleanup, name); err != nil {
			t.Error(err)
		}
		if err := sb.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := sb.FS().Write(ctx, "/tcp-reset", data); err != nil {
		t.Fatal(err)
	}
	if output, err := sb.Exec(ctx, "chmod", []string{"+x", "/tcp-reset"}); err != nil || output.ExitCode() != 0 {
		t.Fatalf("chmod fixture: %v", err)
	}
	process, err := sb.ExecStream(ctx, "/tcp-reset", nil, microsandbox.WithExecStdinPipe(), microsandbox.WithExecTTY(false))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = process.Close() })
	host, service, err := net.SplitHostPort(guestResetLine(t, ctx, process))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(service, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := sb.DialTCP(ctx, host, uint16(port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Abort() })
	return ctx, sb, process, conn
}

func TestGuestSocketResetEndsBlockedTCPReadAndWrite(t *testing.T) {
	ctx, sb, process, conn := guestSocketResetFixture(t)
	if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := conn.Write(make([]byte, 32<<20))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("destination did not stall: %d, %v", n, err)
	}
	t.Logf("destination stalled after %d bytes", n)
	if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	read, write := make(chan error, 1), make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 1)); read <- err }()
	go func() { _, err := conn.Write(make([]byte, 16<<10)); write <- err }()
	stdin := process.TakeStdin()
	if stdin == nil {
		t.Fatal("fixture stdin unavailable")
	}
	defer stdin.Close()
	if _, err := stdin.WriteCtx(ctx, []byte("reset\n")); err != nil {
		t.Fatal(err)
	}
	if line := guestResetLine(t, ctx, process); line != "reset" {
		t.Fatalf("reset not confirmed: %q", line)
	}
	ended, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, call := range []struct {
		name string
		done <-chan error
	}{{"Read", read}, {"Write", write}} {
		select {
		case err := <-call.done:
			if err == nil || errors.Is(err, io.EOF) {
				t.Fatalf("%s did not report reset: %v", call.name, err)
			}
		case <-ended.Done():
			t.Fatalf("guest reset left %s blocked: %v", call.name, ended.Err())
		}
	}
	if err := conn.Abort(); err != nil {
		t.Fatalf("guest reset cleanup: %v", err)
	}
	if output, err := sb.Exec(ctx, "true", nil); err != nil || output.ExitCode() != 0 {
		t.Fatalf("agent control after reset: %v", err)
	}
	if _, err := sb.FS().ReadString(ctx, "/proc/1/net/tcp"); err != nil {
		t.Fatalf("agent filesystem after reset: %v", err)
	}
}

func TestGuestSocketResetReadFailurePreventsLaterWrite(t *testing.T) {
	ctx, sb, process, conn := guestSocketResetFixture(t)
	if err := conn.SetDeadline(time.Now().Add(3 * microsandboxIdleBound)); err != nil {
		t.Fatal(err)
	}
	// Do not fill credit: an idle input has room to accept a later write unless the
	// failed output closes both directions before Read reports the guest's failure.
	stdin := process.TakeStdin()
	if stdin == nil {
		t.Fatal("fixture stdin unavailable")
	}
	defer stdin.Close()
	if _, err := stdin.WriteCtx(ctx, []byte("reset\n")); err != nil {
		t.Fatal(err)
	}
	if line := guestResetLine(t, ctx, process); line != "reset" {
		t.Fatalf("reset not confirmed: %q", line)
	}
	if n, err := conn.Read(make([]byte, 1)); n != 0 || err == nil || !strings.Contains(err.Error(), "guest TCP read:") {
		t.Fatalf("guest reset did not report its read failure: n=%d err=%v", n, err)
	}
	if n, err := conn.Write([]byte("after failure")); n != 0 || err == nil {
		t.Fatalf("write after reported guest failure: n=%d err=%v", n, err)
	}
	if err := conn.Abort(); err != nil {
		t.Fatalf("guest reset cleanup: %v", err)
	}
	if output, err := sb.Exec(ctx, "true", nil); err != nil || output.ExitCode() != 0 {
		t.Fatalf("agent control after reset: %v", err)
	}
}
