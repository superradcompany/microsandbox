//go:build integration

package microsandbox_test

import (
	"context"
	"strings"
	"testing"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

// integrationCtx returns a context with a generous timeout for VM boot.
func integrationCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	return ctx
}

// newTestSandbox creates a sandbox named after the test and registers cleanup.
func newTestSandbox(t *testing.T) *microsandbox.Sandbox {
	t.Helper()
	ctx := integrationCtx(t)
	name := "go-sdk-test-" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-"))
	sb, err := microsandbox.NewSandbox(ctx, name, microsandbox.WithImage("alpine:3.19"))
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})
	return sb
}

// TestNewSandboxAndClose verifies that a sandbox can be created and its handle
// released without error. The name is available in ListSandboxes immediately
// after creation.
func TestNewSandboxAndClose(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-lifecycle-" + t.Name()
	sb, err := microsandbox.NewSandbox(ctx, name, microsandbox.WithImage("alpine:3.19"))
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}
	if sb.Name() != name {
		t.Errorf("Name() = %q, want %q", sb.Name(), name)
	}

	names, err := microsandbox.ListSandboxes(ctx)
	if err != nil {
		t.Fatalf("ListSandboxes: %v", err)
	}
	found := false
	for _, n := range names {
		if n == name {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("sandbox %q not found in ListSandboxes result %v", name, names)
	}

	if err := sb.Stop(ctx); err != nil {
		t.Errorf("Stop: %v", err)
	}
	if err := sb.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestCloseIdempotent verifies that calling Close twice returns ErrInvalidHandle
// on the second call, and that the error kind is correct.
func TestCloseIdempotent(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)

	if err := sb.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := sb.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	err := sb.Close()
	if err == nil {
		t.Fatal("second Close should return an error")
	}
	if !microsandbox.IsKind(err, microsandbox.ErrInvalidHandle) {
		t.Errorf("second Close: want ErrInvalidHandle, got %v", err)
	}
}

// TestGetSandboxNotFound verifies that GetSandbox on a missing name returns
// ErrSandboxNotFound.
func TestGetSandboxNotFound(t *testing.T) {
	ctx := integrationCtx(t)
	_, err := microsandbox.GetSandbox(ctx, "does-not-exist-xyz")
	if err == nil {
		t.Fatal("expected error for missing sandbox")
	}
	if !microsandbox.IsKind(err, microsandbox.ErrSandboxNotFound) {
		t.Errorf("want ErrSandboxNotFound, got %v", err)
	}
}

// TestExecSuccess runs a command that exits 0 and checks stdout.
func TestExecSuccess(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)

	out, err := sb.Exec(ctx, "echo", []string{"hello"})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if !out.Success() {
		t.Errorf("expected exit 0, got %d", out.ExitCode())
	}
	if !strings.Contains(out.Stdout(), "hello") {
		t.Errorf("stdout %q does not contain 'hello'", out.Stdout())
	}
}

// TestExecNonZeroExitNotAnError verifies that a non-zero exit is not a Go error.
func TestExecNonZeroExitNotAnError(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)

	out, err := sb.Exec(ctx, "/bin/sh", []string{"-c", "exit 42"})
	if err != nil {
		t.Fatalf("Exec returned Go error for non-zero exit: %v", err)
	}
	if out.ExitCode() != 42 {
		t.Errorf("ExitCode: got %d, want 42", out.ExitCode())
	}
	if out.Success() {
		t.Error("Success() should be false for exit 42")
	}
}

// TestShell runs a shell command and verifies the output.
func TestShell(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)

	out, err := sb.Shell(ctx, "echo go-sdk-ok")
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	if !strings.Contains(out.Stdout(), "go-sdk-ok") {
		t.Errorf("stdout %q does not contain 'go-sdk-ok'", out.Stdout())
	}
}

// TestExecTimeout verifies that a long-running command returns ErrExecTimeout
// when a per-command timeout is set.
func TestExecTimeout(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)

	_, err := sb.Shell(ctx, "sleep 60", microsandbox.WithExecTimeout(2*time.Second))
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !microsandbox.IsKind(err, microsandbox.ErrExecTimeout) {
		t.Errorf("want ErrExecTimeout, got %v", err)
	}
}

// TestFsWriteAndRead writes a file into the sandbox and reads it back.
func TestFsWriteAndRead(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)
	fs := sb.FS()

	content := "microsandbox go sdk test\n"
	if err := fs.WriteString(ctx, "/tmp/go-sdk.txt", content); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	got, err := fs.ReadString(ctx, "/tmp/go-sdk.txt")
	if err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	if got != content {
		t.Errorf("got %q, want %q", got, content)
	}
}

// TestFsList verifies that a known path appears in the directory listing.
func TestFsList(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)
	fs := sb.FS()

	if err := fs.WriteString(ctx, "/tmp/list-test.txt", "x"); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	entries, err := fs.List(ctx, "/tmp")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, e := range entries {
		if strings.HasSuffix(e.Path, "list-test.txt") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("list-test.txt not found in /tmp listing: %v", entries)
	}
}

// TestFsStat verifies that stat returns non-zero size for a written file.
func TestFsStat(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)
	fs := sb.FS()

	data := "stat test data"
	if err := fs.WriteString(ctx, "/tmp/stat-test.txt", data); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	st, err := fs.Stat(ctx, "/tmp/stat-test.txt")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if st.Size <= 0 {
		t.Errorf("expected positive size, got %d", st.Size)
	}
	if st.IsDir {
		t.Error("file should not be reported as directory")
	}
}

// TestMetrics verifies that Metrics returns a non-zero uptime after exec.
func TestMetrics(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)

	// Run something so there is uptime to report.
	if _, err := sb.Shell(ctx, "true"); err != nil {
		t.Fatalf("Shell: %v", err)
	}
	m, err := sb.Metrics(ctx)
	if err != nil {
		t.Fatalf("Metrics: %v", err)
	}
	if m.Uptime <= 0 {
		t.Errorf("expected positive Uptime, got %v", m.Uptime)
	}
}

// TestVolumeLifecycle creates a volume, lists it, then removes it.
func TestVolumeLifecycle(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-vol-" + t.Name()

	vol, err := microsandbox.NewVolume(ctx, name)
	if err != nil {
		t.Fatalf("NewVolume: %v", err)
	}
	if vol.Name() != name {
		t.Errorf("Name() = %q, want %q", vol.Name(), name)
	}

	vols, err := microsandbox.ListVolumes(ctx)
	if err != nil {
		t.Fatalf("ListVolumes: %v", err)
	}
	found := false
	for _, v := range vols {
		if v.Name() == name {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("volume %q not found in ListVolumes", name)
	}

	if err := vol.Remove(ctx); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	t.Cleanup(func() {
		// Best-effort cleanup if the test failed before Remove.
		_ = microsandbox.RemoveVolume(context.Background(), name)
	})
}

// TestVolumeAlreadyExists verifies that creating a duplicate volume returns
// ErrVolumeAlreadyExists.
func TestVolumeAlreadyExists(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-dupvol-" + t.Name()

	vol, err := microsandbox.NewVolume(ctx, name)
	if err != nil {
		t.Fatalf("first NewVolume: %v", err)
	}
	t.Cleanup(func() { _ = vol.Remove(context.Background()) })

	_, err = microsandbox.NewVolume(ctx, name)
	if err == nil {
		t.Fatal("expected error for duplicate volume")
	}
	if !microsandbox.IsKind(err, microsandbox.ErrVolumeAlreadyExists) {
		t.Errorf("want ErrVolumeAlreadyExists, got %v", err)
	}
}

// TestExecCtxCancel verifies that cancelling the context while a command is
// running causes Exec to return ctx.Err() promptly. The documented behaviour
// is that the Rust side continues to completion in the background; we only
// assert on the Go-visible outcome.
func TestExecCtxCancel(t *testing.T) {
	sb := newTestSandbox(t)

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := sb.Shell(ctx, "sleep 60")
		errc <- err
	}()

	// Give the call time to reach the Rust side before cancelling.
	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected error after ctx cancel")
		}
		if !strings.Contains(err.Error(), "context canceled") {
			t.Errorf("expected context canceled, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Exec did not return after ctx cancel within 5s")
	}
}

// TestRemoveSandbox verifies that a stopped sandbox can be removed and no
// longer appears in ListSandboxes.
func TestRemoveSandbox(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-remove-" + t.Name()

	sb, err := microsandbox.NewSandbox(ctx, name, microsandbox.WithImage("alpine:3.19"))
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}
	if _, err := sb.StopAndWait(ctx); err != nil {
		t.Fatalf("StopAndWait: %v", err)
	}
	if err := sb.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := microsandbox.RemoveSandbox(ctx, name); err != nil {
		t.Fatalf("RemoveSandbox: %v", err)
	}

	names, err := microsandbox.ListSandboxes(ctx)
	if err != nil {
		t.Fatalf("ListSandboxes: %v", err)
	}
	for _, n := range names {
		if n == name {
			t.Errorf("sandbox %q still present after RemoveSandbox", name)
		}
	}
}
