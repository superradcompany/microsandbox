//go:build integration

package microsandbox_test

import (
	"context"
	"net"
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

// ---------------------------------------------------------------------------
// Detached mode
// ---------------------------------------------------------------------------

// TestDetachedSandboxOutlivesHandle verifies that a detached sandbox is still
// listed after its handle is closed, and can be reattached via GetSandbox.
func TestDetachedSandboxOutlivesHandle(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-detached-" + t.Name()

	sb, err := microsandbox.NewSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithDetached(),
	)
	if err != nil {
		t.Fatalf("NewSandbox detached: %v", err)
	}
	// Close the handle — sandbox should keep running.
	if err := sb.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reattach and confirm it is still alive.
	sb2, err := microsandbox.GetSandbox(ctx, name)
	if err != nil {
		t.Fatalf("GetSandbox after detach: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb2.Stop(stopCtx)
		_ = sb2.Close()
		_ = microsandbox.RemoveSandbox(context.Background(), name)
	})

	out, err := sb2.Shell(ctx, "echo still-alive")
	if err != nil {
		t.Fatalf("Shell on reattached sandbox: %v", err)
	}
	if !strings.Contains(out.Stdout(), "still-alive") {
		t.Errorf("stdout %q does not contain 'still-alive'", out.Stdout())
	}
}

// ---------------------------------------------------------------------------
// Port publishing
// ---------------------------------------------------------------------------

// TestPortPublishing verifies that a port published on the host is actually
// reachable. We run a netcat listener on the guest and connect from the host.
func TestPortPublishing(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-ports-" + t.Name()

	sb, err := microsandbox.NewSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithPorts(map[uint16]uint16{17777: 7777}),
	)
	if err != nil {
		t.Fatalf("NewSandbox with ports: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})

	// Start a background listener on guest port 7777 and immediately send a
	// response, then connect from the host side to verify end-to-end.
	handle, err := sb.ShellStream(ctx, "echo hello-port | nc -l -p 7777")
	if err != nil {
		t.Fatalf("ShellStream: %v", err)
	}
	defer handle.Close()

	// Give netcat time to bind.
	time.Sleep(500 * time.Millisecond)

	conn, err := dialWithRetry("localhost:17777", 5, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("connect to published port: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 64)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := conn.Read(buf)
	if !strings.Contains(string(buf[:n]), "hello-port") {
		t.Errorf("got %q from published port, want 'hello-port'", string(buf[:n]))
	}
}

// dialWithRetry attempts a TCP dial up to attempts times with the given delay
// between each attempt.
func dialWithRetry(addr string, attempts int, delay time.Duration) (net.Conn, error) {
	var (
		conn net.Conn
		err  error
	)
	for i := 0; i < attempts; i++ {
		conn, err = net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			return conn, nil
		}
		time.Sleep(delay)
	}
	return nil, err
}

// ---------------------------------------------------------------------------
// Network policy
// ---------------------------------------------------------------------------

// TestNetworkPolicyNone verifies that a sandbox with policy "none" cannot
// reach external hosts. We attempt a DNS lookup; it should fail or time out.
func TestNetworkPolicyNone(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-netpolicy-" + t.Name()

	sb, err := microsandbox.NewSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithNetwork(&microsandbox.NetworkOptions{Policy: "none"}),
	)
	if err != nil {
		t.Fatalf("NewSandbox with network none: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})

	// nslookup should fail when there is no network.
	out, err := sb.Shell(ctx, "nslookup example.com; true",
		microsandbox.WithExecTimeout(10*time.Second))
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	// Either a non-zero exit or an error message in stderr/stdout.
	combined := out.Stdout() + out.Stderr()
	if out.Success() && !strings.Contains(combined, "SERVFAIL") &&
		!strings.Contains(combined, "connection refused") &&
		!strings.Contains(combined, "timed out") &&
		!strings.Contains(combined, "can't resolve") {
		t.Errorf("expected DNS failure with policy=none, got stdout=%q stderr=%q",
			out.Stdout(), out.Stderr())
	}
}

// TestNetworkPolicyAllowAll verifies that allow-all policy lets the sandbox
// reach the network. We use a simple wget to a well-known IP.
func TestNetworkPolicyAllowAll(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-netallow-" + t.Name()

	sb, err := microsandbox.NewSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithNetwork(&microsandbox.NetworkOptions{Policy: "allow-all"}),
	)
	if err != nil {
		t.Fatalf("NewSandbox allow-all: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})

	// Ping 1.1.1.1 — should succeed with allow-all.
	out, err := sb.Shell(ctx, "ping -c 1 -W 5 1.1.1.1",
		microsandbox.WithExecTimeout(15*time.Second))
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	if !out.Success() {
		t.Errorf("ping failed with allow-all policy: stdout=%q stderr=%q",
			out.Stdout(), out.Stderr())
	}
}

// ---------------------------------------------------------------------------
// DNS filtering
// ---------------------------------------------------------------------------

// TestDNSBlockDomain verifies that a blocked domain cannot be resolved.
func TestDNSBlockDomain(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-dns-" + t.Name()

	sb, err := microsandbox.NewSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithNetwork(&microsandbox.NetworkOptions{
			Policy:       "allow-all",
			BlockDomains: []string{"blocked-domain-test.example.com"},
		}),
	)
	if err != nil {
		t.Fatalf("NewSandbox with block_domains: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})

	out, err := sb.Shell(ctx, "nslookup blocked-domain-test.example.com; true",
		microsandbox.WithExecTimeout(10*time.Second))
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	combined := out.Stdout() + out.Stderr()
	if out.Success() && !strings.Contains(combined, "NXDOMAIN") &&
		!strings.Contains(combined, "SERVFAIL") &&
		!strings.Contains(combined, "can't resolve") {
		t.Errorf("expected DNS block, got stdout=%q stderr=%q", out.Stdout(), out.Stderr())
	}
}

// TestDNSBlockDomainSuffix verifies that a blocked suffix prevents resolution
// of any domain under that suffix.
func TestDNSBlockDomainSuffix(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-dnssuffix-" + t.Name()

	sb, err := microsandbox.NewSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithNetwork(&microsandbox.NetworkOptions{
			Policy:              "allow-all",
			BlockDomainSuffixes: []string{".blocked-suffix-test.invalid"},
		}),
	)
	if err != nil {
		t.Fatalf("NewSandbox with block_domain_suffixes: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})

	out, err := sb.Shell(ctx, "nslookup anything.blocked-suffix-test.invalid; true",
		microsandbox.WithExecTimeout(10*time.Second))
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	combined := out.Stdout() + out.Stderr()
	if out.Success() && !strings.Contains(combined, "NXDOMAIN") &&
		!strings.Contains(combined, "SERVFAIL") &&
		!strings.Contains(combined, "can't resolve") {
		t.Errorf("expected DNS block for suffix, got stdout=%q stderr=%q",
			out.Stdout(), out.Stderr())
	}
}

// ---------------------------------------------------------------------------
// Rootfs patches
// ---------------------------------------------------------------------------

// TestPatchText verifies that a text patch creates a file with the expected
// content before the VM boots.
func TestPatchText(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-patch-text-" + t.Name()

	sb, err := microsandbox.NewSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithPatches(
			microsandbox.PatchText("/etc/go-sdk-test.conf", "hello-from-patch\n", nil, false),
		),
	)
	if err != nil {
		t.Fatalf("NewSandbox with patch: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})

	out, err := sb.Shell(ctx, "cat /etc/go-sdk-test.conf")
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	if !strings.Contains(out.Stdout(), "hello-from-patch") {
		t.Errorf("patched file content: got %q", out.Stdout())
	}
}

// TestPatchMkdir verifies that a mkdir patch creates a directory.
func TestPatchMkdir(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-patch-mkdir-" + t.Name()

	mode := uint32(0o755)
	sb, err := microsandbox.NewSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithPatches(
			microsandbox.PatchMkdir("/opt/go-sdk-dir", &mode),
		),
	)
	if err != nil {
		t.Fatalf("NewSandbox with mkdir patch: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})

	out, err := sb.Shell(ctx, "test -d /opt/go-sdk-dir && echo dir-exists")
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	if !strings.Contains(out.Stdout(), "dir-exists") {
		t.Errorf("expected directory to exist, stdout=%q", out.Stdout())
	}
}

// TestPatchAppend verifies that an append patch adds content to an existing file.
func TestPatchAppend(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-patch-append-" + t.Name()

	sb, err := microsandbox.NewSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithPatches(
			microsandbox.PatchAppend("/etc/hosts", "192.0.2.1 go-sdk-test.local\n"),
		),
	)
	if err != nil {
		t.Fatalf("NewSandbox with append patch: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})

	out, err := sb.Shell(ctx, "grep go-sdk-test.local /etc/hosts")
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	if !strings.Contains(out.Stdout(), "go-sdk-test.local") {
		t.Errorf("expected appended line in /etc/hosts, stdout=%q", out.Stdout())
	}
}

// TestPatchSymlink verifies that a symlink patch creates a working symlink.
func TestPatchSymlink(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-patch-symlink-" + t.Name()

	sb, err := microsandbox.NewSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithPatches(
			microsandbox.PatchText("/tmp/original.txt", "original\n", nil, false),
			microsandbox.PatchSymlink("/tmp/original.txt", "/tmp/link.txt", false),
		),
	)
	if err != nil {
		t.Fatalf("NewSandbox with symlink patch: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})

	out, err := sb.Shell(ctx, "cat /tmp/link.txt")
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	if !strings.Contains(out.Stdout(), "original") {
		t.Errorf("symlink did not resolve: stdout=%q", out.Stdout())
	}
}

// ---------------------------------------------------------------------------
// Streaming exec
// ---------------------------------------------------------------------------

// TestExecStreamCollect starts a streaming exec session and collects all events
// into stdout/stderr, verifying the exit code and content.
func TestExecStreamCollect(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)

	handle, err := sb.ShellStream(ctx, "echo stream-out; echo stream-err >&2; exit 7")
	if err != nil {
		t.Fatalf("ShellStream: %v", err)
	}
	defer handle.Close()

	var stdout, stderr strings.Builder
	var exitCode int
	for {
		ev, err := handle.Recv(ctx)
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		switch ev.Kind {
		case microsandbox.ExecEventStdout:
			stdout.Write(ev.Data)
		case microsandbox.ExecEventStderr:
			stderr.Write(ev.Data)
		case microsandbox.ExecEventExited:
			exitCode = ev.ExitCode
		case microsandbox.ExecEventDone:
			goto done
		}
	}
done:
	if !strings.Contains(stdout.String(), "stream-out") {
		t.Errorf("stdout %q missing 'stream-out'", stdout.String())
	}
	if !strings.Contains(stderr.String(), "stream-err") {
		t.Errorf("stderr %q missing 'stream-err'", stderr.String())
	}
	if exitCode != 7 {
		t.Errorf("exit code: got %d, want 7", exitCode)
	}
}

// TestExecStreamStartedEvent verifies the Started event carries a non-zero PID.
func TestExecStreamStartedEvent(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)

	handle, err := sb.ExecStream(ctx, "echo", []string{"hi"})
	if err != nil {
		t.Fatalf("ExecStream: %v", err)
	}
	defer handle.Close()

	var gotStarted bool
	for {
		ev, err := handle.Recv(ctx)
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		if ev.Kind == microsandbox.ExecEventStarted {
			if ev.PID == 0 {
				t.Error("Started event: PID should be non-zero")
			}
			gotStarted = true
		}
		if ev.Kind == microsandbox.ExecEventDone {
			break
		}
	}
	if !gotStarted {
		t.Error("never received ExecEventStarted")
	}
}

// TestExecStreamSignal verifies that sending SIGTERM to a running process
// causes it to exit and the stream to end.
func TestExecStreamSignal(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)

	handle, err := sb.ShellStream(ctx, "sleep 60")
	if err != nil {
		t.Fatalf("ShellStream: %v", err)
	}
	defer handle.Close()

	// Wait for the Started event so the process is actually running.
	for {
		ev, err := handle.Recv(ctx)
		if err != nil {
			t.Fatalf("Recv (waiting for start): %v", err)
		}
		if ev.Kind == microsandbox.ExecEventStarted {
			break
		}
	}

	// Send SIGTERM (15).
	if err := handle.Signal(ctx, 15); err != nil {
		t.Fatalf("Signal: %v", err)
	}

	// Drain until done; expect an Exited event.
	deadline := time.After(10 * time.Second)
	var gotExited bool
	for {
		select {
		case <-deadline:
			t.Fatal("stream did not end within 10s after SIGTERM")
		default:
		}
		ev, err := handle.Recv(ctx)
		if err != nil {
			t.Fatalf("Recv after signal: %v", err)
		}
		if ev.Kind == microsandbox.ExecEventExited {
			gotExited = true
		}
		if ev.Kind == microsandbox.ExecEventDone {
			break
		}
	}
	if !gotExited {
		t.Error("never received ExecEventExited after SIGTERM")
	}
}

// TestExecStreamCtxCancel verifies that cancelling the ctx on Recv returns
// ctx.Err() promptly.
func TestExecStreamCtxCancel(t *testing.T) {
	sb := newTestSandbox(t)
	outerCtx := integrationCtx(t)

	handle, err := sb.ShellStream(outerCtx, "sleep 60")
	if err != nil {
		t.Fatalf("ShellStream: %v", err)
	}
	defer handle.Close()

	// Wait for Started so the process is alive.
	for {
		ev, err := handle.Recv(outerCtx)
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		if ev.Kind == microsandbox.ExecEventStarted {
			break
		}
	}

	recvCtx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := handle.Recv(recvCtx)
		errc <- err
	}()

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
		t.Fatal("Recv did not return after ctx cancel within 5s")
	}
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

// TestSecretPlaceholderSubstitution verifies that a secret value never appears
// in the sandbox environment and that the placeholder is visible inside.
func TestSecretPlaceholderSubstitution(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-secret-" + t.Name()

	sb, err := microsandbox.NewSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithSecrets(microsandbox.SecretOptions{
			EnvVar:      "MY_API_KEY",
			Value:       "super-secret-value-xyz",
			AllowHosts:  []string{"api.example.com"},
			Placeholder: "$MY_API_KEY_PLACEHOLDER",
		}),
	)
	if err != nil {
		t.Fatalf("NewSandbox with secret: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})

	// The actual secret value must not appear inside the sandbox.
	out, err := sb.Shell(ctx, "printenv MY_API_KEY; true")
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	if strings.Contains(out.Stdout(), "super-secret-value-xyz") {
		t.Error("secret value leaked into sandbox environment")
	}
	// The placeholder should be visible instead.
	if !strings.Contains(out.Stdout(), "$MY_API_KEY_PLACEHOLDER") {
		t.Errorf("placeholder not visible in sandbox env, got %q", out.Stdout())
	}
}

// ---------------------------------------------------------------------------
// TestRemoveSandbox
// ---------------------------------------------------------------------------

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
