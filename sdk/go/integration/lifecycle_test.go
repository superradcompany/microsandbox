//go:build integration && microsandbox_ffi_path

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

// TestSandboxStopWaitsUntilStopped verifies that Stop returns after stopped
// state is observed.
func TestSandboxStopWaitsUntilStopped(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)

	if err := sb.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := sb.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestSandboxWaitUntilStopped blocks until the sandbox reaches terminal state.
func TestSandboxWaitUntilStopped(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)

	go func() {
		time.Sleep(500 * time.Millisecond)
		_ = sb.RequestStop(context.Background())
	}()

	result, err := sb.WaitUntilStopped(ctx)
	if err != nil {
		t.Fatalf("WaitUntilStopped: %v", err)
	}
	if result.Status != microsandbox.SandboxStatusStopped && result.Status != microsandbox.SandboxStatusCrashed {
		t.Fatalf("WaitUntilStopped status = %q", result.Status)
	}
}

// TestSandboxRequestDrain sends SIGUSR1. A vanilla alpine guest doesn't have a
// SIGUSR1 handler so we only assert the call doesn't error out, mirroring
// how the Node and Python SDKs cover this surface.
func TestSandboxRequestDrain(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)

	if err := sb.RequestDrain(ctx); err != nil {
		t.Fatalf("RequestDrain: %v", err)
	}
}

// TestSandboxPingTouch verifies health checks and explicit idle refreshes on
// live sandboxes, then proves name-addressed handles do not start stopped
// sandboxes implicitly.
func TestSandboxPingTouch(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-pingtouch-" + t.Name()

	sb, err := createSandbox(t, ctx, name, microsandbox.WithImage(goIntegrationImage))
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
		_ = microsandbox.RemoveSandbox(context.Background(), name)
	})

	ping, err := sb.Ping(ctx)
	if err != nil {
		t.Fatalf("Sandbox.Ping: %v", err)
	}
	if ping.Name != name {
		t.Fatalf("Sandbox.Ping name = %q, want %q", ping.Name, name)
	}
	if ping.Latency < 0 {
		t.Fatalf("Sandbox.Ping latency = %s, want non-negative", ping.Latency)
	}

	touch, err := sb.Touch(ctx)
	if err != nil {
		t.Fatalf("Sandbox.Touch: %v", err)
	}
	if touch.Name != name || touch.ActivitySeq == 0 {
		t.Fatalf("Sandbox.Touch = %+v", touch)
	}

	handle, err := microsandbox.GetSandbox(ctx, name)
	if err != nil {
		t.Fatalf("GetSandbox: %v", err)
	}
	if _, err := handle.Ping(ctx); err != nil {
		t.Fatalf("SandboxHandle.Ping: %v", err)
	}
	if _, err := handle.Touch(ctx); err != nil {
		t.Fatalf("SandboxHandle.Touch: %v", err)
	}

	if err := sb.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if _, err := handle.Ping(ctx); err == nil {
		t.Fatal("SandboxHandle.Ping on stopped sandbox succeeded; want error")
	}
	if _, err := handle.Touch(ctx); err == nil {
		t.Fatal("SandboxHandle.Touch on stopped sandbox succeeded; want error")
	}

	refreshed, err := handle.Refresh(ctx)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if refreshed.Status() != microsandbox.SandboxStatusStopped {
		t.Fatalf("status after stopped ping/touch = %q, want stopped", refreshed.Status())
	}
}

// TestSandboxModifyDryRun plans a modification against a live sandbox without
// applying it, on both the live Sandbox and the name-addressed handle.
func TestSandboxModifyDryRun(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-modify-" + t.Name()

	sb, err := createSandbox(t, ctx, name, microsandbox.WithImage(goIntegrationImage))
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
		_ = microsandbox.RemoveSandbox(context.Background(), name)
	})

	plan, err := sb.Modify(ctx, microsandbox.ModifyOptions{
		CPUs:   2,
		Labels: map[string]string{"tier": "gold"},
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("Sandbox.Modify: %v", err)
	}
	if plan.Sandbox != name || plan.Applied {
		t.Fatalf("Sandbox.Modify plan = %+v", plan)
	}
	if plan.Policy != microsandbox.ModificationPolicyNoRestart {
		t.Fatalf("Sandbox.Modify policy = %q", plan.Policy)
	}
	fields := map[string]bool{}
	for _, change := range plan.Changes {
		fields[change.Field] = true
	}
	if !fields["cpus"] || !fields["label"] {
		t.Fatalf("Sandbox.Modify changes = %+v", plan.Changes)
	}

	handle, err := microsandbox.GetSandbox(ctx, name)
	if err != nil {
		t.Fatalf("GetSandbox: %v", err)
	}
	handlePlan, err := handle.Modify(ctx, microsandbox.ModifyOptions{
		Env:    map[string]string{"MODIFIED": "1"},
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("SandboxHandle.Modify: %v", err)
	}
	if handlePlan.Sandbox != name || handlePlan.Applied {
		t.Fatalf("SandboxHandle.Modify plan = %+v", handlePlan)
	}
}

// TestSandboxRemove removes the persisted state of a stopped sandbox.
func TestSandboxRemove(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-rmpersist-" + t.Name()

	sb, err := createSandbox(t, ctx, name, microsandbox.WithImage(goIntegrationImage))
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	if err := sb.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := sb.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := microsandbox.RemoveSandbox(ctx, name); err != nil {
		t.Fatalf("RemoveSandbox: %v", err)
	}

	// Sandbox should no longer be discoverable.
	if _, err := microsandbox.GetSandbox(ctx, name); err == nil {
		t.Errorf("GetSandbox still succeeds after RemoveSandbox")
	} else if !microsandbox.IsKind(err, microsandbox.ErrSandboxNotFound) {
		t.Errorf("expected ErrSandboxNotFound, got %v", err)
	}
}

// TestOwnsLifecycleSignature exercises the (bool, error) signature added in
// this change set. For a sandbox created via CreateSandbox, ownership must
// be true; the error must be nil.
func TestOwnsLifecycleSignature(t *testing.T) {
	sb := newTestSandbox(t)

	owns, err := sb.OwnsLifecycle()
	if err != nil {
		t.Fatalf("OwnsLifecycle: %v", err)
	}
	if !owns {
		t.Error("OwnsLifecycle: want true for handle returned by CreateSandbox")
	}
	// Best-effort variant agrees.
	if !sb.OwnsLifecycleOrFalse() {
		t.Error("OwnsLifecycleOrFalse: want true")
	}
}

// TestOwnsLifecycleAfterDetach verifies that OwnsLifecycle drops to false
// once the handle is detached, *if* the handle survives the call. After
// Detach the sandbox handle is invalidated and the FFI returns false; we
// only assert that no panic occurs and a value comes back.
func TestOwnsLifecycleAfterDetachOrConnect(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-ownsconn-" + t.Name()

	sb, err := createSandbox(t, ctx, name,
		microsandbox.WithImage(goIntegrationImage),
		microsandbox.WithDetached(),
	)
	if err != nil {
		t.Fatalf("CreateSandbox detached: %v", err)
	}
	if err := sb.Detach(ctx); err != nil {
		t.Fatalf("Detach: %v", err)
	}

	// Reattach via Connect — the connect handle does NOT own the lifecycle.
	h, err := microsandbox.GetSandbox(ctx, name)
	if err != nil {
		t.Fatalf("GetSandbox: %v", err)
	}
	sb2, err := h.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb2.Stop(stopCtx)
		_ = sb2.Close()
		_ = microsandbox.RemoveSandbox(context.Background(), name)
	})

	owns, err := sb2.OwnsLifecycle()
	if err != nil {
		t.Fatalf("OwnsLifecycle on connect handle: %v", err)
	}
	if owns {
		t.Error("OwnsLifecycle on a Connect()'d handle should be false")
	}
}

// TestWithReplace verifies that creating a sandbox with the same name
// while one already exists succeeds when WithReplace is set.
func TestWithReplace(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-replace-" + t.Name()

	first, err := createSandbox(t, ctx, name, microsandbox.WithImage(goIntegrationImage))
	if err != nil {
		t.Fatalf("first CreateSandbox: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = first.Stop(stopCtx)
		_ = first.Close()
		_ = microsandbox.RemoveSandbox(context.Background(), name)
	})

	// Without replace, the second create should fail.
	if _, err := microsandbox.CreateSandbox(ctx, name, microsandbox.WithImage(goIntegrationImage)); err == nil {
		t.Error("expected error creating duplicate sandbox without WithReplace")
	}

	// With replace, it should succeed.
	second, err := createSandbox(t, ctx, name,
		microsandbox.WithImage(goIntegrationImage),
		microsandbox.WithReplace(),
	)
	if err != nil {
		t.Fatalf("CreateSandbox with WithReplace: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = second.Stop(stopCtx)
		_ = second.Close()
	})
	if second.Name() != name {
		t.Errorf("Name: got %q want %q", second.Name(), name)
	}
}

// TestWithUser runs `whoami` inside the sandbox and verifies the configured
// user is visible. Alpine images include the `nobody` user by default.
func TestWithUser(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-user-" + t.Name()

	sb, err := createSandbox(t, ctx, name,
		microsandbox.WithImage(goIntegrationImage),
		microsandbox.WithUser("nobody"),
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

	out, err := sb.Shell(ctx, "whoami")
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	if !strings.Contains(out.Stdout(), "nobody") {
		t.Errorf("whoami: got %q want it to contain 'nobody'", out.Stdout())
	}
}

// TestWithHostname verifies that the configured hostname is reflected by
// `hostname` inside the guest.
func TestWithHostname(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-hostname-" + t.Name()

	sb, err := createSandbox(t, ctx, name,
		microsandbox.WithImage(goIntegrationImage),
		microsandbox.WithHostname("go-sdk-test-host"),
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

	out, err := sb.Shell(ctx, "hostname")
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	if !strings.Contains(out.Stdout(), "go-sdk-test-host") {
		t.Errorf("hostname: got %q", out.Stdout())
	}
}

// TestWithWorkdir verifies that pwd inside the guest matches the configured
// workdir.
func TestWithWorkdir(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-workdir-" + t.Name()

	sb, err := createSandbox(t, ctx, name,
		microsandbox.WithImage(goIntegrationImage),
		microsandbox.WithWorkdir("/var/log"),
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

	out, err := sb.Shell(ctx, "pwd")
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	if !strings.Contains(out.Stdout(), "/var/log") {
		t.Errorf("pwd: got %q", out.Stdout())
	}
}

// TestWithEnvVisibleInsideSandbox verifies that vars passed through WithEnv
// are exported into the guest environment.
func TestWithEnvVisibleInsideSandbox(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-env-" + t.Name()

	sb, err := createSandbox(t, ctx, name,
		microsandbox.WithImage(goIntegrationImage),
		microsandbox.WithEnv(map[string]string{
			"FOO_INTEGRATION": "bar-marker-123",
			"BAZ_INTEGRATION": "qux-marker-456",
		}),
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

	out, err := sb.Shell(ctx, "echo $FOO_INTEGRATION:$BAZ_INTEGRATION")
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	if !strings.Contains(out.Stdout(), "bar-marker-123:qux-marker-456") {
		t.Errorf("env: got %q", out.Stdout())
	}
}

// TestSandboxHandleListsRichMetadata verifies that ListSandboxes returns
// SandboxHandle values populated with status, config_json, and timestamps.
func TestSandboxHandleListsRichMetadata(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-handle-rich-" + t.Name()

	sb, err := createSandbox(t, ctx, name, microsandbox.WithImage(goIntegrationImage))
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})

	handles, err := microsandbox.ListSandboxes(ctx)
	if err != nil {
		t.Fatalf("ListSandboxes: %v", err)
	}
	var found *microsandbox.SandboxHandle
	for _, h := range handles {
		if h.Name() == name {
			found = h
			break
		}
	}
	if found == nil {
		t.Fatalf("sandbox %q missing from ListSandboxes", name)
	}
	if found.Status() == "" {
		t.Error("Status: empty")
	}
	if found.ConfigJSON() == "" {
		t.Error("ConfigJSON: empty")
	}
	if found.CreatedAt().IsZero() {
		t.Error("CreatedAt: zero — listing should populate timestamps")
	}
}

// TestSandboxHandleStopKill exercises name-addressed stop / kill on a
// sandbox via SandboxHandle.
func TestSandboxHandleStopKill(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-handle-stop-" + t.Name()

	sb, err := createSandbox(t, ctx, name, microsandbox.WithImage(goIntegrationImage))
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	t.Cleanup(func() { _ = sb.Close() })

	h, err := microsandbox.GetSandbox(ctx, name)
	if err != nil {
		t.Fatalf("GetSandbox: %v", err)
	}
	if err := h.Stop(ctx); err != nil {
		t.Fatalf("SandboxHandle.Stop: %v", err)
	}
	// After stop, kill should be a no-op or error cleanly — just verify it
	// doesn't panic.
	_ = h.Kill(ctx)
	if err := h.Remove(ctx); err != nil {
		t.Errorf("SandboxHandle.Remove: %v", err)
	}
}

// TestSandboxHandleMetricsByName verifies that SandboxHandle.Metrics returns
// a snapshot for a running sandbox without needing a live handle.
func TestSandboxHandleMetricsByName(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)

	// Give the metrics sampler a beat to take its first sample.
	if _, err := sb.Shell(ctx, "true"); err != nil {
		t.Fatalf("Shell: %v", err)
	}
	time.Sleep(1200 * time.Millisecond)

	h, err := microsandbox.GetSandbox(ctx, sb.Name())
	if err != nil {
		t.Fatalf("GetSandbox: %v", err)
	}
	m, err := h.Metrics(ctx)
	if err != nil {
		t.Fatalf("Metrics: %v", err)
	}
	if m.Uptime <= 0 {
		t.Errorf("Uptime: got %v", m.Uptime)
	}
}
