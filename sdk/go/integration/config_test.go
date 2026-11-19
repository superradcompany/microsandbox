//go:build integration && microsandbox_ffi_path

package integration

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

// TestSDKVersion is a smoke check on the synchronous SDKVersion accessor.
func TestSDKVersion(t *testing.T) {
	v := microsandbox.SDKVersion()
	if v == "" {
		t.Error("SDKVersion: empty string")
	}
	if !strings.Contains(v, ".") {
		t.Errorf("SDKVersion: %q does not look like semver", v)
	}
}

// TestRuntimeVersion verifies that the loaded library reports a non-empty
// version that the SDK recognises.
func TestRuntimeVersion(t *testing.T) {
	v, err := microsandbox.RuntimeVersion()
	if err != nil {
		t.Fatalf("RuntimeVersion: %v", err)
	}
	if v == "" {
		t.Error("RuntimeVersion: empty")
	}
	t.Logf("runtime version: %s, sdk version: %s", v, microsandbox.SDKVersion())
}

// TestWithShellSetsDefaultShell uses an image where /bin/bash is present
// (alpine ships /bin/sh by default; busybox provides a symlink). We confirm
// that AttachShell would dispatch to the configured shell. Smoke-only:
// AttachShell needs a TTY which we can't supply in tests, so we verify the
// option round-trips through ConfigJSON.
func TestWithShellRoundTripsThroughConfig(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-shell-" + t.Name()

	sb, err := createSandbox(t, ctx, name,
		microsandbox.WithImage(goIntegrationImage),
		microsandbox.WithShell("/bin/sh"),
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

	h, err := microsandbox.GetSandbox(ctx, name)
	if err != nil {
		t.Fatalf("GetSandbox: %v", err)
	}
	if !strings.Contains(liveConfigJSON(t, ctx, h), `"shell"`) ||
		!strings.Contains(liveConfigJSON(t, ctx, h), "/bin/sh") {
		t.Errorf("Shell not visible in ConfigJSON: %s", liveConfigJSON(t, ctx, h))
	}
}

// TestWithEntrypointVisibleInConfig verifies that the user-workload
// entrypoint round-trips into SandboxConfig. We don't trigger the
// entrypoint here (it's the agent's per-request workload, not init).
func TestWithEntrypointVisibleInConfig(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-entrypoint-" + t.Name()

	sb, err := createSandbox(t, ctx, name,
		microsandbox.WithImage(goIntegrationImage),
		microsandbox.WithEntrypoint("/bin/sh", "-c", "echo hi"),
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

	h, err := microsandbox.GetSandbox(ctx, name)
	if err != nil {
		t.Fatalf("GetSandbox: %v", err)
	}
	cfg := liveConfigJSON(t, ctx, h)
	if !strings.Contains(cfg, "echo hi") || !strings.Contains(cfg, "entrypoint") {
		t.Errorf("Entrypoint not visible in ConfigJSON: %s", cfg)
	}
}

// TestWithInitAuto verifies that the `auto` init sentinel round-trips
// through the FFI as a HandoffInit on the config. We don't assert on the
// resolved init binary because that depends on the image.
func TestWithInitAuto(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-init-auto-" + t.Name()

	sb, err := createSandbox(t, ctx, name,
		microsandbox.WithImage(goIntegrationImage),
		microsandbox.WithInit(microsandbox.Init.Auto()),
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

	h, err := microsandbox.GetSandbox(ctx, name)
	if err != nil {
		t.Fatalf("GetSandbox: %v", err)
	}
	if !strings.Contains(liveConfigJSON(t, ctx, h), `"auto"`) {
		t.Errorf("Init.Auto not visible in ConfigJSON: %s", liveConfigJSON(t, ctx, h))
	}
	parsed, err := h.Config(ctx)
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	var init struct {
		Cmd string `json:"cmd"`
	}
	if err := json.Unmarshal(parsed.Spec.Init, &init); err != nil {
		t.Fatalf("decode inspected init: %v", err)
	}
	if init.Cmd != "auto" {
		t.Errorf("Init.Auto not visible in parsed Config: %+v", parsed.Spec.Init)
	}
}

// TestWithLogLevelRoundTrip verifies that WithLogLevel surfaces in the
// persisted ConfigJSON.
//
// WithLogLevel and WithQuietLogs are mutually exclusive in the underlying
// SDK: `quiet_logs()` sets log_level to None, so calling both with quiet
// last clears the level. They're tested separately for that reason.
func TestWithLogLevelRoundTrip(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-log-" + t.Name()

	sb, err := createSandbox(t, ctx, name,
		microsandbox.WithImage(goIntegrationImage),
		microsandbox.WithLogLevel(microsandbox.LogLevelInfo),
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

	h, err := microsandbox.GetSandbox(ctx, name)
	if err != nil {
		t.Fatalf("GetSandbox: %v", err)
	}
	cfg := liveConfigJSON(t, ctx, h)
	if !strings.Contains(cfg, `"info"`) {
		t.Errorf("LogLevel not in ConfigJSON: %s", cfg)
	}
}

// TestWithQuietLogsClearsLogLevel verifies that WithQuietLogs results in
// a null log_level in the persisted ConfigJSON (quiet is a "clear the
// level" intent, not its own field).
func TestWithQuietLogsClearsLogLevel(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-quiet-" + t.Name()

	sb, err := createSandbox(t, ctx, name,
		microsandbox.WithImage(goIntegrationImage),
		microsandbox.WithQuietLogs(),
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

	h, err := microsandbox.GetSandbox(ctx, name)
	if err != nil {
		t.Fatalf("GetSandbox: %v", err)
	}
	cfg := liveConfigJSON(t, ctx, h)
	if !strings.Contains(cfg, `"log_level":null`) {
		t.Errorf("expected log_level:null in ConfigJSON, got: %s", cfg)
	}
}

// TestWithMaxDurationAndIdleTimeoutCreates is a creation smoke test:
// timeouts are wall-clock-driven and not deterministic in CI, so we only
// confirm the runtime accepts the configuration without erroring.
func TestWithMaxDurationAndIdleTimeoutCreates(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-timeouts-" + t.Name()

	sb, err := createSandbox(t, ctx, name,
		microsandbox.WithImage(goIntegrationImage),
		microsandbox.WithMaxDuration(2*time.Hour),
		microsandbox.WithIdleTimeout(30*time.Minute),
	)
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
		_ = microsandbox.RemoveSandbox(stopCtx, name)
	})

	h, err := microsandbox.GetSandbox(ctx, name)
	if err != nil {
		t.Fatalf("GetSandbox: %v", err)
	}
	defer h.Close()
	cfg, err := h.Config(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for field, want := range map[string]float64{"max_duration_secs": 7200, "idle_timeout_secs": 1800} {
		if got := cfg.Spec.Lifecycle[field]; got != want {
			t.Errorf("%s = %v, want %v", field, got, want)
		}
	}
}

func TestContextRejectsFractionalLifecycleLimits(t *testing.T) {
	sandboxes, err := microsandbox.SandboxLocal()
	if err != nil {
		t.Fatal(err)
	}
	ctx := integrationCtx(t)
	check := func(method string, err error) {
		t.Helper()
		if !microsandbox.IsKind(err, microsandbox.ErrInvalidConfig) || !strings.Contains(err.Error(), "whole number of seconds") {
			t.Errorf("%s returned %v, want a whole-second validation error", method, err)
		}
	}

	create := microsandbox.WithIdleTimeout(1500 * time.Millisecond)
	restore := microsandbox.WithRestoreMaxDuration(time.Nanosecond)
	_, err = sandboxes.Create(ctx, "invalid-duration", create)
	check("create", err)
	_, err = sandboxes.ConnectOrCreate(ctx, "invalid-duration", create)
	check("connect or create", err)
	_, created := sandboxes.CreateWithProgress(ctx, "invalid-duration", create)
	check("create with progress", (<-created).Err)
	_, err = sandboxes.Restore(ctx, "missing-snapshot", "invalid-duration", restore)
	check("restore", err)
	_, restored := sandboxes.RestoreWithProgress(ctx, "missing-snapshot", "invalid-duration", restore)
	check("restore with progress", (<-restored).Err)
}

// TestWithScriptsRoundTrip verifies scripts pass through to the runtime.
func TestWithScriptsRoundTrip(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-scripts-" + t.Name()

	sb, err := createSandbox(t, ctx, name,
		microsandbox.WithImage(goIntegrationImage),
		microsandbox.WithScripts(map[string]string{
			"hello": "echo hello-from-script",
			"date":  "date +%Y",
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

	h, err := microsandbox.GetSandbox(ctx, name)
	if err != nil {
		t.Fatalf("GetSandbox: %v", err)
	}
	cfg := liveConfigJSON(t, ctx, h)
	if !strings.Contains(cfg, "hello-from-script") {
		t.Errorf("scripts not visible in ConfigJSON: %s", cfg)
	}
}

// TestWithPullPolicyRoundTrip verifies each PullPolicy preset round-trips.
// We don't assert on actual pull behaviour because the cache state varies.
func TestWithPullPolicyRoundTrip(t *testing.T) {
	for _, p := range []microsandbox.PullPolicy{
		microsandbox.PullPolicyAlways,
		microsandbox.PullPolicyIfMissing,
		microsandbox.PullPolicyNever,
	} {
		t.Run(string(p), func(t *testing.T) {
			ctx := integrationCtx(t)
			name := "go-sdk-pull-" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-"))
			sb, err := createSandbox(t, ctx, name,
				microsandbox.WithImage(goIntegrationImage),
				microsandbox.WithPullPolicy(p),
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
		})
	}
}
