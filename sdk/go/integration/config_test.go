//go:build integration && microsandbox_ffi_path

package integration

import (
	"context"
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

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
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
	if !strings.Contains(h.ConfigJSON(), `"shell"`) ||
		!strings.Contains(h.ConfigJSON(), "/bin/sh") {
		t.Errorf("Shell not visible in ConfigJSON: %s", h.ConfigJSON())
	}
}

// TestWithEntrypointVisibleInConfig verifies that the user-workload
// entrypoint round-trips into SandboxConfig. We don't trigger the
// entrypoint here (it's the agent's per-request workload, not init).
func TestWithEntrypointVisibleInConfig(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-entrypoint-" + t.Name()

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
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
	cfg := h.ConfigJSON()
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

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
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
	if !strings.Contains(h.ConfigJSON(), `"auto"`) {
		t.Errorf("Init.Auto not visible in ConfigJSON: %s", h.ConfigJSON())
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

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
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
	cfg := h.ConfigJSON()
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

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
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
	cfg := h.ConfigJSON()
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

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
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
	})

	h, err := microsandbox.GetSandbox(ctx, name)
	if err != nil {
		t.Fatalf("GetSandbox: %v", err)
	}
	cfg := h.ConfigJSON()
	// Sub-second durations are rounded up to whole seconds; here they're
	// already whole, so the seconds count must appear.
	if !strings.Contains(cfg, "max_duration") || !strings.Contains(cfg, "7200") {
		t.Errorf("MaxDuration not in ConfigJSON: %s", cfg)
	}
	if !strings.Contains(cfg, "idle_timeout") || !strings.Contains(cfg, "1800") {
		t.Errorf("IdleTimeout not in ConfigJSON: %s", cfg)
	}
}

// TestWithScriptsRoundTrip verifies scripts pass through to the runtime.
func TestWithScriptsRoundTrip(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-scripts-" + t.Name()

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
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
	cfg := h.ConfigJSON()
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
			name := "go-sdk-pull-" + t.Name()
			sb, err := microsandbox.CreateSandbox(ctx, name,
				microsandbox.WithImage("alpine:3.19"),
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
