//go:build readiness_native && !windows

package microsandbox

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// Isolate the native context cache from other tests and the developer's home.
func TestGetRunningSandboxNative(t *testing.T) {
	library := os.Getenv("MSB_READINESS_NATIVE_LIBRARY")
	if library == "" {
		t.Skip("requires MSB_READINESS_NATIVE_LIBRARY")
	}
	if os.Getenv("MSB_READINESS_NATIVE_CHILD") != "1" {
		home := t.TempDir()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGetRunningSandboxNative$", "-test.count=1")
		for _, entry := range os.Environ() {
			key, _, _ := strings.Cut(entry, "=")
			if !strings.HasPrefix(key, "MSB_") {
				child.Env = append(child.Env, entry)
			}
		}
		child.Env = append(child.Env, "MSB_READINESS_NATIVE_LIBRARY="+library, "MSB_READINESS_NATIVE_CHILD=1", "MSB_HOME="+home, "MSB_CONFIG_PATH="+filepath.Join(home, "config.json"))
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("native readiness: %v\n%s", err, output)
		}
		return
	}
	var running atomic.Bool
	var starts atomic.Int32
	var lookups atomic.Int32
	var unavailable atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/sandboxes":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"id": "original", "name": "task", "org_id": "org", "slug": "task", "status": "stopped", "ephemeral": false, "created_at": "2026-11-15T00:00:00.123456789Z"}}, "next_cursor": "next"})
			return
		case "GET /v1/sandboxes/by-name/task", "GET /v1/sandboxes/original":
			lookups.Add(1)
			if unavailable.Load() {
				w.WriteHeader(503)
				_, _ = w.Write([]byte(`{"error":"unavailable"}`))
				return
			}
		case "POST /v1/sandboxes/original/start":
			starts.Add(1)
			running.Store(true)
		default:
			t.Errorf("unexpected provider request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
			return
		}
		status := "stopped"
		if running.Load() {
			status = "running"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "original", "name": "task", "org_id": "org", "slug": "task",
			"status": status, "ephemeral": false, "created_at": "2026-11-15T00:00:00.123456789Z",
		})
	}))
	defer server.Close()
	if err := ffi.Load(library); err != nil {
		t.Fatal(err)
	}
	remote, err := NewRemoteContextWithURL(server.URL, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	page, err := remote.Sandboxes().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Sandboxes) != 1 || page.NextCursor == nil || *page.NextCursor != "next" {
		t.Fatalf("unexpected page: %+v", page)
	}
	if lookups.Load() != 0 || starts.Load() != 0 {
		t.Fatal("list performed per-item lookups or started a resource")
	}
	listed := page.Sandboxes[0]
	defer listed.Close()
	if err := listed.WaitForStatus(ctx, SandboxStatusStopped); err != nil {
		t.Fatal(err)
	}
	waiting, stopWaiting := context.WithTimeout(ctx, 30*time.Millisecond)
	err = listed.WaitForStatus(waiting, SandboxStatusRunning)
	stopWaiting()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled wait: %v", err)
	}
	if starts.Load() != 0 {
		t.Fatal("status wait started the sandbox")
	}
	if status, err := listed.Status(ctx); err != nil || status != SandboxStatusStopped {
		t.Fatalf("listed status: %v %v", status, err)
	}
	// Missing persisted configuration must fail, not manufacture defaults.
	if _, err := listed.Config(ctx); err == nil {
		t.Fatal("missing provider config returned defaults")
	}
	if starts.Load() != 0 {
		t.Fatal("inspection started a resource")
	}
	if err := listed.EnsureRunning(ctx); err != nil {
		t.Fatal(err)
	}
	if err := listed.EnsureRunning(ctx); err != nil {
		t.Fatal(err)
	}
	if status, err := listed.Status(ctx); err != nil || status != SandboxStatusRunning {
		t.Fatalf("fresh status: %v %v", status, err)
	}
	observation, err := listed.Info(ctx)
	if err != nil || observation.CreatedAt == nil || observation.CreatedAt.Nanosecond() != 123456789 {
		t.Fatalf("timestamp precision lost: %+v %v", observation, err)
	}
	unavailable.Store(true)
	if _, err := listed.Info(ctx); err == nil {
		t.Fatal("failed lookup returned stale observation")
	}
	unavailable.Store(false)
	unprepared, err := remote.Sandboxes().Get(ctx, "task")
	if err != nil {
		t.Fatal(err)
	}
	if unprepared.ID() != listed.ID() {
		t.Fatal("get/list identity mismatch")
	}
	_ = unprepared.Close()
	for range 2 {
		sb, err := remote.Sandboxes().GetRunning(ctx, "task")
		if err != nil {
			t.Fatal(err)
		}
		if sb.Name() != "task" || sb.ID() == "" {
			t.Fatalf("missing identity: %q/%q", sb.Name(), sb.ID())
		}
		// Detach must neither consume the registered handle nor require exclusive
		// ownership. Subsequent live inspection and repeated detach still work.
		for range 2 {
			if err := sb.Detach(ctx); err != nil {
				t.Fatal(err)
			}
		}
		if owned, err := sb.OwnsLifecycle(); err != nil || owned {
			t.Fatalf("ownership after detach: %v %v", owned, err)
		}
		if err := sb.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if starts.Load() != 1 {
		t.Fatalf("expected one startup, got %d", starts.Load())
	}
}
