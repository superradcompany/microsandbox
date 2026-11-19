//go:build readiness_native && !windows

package microsandbox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"testing"
)

// Real separately compiled libraries intentionally reuse native registration IDs.
// A process-wide function table would send these IDs to the wrong registry.
func TestProviderCoexistenceNative(t *testing.T) {
	localPath, remotePath := os.Getenv("MSB_GO_LOCAL_PROVIDER"), os.Getenv("MSB_GO_REMOTE_PROVIDER")
	if localPath == "" || remotePath == "" {
		t.Skip("requires both Go native providers")
	}
	t.Setenv("MSB_HOME", t.TempDir())
	if fullPath := os.Getenv("MSB_GO_FULL_PROVIDER"); fullPath != "" {
		// Resolve a default resource destination before registering lean providers.
		// Later registration must preserve the full library on that destination.
		if err := LoadFullNative(fullPath); err != nil {
			t.Fatal(err)
		}
		if _, err := configuredContext(); err != nil {
			t.Fatal(err)
		}
	}
	remote, err := LoadNativeProvider(remotePath, ContextRemote)
	if err != nil {
		t.Fatal(err)
	}
	local, err := LoadNativeProvider(localPath, ContextLocal)
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := configuredContext()
	if err != nil {
		t.Fatal(err)
	}
	defaultLibrary := pinned.nativeContext().Library()
	if os.Getenv("MSB_GO_FULL_PROVIDER") != "" && defaultLibrary == local.library {
		t.Fatal("lean registration replaced the retained full provider")
	}
	localContext, err := local.NewLocalContext(LocalOptions{Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer provider-key" {
			t.Error("wrong credentials")
		}
		w.Header().Set("Content-Type", "application/json")
		observation := map[string]any{"id": "remote-id", "name": "task", "slug": "task", "org_id": "org", "status": "running", "ephemeral": false, "created_at": "2026-11-15T00:00:00Z"}
		if r.URL.Path == "/v1/sandboxes" {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{observation}})
		} else {
			_ = json.NewEncoder(w).Encode(observation)
		}
	}))
	defer server.Close()
	if _, err := remote.NewRemoteContext("hosted-key"); err != nil {
		t.Fatal("provider hosted constructor:", err)
	}
	if _, err := remote.NewRemoteContextWithURL("", "key"); err == nil {
		t.Fatal("provider accepted empty explicit URL")
	}
	selected, err := remote.NewRemoteContextWithURL(server.URL, "provider-key")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MSB_BACKEND", "cloud")
	t.Setenv("MSB_API_URL", server.URL)
	t.Setenv("MSB_API_KEY", "provider-key")
	configured, err := configuredContext()
	if err != nil || configured.Kind() != ContextRemote || configured.nativeContext().Library() != remote.library {
		t.Fatal("configured remote provider was not selected", err)
	}
	t.Setenv("MSB_BACKEND", "local")
	ctx := context.Background()
	sb, err := selected.Sandboxes().Get(ctx, "task")
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close()
	// Call the actual lean library: workspace feature unification must not
	// hide missing resize exports or turn unsupported observation into success.
	for name, observe := range map[string]func() error{
		"status":     func() error { _, err := sb.ResizeStatus(ctx); return err },
		"operations": func() error { _, err := sb.ResizeOperations(ctx); return err },
		"wait":       func() error { _, err := sb.WaitUntilResized(ctx); return err },
	} {
		if err := observe(); !IsKind(err, ErrUnsupportedOperation) {
			t.Fatalf("remote resize %s: expected unsupported, got %v", name, err)
		}
	}
	if sb.ID() != "cloud:remote-id" || sb.Context().Kind() != ContextRemote {
		t.Fatalf("resource lost destination: id=%q kind=%q", sb.ID(), sb.Context().Kind())
	}
	// Registering another local provider cannot redirect an existing remote object.
	if _, err := LoadNativeProvider(localPath, ContextLocal); err != nil {
		t.Fatal(err)
	}
	again, err := configuredContext()
	if err != nil || again.nativeContext().Library() != defaultLibrary {
		t.Fatal("default provider changed", err)
	}
	if _, err := pinned.Sandboxes().List(ctx); err != nil {
		t.Fatal("retained default provider:", err)
	}
	if _, err := localContext.Sandboxes().List(ctx); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	if _, err := sb.Info(ctx); err != nil {
		t.Fatal(err)
	}
	page, err := selected.Sandboxes().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Sandboxes) != 1 {
		t.Fatal("wrong page")
	}
	for _, listed := range page.Sandboxes {
		if _, err := listed.Status(ctx); err != nil {
			t.Fatal(err)
		}
		_ = listed.Close()
	}
	// Cancellation IDs belong to each provider as well as resource IDs.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := selected.Sandboxes().Get(cancelled, "task"); err == nil {
		t.Fatal("cancelled lookup succeeded")
	}
	if _, err := sb.Info(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := remote.NewLocalContext(LocalOptions{}); err == nil {
		t.Fatal("remote provider accepted local construction")
	}
}
