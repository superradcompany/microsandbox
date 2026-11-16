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
	remote, err := LoadNativeProvider(remotePath, ContextRemote)
	if err != nil {
		t.Fatal(err)
	}
	local, err := LoadNativeProvider(localPath, ContextLocal)
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := defaultLocalContext()
	if err != nil {
		t.Fatal(err)
	}
	defaultLibrary := pinned.inner.Library()
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
	selected, err := remote.NewRemoteContext(server.URL, "provider-key")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sb, err := selected.Sandboxes().Get(ctx, "task")
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close()
	if sb.ID() != "cloud:remote-id" || sb.Context().Kind() != ContextRemote {
		t.Fatalf("resource lost destination: id=%q kind=%q", sb.ID(), sb.Context().Kind())
	}
	// Registering another local provider cannot redirect an existing remote object.
	if _, err := LoadNativeProvider(localPath, ContextLocal); err != nil {
		t.Fatal(err)
	}
	again, err := defaultLocalContext()
	if err != nil || again.inner.Library() != defaultLibrary {
		t.Fatal("default provider changed", err)
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
