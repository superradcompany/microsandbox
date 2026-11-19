//go:build readiness_native && !windows

package microsandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

func TestExplicitContextsNative(t *testing.T) {
	library := os.Getenv("MSB_READINESS_NATIVE_LIBRARY")
	if library == "" {
		t.Skip("requires MSB_READINESS_NATIVE_LIBRARY")
	}
	if os.Getenv("MSB_CONTEXT_NATIVE_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestExplicitContextsNative$", "-test.count=1")
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "MSB_") {
				child.Env = append(child.Env, entry)
			}
		}
		child.Env = append(child.Env, "MSB_READINESS_NATIVE_LIBRARY="+library, "MSB_CONTEXT_NATIVE_CHILD=1", "MSB_HOME="+t.TempDir(), "MSB_GO_REMOTE_PROVIDER="+os.Getenv("MSB_GO_REMOTE_PROVIDER"))
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("native contexts: %v\n%s", err, output)
		}
		return
	}
	if err := ffi.Load(library); err != nil {
		t.Fatal(err)
	}
	hosted, err := NewRemoteContext("hosted-key")
	if err != nil || hosted.Kind() != ContextRemote {
		t.Fatalf("hosted constructor: %v", err)
	}
	if _, err := NewRemoteContext(""); err == nil {
		t.Fatal("empty API key accepted")
	}
	if _, err := NewRemoteContextWithURL(" ", "key"); err == nil {
		t.Fatal("empty explicit endpoint silently selected hosted service")
	}
	urls := map[string]string{}
	provider := func(id string) *RemoteContext {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer key-"+id {
				t.Errorf("context credentials crossed destinations")
			}
			if r.Method != "GET" {
				t.Errorf("lookup started or mutated resource: %s", r.Method)
				w.WriteHeader(500)
				return
			}
			observation := map[string]any{"id": id, "name": "task", "slug": "task", "org_id": "org", "status": "running", "ephemeral": false, "created_at": "2026-11-15T00:00:00Z"}
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/v1/sandboxes" {
				_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{observation}})
			} else {
				_ = json.NewEncoder(w).Encode(observation)
			}
		}))
		t.Cleanup(server.Close)
		urls[id] = server.URL
		destination, err := NewRemoteContextWithURL(server.URL, "key-"+id)
		if err != nil {
			t.Fatal(err)
		}
		return destination
	}
	a, b := provider("a"), provider("b")
	if _, err := SandboxRemote(); err == nil {
		t.Fatal("missing credentials accepted")
	}
	if _, err := VolumeRemote(); err == nil {
		t.Fatal("missing credentials accepted")
	}
	if _, err := SnapshotRemote(); err == nil {
		t.Fatal("missing credentials accepted")
	}
	t.Setenv("MSB_API_URL", urls["a"])
	t.Setenv("MSB_API_KEY", "key-a")
	t.Setenv("MSB_BACKEND", "local")
	for _, tc := range []struct {
		envURL, envKey string
		options        []RemoteContextOption
	}{
		{urls["a"], "key-a", []RemoteContextOption{WithRemoteComputeType(ComputeShared)}},
		{urls["a"], "wrong", []RemoteContextOption{WithRemoteAPIKey("key-a")}},
		{urls["b"], "key-a", []RemoteContextOption{WithRemoteURL(urls["a"])}},
	} {
		t.Setenv("MSB_API_URL", tc.envURL)
		t.Setenv("MSB_API_KEY", tc.envKey)
		remote, err := NewRemoteContextWithOptions(tc.options...)
		if err != nil {
			t.Fatal(err)
		}
		task, err := remote.Sandboxes().Get(context.Background(), "task")
		if err != nil {
			t.Fatal(err)
		}
		if task.ID() != "cloud:a" {
			t.Errorf("unexpected destination: %s", task.ID())
		}
		task.Close()
	}
	t.Setenv("MSB_API_URL", urls["a"])
	collection, err := SandboxRemote()
	if err != nil {
		t.Fatal(err)
	}
	vr, err := VolumeRemote()
	if err != nil || vr.Context().Kind() != ContextRemote {
		t.Fatal("volume remote selector", err)
	}
	sr, err := SnapshotRemote()
	if err != nil || sr.Context().Kind() != ContextRemote {
		t.Fatal("snapshot remote selector", err)
	}
	t.Setenv("MSB_BACKEND", "remote")
	routed, err := GetSandbox(context.Background(), "task")
	if err != nil {
		t.Fatal(err)
	}
	defer routed.Close()
	if routed.ID() != "cloud:a" {
		t.Fatalf("configured lookup reached %q", routed.ID())
	}
	sl, err := SandboxLocal()
	if err != nil || sl.Context().Kind() != ContextLocal {
		t.Fatal("sandbox local selector", err)
	}
	vl, err := VolumeLocal()
	if err != nil || vl.Context().Kind() != ContextLocal {
		t.Fatal("volume local selector", err)
	}
	snl, err := SnapshotLocal()
	if err != nil || snl.Context().Kind() != ContextLocal {
		t.Fatal("snapshot local selector", err)
	}
	t.Setenv("MSB_API_URL", urls["b"])
	t.Setenv("MSB_API_KEY", "key-b")
	unchanged, err := a.WithOptions()
	if err != nil {
		t.Fatal(err)
	}
	original, err := unchanged.Sandboxes().Get(context.Background(), "task")
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	expectedOriginal, err := collection.Get(context.Background(), "task")
	if err != nil {
		t.Fatal(err)
	}
	defer expectedOriginal.Close()
	if original.ID() != expectedOriginal.ID() {
		t.Fatal("unchanged derivation lost settings")
	}
	for _, option := range []RemoteContextOption{WithRemoteAPIKey(""), WithRemoteURL(""), WithRemoteRequestTimeout(-time.Second), nil} {
		if _, err := a.WithOptions(option); err == nil {
			t.Fatal("invalid override accepted")
		}
	}
	b, err = a.WithOptions(WithRemoteURL(urls["b"]), WithRemoteAPIKey("key-b"))
	if err != nil {
		t.Fatal(err)
	}
	b, err = b.WithOptions(WithRemoteUserAgent("derived-agent"), WithRemoteRequestTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	first, err := collection.Get(ctx, "task")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	cancel() // A finished lookup's request context must not poison the returned resource.
	second, err := SandboxCtx(b).Get(context.Background(), "task")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if first.ID() == second.ID() {
		t.Fatal("destinations collapsed")
	}
	a, b = nil, nil
	runtime.GC()
	again, err := first.Context().Sandboxes().Get(context.Background(), "task")
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if again.ID() != first.ID() {
		t.Fatal("resource context changed")
	}
	page, err := collection.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Sandboxes) != 1 {
		t.Fatal("unexpected page")
	}
	defer page.Sandboxes[0].Close()
	info, err := page.Sandboxes[0].Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.ID != first.ID() {
		t.Fatal("listed resource lost identity")
	}
	if path := os.Getenv("MSB_GO_REMOTE_PROVIDER"); path != "" {
		provider, err := LoadNativeProvider(path, ContextRemote)
		if err != nil {
			t.Fatal(err)
		}
		if provider.library == unchanged.inner.Library() {
			t.Fatal("fixture requires independent native libraries")
		}
		derived, err := unchanged.WithOptions(WithRemoteUserAgent("original-provider"))
		if err != nil {
			t.Fatal(err)
		}
		if derived.inner.Library() != unchanged.inner.Library() {
			t.Fatal("derivation reselected the provider")
		}
		fetched, err := derived.Sandboxes().Get(context.Background(), "task")
		if err != nil {
			t.Fatal(err)
		}
		defer fetched.Close()
		if fetched.ID() != original.ID() {
			t.Fatal("derived context lost its original registration")
		}
	}

	exercisePersistentResources(t)
	var nilRemote *RemoteContext
	if _, err := nilRemote.WithOptions(); err == nil {
		t.Fatal("nil context derivation accepted")
	}
	for _, selected := range []Context{nil, nilRemote, &RemoteContext{}} {
		if _, err := SandboxCtx(selected).Get(context.Background(), "task"); err == nil {
			t.Fatal("nil destination accepted")
		}
	}
}

func exercisePersistentResources(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	firstHome := t.TempDir()
	first, err := NewLocalContext(LocalOptions{Home: firstHome})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewLocalContext(LocalOptions{Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	a, err := first.Volumes().Create(ctx, "same-name")
	if err != nil {
		t.Fatal(err)
	}
	b, err := VolumeCtx(second).Create(ctx, "same-name")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.FS().WriteString(ctx, "value", "a"); err != nil {
		t.Fatal(err)
	}
	if err := b.FS().WriteString(ctx, "value", "b"); err != nil {
		t.Fatal(err)
	}
	fetched, err := a.Context().Volumes().Get(ctx, "same-name")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := fetched.FS().ReadString(ctx, "value"); err != nil || got != "a" {
		t.Fatalf("retained volume = %q, %v", got, err)
	}
	// Exercise the unified retained-resource route, not the legacy root-only helper.
	large := bytes.Repeat([]byte("volume-data"), 200000)
	if err := a.FS().Write(ctx, "large", large); err != nil {
		t.Fatal(err)
	}
	if got, err := fetched.FS().Read(ctx, "large"); err != nil || !bytes.Equal(got, large) {
		t.Fatalf("unified large read: %d bytes, %v", len(got), err)
	}
	if got, err := fetched.FS().ReadString(ctx, "large"); err != nil || got != string(large) {
		t.Fatalf("unified large string read: %d bytes, %v", len(got), err)
	}
	info, err := a.Info(ctx)
	if err != nil || info.ID != a.ID() || info.Kind != a.Kind() || info.Kind != VolumeKindDir {
		t.Fatalf("volume info = %+v, %v", info, err)
	}
	disk, err := first.Volumes().Create(ctx, "scratch", WithVolumeKind(VolumeKindDisk), WithVolumeSize(256))
	if err != nil {
		t.Fatal(err)
	}
	diskInfo, err := disk.Info(ctx)
	if err != nil || diskInfo.Kind != VolumeKindDisk || diskInfo.Kind != disk.Kind() {
		t.Fatalf("disk volume info = %+v, %v", diskInfo, err)
	}
	if err := disk.Destroy(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.Destroy(ctx); err != nil {
		t.Fatal(err)
	}
	replacement, err := first.Volumes().Create(ctx, "same-name")
	if err != nil {
		t.Fatal(err)
	}
	if replacement.ID() == a.ID() {
		t.Fatal("replacement reused volume identity")
	}
	if err := fetched.FS().WriteString(ctx, "value", "stale"); err == nil {
		t.Fatal("stale filesystem reached replacement")
	}
	if err := fetched.Destroy(ctx); err == nil {
		t.Fatal("stale destruction accepted")
	}
	if _, err := replacement.Info(ctx); err != nil {
		t.Fatal("replacement was deleted", err)
	}

	directory := filepath.Join(firstHome, "snapshots", "fixture")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	descriptor := `{"schema":1,"artifact":"snapshot","scope":"disk","created_at":"2026-05-01T12:00:00Z","parent":null,"image":{"ref":"alpine:3.21","manifest_digest":"sha256:` + strings.Repeat("a", 64) + `"},"source_sandbox":"fixture","labels":{},"state":{"kind":"file","format":"raw","fstype":"ext4","upper":{"file":"disk.ext4","size_bytes":4,"integrity":null}},"extensions":{},"requires":[]}`
	if err := os.WriteFile(filepath.Join(directory, "snapshot.json"), []byte(descriptor), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "disk.ext4"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := first.Checkpoints().Open(ctx, directory)
	if err != nil {
		t.Fatal(err)
	}
	fetchedSnapshot, err := snapshot.Context().Checkpoints().Get(ctx, snapshot.ID())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fetchedSnapshot.Manifest(ctx); err != nil {
		t.Fatal(err)
	}
	state, err := fetchedSnapshot.State(ctx)
	if err != nil || state.Kind != "file" {
		t.Fatalf("snapshot state = %+v, %v", state, err)
	}
	if err := os.Remove(filepath.Join(directory, "snapshot.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.Manifest(ctx); err == nil {
		t.Fatal("missing artifact returned cached manifest")
	}
	if err := os.WriteFile(filepath.Join(directory, "snapshot.json"), []byte(descriptor), 0600); err != nil {
		t.Fatal(err)
	}
	if err := fetchedSnapshot.Destroy(ctx, false); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.Manifest(ctx); err == nil {
		t.Fatal("deleted snapshot remained readable")
	}
}

func TestRemoteComputeTypeNative(t *testing.T) {
	library := os.Getenv("MSB_READINESS_NATIVE_LIBRARY")
	if library == "" {
		t.Skip("requires MSB_READINESS_NATIVE_LIBRARY")
	}
	provider, err := LoadNativeProvider(library, ContextRemote)
	if err != nil {
		t.Fatal(err)
	}
	choices := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Compute struct {
				Type string `json:"type"`
			} `json:"compute"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		choices <- body.Compute.Type
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	remote, err := provider.NewRemoteContextWithURL(server.URL, "key")
	if err != nil {
		t.Fatal(err)
	}
	remote, err = remote.WithOptions(WithRemoteComputeType(ComputeShared))
	if err != nil {
		t.Fatal(err)
	}
	retained, err := remote.WithOptions()
	if err != nil {
		t.Fatal(err)
	}
	standard, err := remote.WithOptions(WithRemoteComputeType(ComputeStandard))
	if err != nil {
		t.Fatal(err)
	}
	for _, selected := range []*RemoteContext{retained, standard} {
		if _, err := selected.Sandboxes().Create(context.Background(), "task", WithImage("python")); err == nil {
			t.Fatal("fixture should deny creation")
		}
	}
	if shared, standard := <-choices, <-choices; shared != "shared" || standard != "standard" {
		t.Fatalf("compute choices: %q, %q", shared, standard)
	}
	if _, err := remote.WithOptions(WithRemoteComputeType("invalid")); err == nil {
		t.Fatal("invalid compute type accepted")
	}
}
