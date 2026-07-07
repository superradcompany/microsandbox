//go:build smoke && microsandbox_ffi_path

// FFI smoke tests: load the path-tagged FFI binding and exercise
// non-VM operations.
//
// Run with:
//
//	MICROSANDBOX_FFI_PATH=/path/to/libmicrosandbox_go_ffi.{so,dylib} \
//	    go test -tags "smoke microsandbox_ffi_path" -count=1 ./...
//
// The microsandbox_ffi_path build tag swaps the embedded FFI for a
// reader of the env var (see internal/bundle/bundle_path.go), so the
// test always uses the freshly-built local library rather than the
// (sentinel/release-pinned) embed.

package microsandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/bundle"
)

func smokeSetup(t *testing.T) context.Context {
	t.Helper()
	if os.Getenv(bundle.FFIPathEnv) == "" {
		t.Skipf("%s not set; skipping FFI smoke test", bundle.FFIPathEnv)
	}

	// Anchor under /tmp so sandbox socket paths fit under sun_path (108 bytes).
	dir, err := os.MkdirTemp("/tmp", "msb")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	prev := os.Getenv("MSB_HOME")
	t.Setenv("MSB_HOME", dir)
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
		if prev == "" {
			_ = os.Unsetenv("MSB_HOME")
		} else {
			_ = os.Setenv("MSB_HOME", prev)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	if err := EnsureInstalled(ctx); err != nil {
		t.Fatalf("EnsureInstalled: %v", err)
	}
	return ctx
}

func TestSmokeLibraryLoads(t *testing.T) {
	smokeSetup(t)
	if v := SDKVersion(); v == "" {
		t.Fatal("SDKVersion empty")
	}
}

func TestSmokeRuntimeVersion(t *testing.T) {
	smokeSetup(t)
	v, err := RuntimeVersion()
	if err != nil {
		t.Fatalf("RuntimeVersion: %v", err)
	}
	if v == "" {
		t.Fatal("RuntimeVersion returned empty string")
	}
}

func TestSmokeGetSandboxNotFound(t *testing.T) {
	ctx := smokeSetup(t)
	_, err := GetSandbox(ctx, "smoke-this-sandbox-never-existed")
	if err == nil {
		t.Fatal("expected ErrSandboxNotFound, got nil")
	}
	if !IsKind(err, ErrSandboxNotFound) {
		var me *Error
		if errors.As(err, &me) {
			t.Fatalf("wanted ErrSandboxNotFound, got Kind=%s (%v)", me.Kind, err)
		}
		t.Fatalf("wanted ErrSandboxNotFound, got non-*Error: %v", err)
	}
}

func TestSmokeGetVolumeNotFound(t *testing.T) {
	ctx := smokeSetup(t)
	_, err := GetVolume(ctx, "smoke-this-volume-never-existed")
	if err == nil {
		t.Fatal("expected ErrVolumeNotFound, got nil")
	}
	if !IsKind(err, ErrVolumeNotFound) {
		t.Fatalf("wanted ErrVolumeNotFound, got %v", err)
	}
}

func TestSmokeListSandboxesEmpty(t *testing.T) {
	ctx := smokeSetup(t)
	handles, err := ListSandboxes(ctx)
	if err != nil {
		t.Fatalf("ListSandboxes: %v", err)
	}
	if len(handles) != 0 {
		t.Fatalf("fresh MSB_HOME should have zero sandboxes, got %d", len(handles))
	}
}

func TestSmokeListVolumesEmpty(t *testing.T) {
	ctx := smokeSetup(t)
	vols, err := ListVolumes(ctx)
	if err != nil {
		t.Fatalf("ListVolumes: %v", err)
	}
	if len(vols) != 0 {
		t.Fatalf("fresh MSB_HOME should have zero volumes, got %d", len(vols))
	}
}

func TestSmokeAllSandboxMetricsEmpty(t *testing.T) {
	ctx := smokeSetup(t)
	all, err := AllSandboxMetrics(ctx)
	if err != nil {
		t.Fatalf("AllSandboxMetrics: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("fresh MSB_HOME should have zero running sandboxes, got %d", len(all))
	}
}

func TestSmokeSnapshotListDirEmpty(t *testing.T) {
	ctx := smokeSetup(t)
	dir := t.TempDir()
	snaps, err := Snapshot.ListDir(ctx, dir)
	if err != nil {
		t.Fatalf("Snapshot.ListDir: %v", err)
	}
	if len(snaps) != 0 {
		t.Fatalf("empty dir should yield zero artifacts, got %d", len(snaps))
	}
}

func TestSmokeSnapshotReindexEmpty(t *testing.T) {
	ctx := smokeSetup(t)
	dir := t.TempDir()
	n, err := Snapshot.Reindex(ctx, dir)
	if err != nil {
		t.Fatalf("Snapshot.Reindex: %v", err)
	}
	if n != 0 {
		t.Fatalf("empty dir should index zero artifacts, got %d", n)
	}
}

func TestSmokeSnapshotImportBogusErrors(t *testing.T) {
	ctx := smokeSetup(t)
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "bogus.tar")
	if err := os.WriteFile(archive, make([]byte, 1024), 0o644); err != nil {
		t.Fatalf("write bogus archive: %v", err)
	}
	dest := filepath.Join(tmp, "imported")

	_, err := Snapshot.Import(ctx, archive, dest)
	if err == nil {
		t.Fatal("expected import of bogus archive to fail")
	}
	var me *Error
	if !errors.As(err, &me) {
		t.Fatalf("expected *microsandbox.Error, got %T (%v)", err, err)
	}
	if me.Message == "" && me.Cause == nil {
		t.Fatal("error round-tripped through FFI with no detail")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "manifest") &&
		!strings.Contains(strings.ToLower(err.Error()), "archive") &&
		!strings.Contains(strings.ToLower(err.Error()), "tar") {
		t.Logf("unexpected error message: %v", err)
	}
}

func TestSmokeImageListEmpty(t *testing.T) {
	ctx := smokeSetup(t)
	images, err := Image.List(ctx)
	if err != nil {
		t.Fatalf("Image.List: %v", err)
	}
	if len(images) != 0 {
		t.Fatalf("fresh MSB_HOME should have zero cached images, got %d", len(images))
	}
}
