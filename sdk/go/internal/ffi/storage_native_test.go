//go:build storage_native && !windows

package ffi

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Opt in with MSB_STORAGE_NATIVE_LIBRARY pointing at a freshly built native library. Each run
// gets a private home and fresh process, so the native default backend cannot reach user data.
func TestStorageNativeReportsAndPruning(t *testing.T) {
	library := os.Getenv("MSB_STORAGE_NATIVE_LIBRARY")
	if library == "" {
		t.Skip("requires a native storage library via MSB_STORAGE_NATIVE_LIBRARY")
	}
	if os.Getenv("MSB_STORAGE_NATIVE_CHILD") != "1" {
		home := t.TempDir()
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStorageNativeReportsAndPruning$", "-test.count=1")
		for _, entry := range os.Environ() {
			key, _, _ := strings.Cut(entry, "=")
			switch key {
			case "MSB_HOME", "MSB_CONFIG_PATH", "MSB_BACKEND", "MSB_PROFILE", "MSB_STORAGE_NATIVE_CHILD":
				continue
			}
			child.Env = append(child.Env, entry)
		}
		child.Env = append(child.Env, "MSB_HOME="+home, "MSB_CONFIG_PATH="+filepath.Join(home, "test-config.json"), "MSB_BACKEND=local", "MSB_STORAGE_NATIVE_CHILD=1")
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("native storage smoke: %v\n%s", err, output)
		}
		return
	}
	if err := Load(library); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root := filepath.Join(os.Getenv("MSB_HOME"), "cache", "memory")
	branch := filepath.Join(root, "branches", "branch_fixture-4096.ram")
	lock := strings.TrimSuffix(branch, ".ram") + ".handoff-lock"
	snapshot := filepath.Join(root, "snapshots", "sha256-"+strings.Repeat("a", 64)+"-4096.ram")
	for path, size := range map[string]int{branch: 8192, lock: 0, snapshot: 4096} {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, make([]byte, size), 0600); err != nil {
			t.Fatal(err)
		}
	}
	usage, err := StorageUsage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if usage.BranchMemory.Count == nil || *usage.BranchMemory.Count != 1 || usage.BranchMemory.LogicalBytes == nil || *usage.BranchMemory.LogicalBytes != 8192 || usage.SnapshotMemory.LogicalBytes == nil || *usage.SnapshotMemory.LogicalBytes != 4096 || usage.Images.InUse != nil {
		t.Fatalf("incorrect native storage accounting: %+v", usage)
	}
	preview, err := PruneStorage(ctx, StoragePruneOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if !preview.DryRun || preview.FilesRemoved != 0 || preview.LogicalBytesRemoved != 0 || preview.PhysicalBytesReclaimed != nil || len(preview.Entries) != 2 {
		t.Fatalf("invalid native dry run: %+v", preview)
	}
	for _, entry := range preview.Entries {
		if entry.State != "reclaimable" {
			t.Fatalf("unused backing not reclaimable: %+v", entry)
		}
		if _, err := os.Stat(entry.Path); err != nil {
			t.Fatalf("preview removed backing: %v", err)
		}
	}
	reservation, err := os.Open(lock)
	if err != nil {
		t.Fatal(err)
	}
	defer reservation.Close()
	if err := syscall.Flock(int(reservation.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	pinned, err := PruneStorage(ctx, StoragePruneOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	protected := false
	for _, entry := range pinned.Entries {
		if entry.Path == branch {
			protected = entry.State == "pending_handoff"
		}
	}
	if !protected {
		t.Fatalf("held native handoff reservation was not protected: %+v", pinned.Entries)
	}
	if err := syscall.Flock(int(reservation.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	pin, err := os.Open(branch)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	if err := syscall.Flock(int(pin.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	pinned, err = PruneStorage(ctx, StoragePruneOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	protected = false
	for _, entry := range pinned.Entries {
		if entry.Path == branch {
			protected = entry.State == "in_use"
		}
	}
	if !protected {
		t.Fatalf("held native RAM pin was not protected: %+v", pinned.Entries)
	}
	if err := syscall.Flock(int(pin.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	for _, path := range []string{branch, snapshot} {
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
	}
	result, err := PruneStorage(ctx, StoragePruneOptions{OlderThanSeconds: 600})
	if err != nil {
		t.Fatal(err)
	}
	if result.DryRun || result.FilesRemoved != 2 || result.LogicalBytesRemoved != 12288 || result.PhysicalBytesReclaimed != nil || len(result.Entries) != 2 {
		t.Fatalf("incorrect native removal report: %+v", result)
	}
	for _, entry := range result.Entries {
		if entry.State != "removed" {
			t.Fatalf("eligible backing not removed: %+v", entry)
		}
		if _, err := os.Stat(entry.Path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("removed backing remains: %s (%v)", entry.Path, err)
		}
	}
	if _, err := os.Stat(lock); err != nil {
		t.Fatalf("stable handoff lock was removed: %v", err)
	}
	empty, err := PruneStorage(ctx, StoragePruneOptions{DryRun: true})
	if err != nil || len(empty.Entries) != 0 || empty.FilesRemoved != 0 {
		t.Fatalf("expected empty subsequent sweep: %+v (%v)", empty, err)
	}
	// A nonzero unknown handle proves the optional receiver symbol loaded: absence returns
	// unsupported before dispatch, whereas the native registry must reject this exact identity.
	sandbox := &Sandbox{}
	sandbox.handle.Store(^uint64(0))
	var nativeError *Error
	if _, err := sandbox.StorageUsage(ctx); !errors.As(err, &nativeError) || nativeError.Kind != KindInvalidHandle {
		t.Fatalf("native sandbox usage export did not validate the handle: %v", err)
	}
}
