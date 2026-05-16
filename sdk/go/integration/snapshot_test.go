//go:build integration && microsandbox_ffi_path

package integration

import (
	"context"
	"fmt"
	"hash/fnv"
	"path/filepath"
	"testing"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

func TestSandboxHandleSnapshotAndWithSnapshotFork(t *testing.T) {
	ctx := integrationCtx(t)
	baseName := uniqueIntegrationName(t, "go-sdk-snapshot-base")
	forkName := uniqueIntegrationName(t, "go-sdk-snapshot-fork")
	snapshotName := uniqueIntegrationName(t, "go-sdk-snapshot")

	t.Cleanup(func() {
		removeSandboxBestEffort(forkName)
		removeSandboxBestEffort(baseName)
		removeSnapshotBestEffort(snapshotName)
	})

	base, err := microsandbox.CreateSandbox(ctx, baseName, microsandbox.WithImage("alpine:3.19"))
	if err != nil {
		t.Fatalf("CreateSandbox base: %v", err)
	}
	if _, err := base.StopAndWait(ctx); err != nil {
		t.Fatalf("StopAndWait base: %v", err)
	}
	if err := base.Close(); err != nil {
		t.Fatalf("Close base: %v", err)
	}

	baseHandle, err := microsandbox.GetSandbox(ctx, baseName)
	if err != nil {
		t.Fatalf("GetSandbox base: %v", err)
	}
	artifact, err := baseHandle.Snapshot(ctx, snapshotName)
	if err != nil {
		t.Fatalf("SandboxHandle.Snapshot: %v", err)
	}
	if artifact.Digest() == "" {
		t.Fatal("Snapshot artifact has empty digest")
	}
	if artifact.ImageRef() == "" {
		t.Fatal("Snapshot artifact has empty image ref")
	}
	if artifact.SizeBytes() == 0 {
		t.Fatal("Snapshot artifact has zero size")
	}

	report, err := artifact.Verify(ctx)
	if err != nil {
		t.Fatalf("SnapshotArtifact.Verify: %v", err)
	}
	if report.Digest == "" || report.Path == "" {
		t.Fatalf("Verify returned incomplete report: %+v", report)
	}

	handle, err := microsandbox.Snapshot.Get(ctx, snapshotName)
	if err != nil {
		t.Fatalf("Snapshot.Get: %v", err)
	}
	if handle.Digest() != artifact.Digest() {
		t.Fatalf("Snapshot.Get digest = %q, want %q", handle.Digest(), artifact.Digest())
	}
	if gotName := handle.Name(); gotName == nil || *gotName != snapshotName {
		t.Fatalf("Snapshot.Get name = %v, want %q", gotName, snapshotName)
	}

	opened, err := handle.Open(ctx)
	if err != nil {
		t.Fatalf("SnapshotHandle.Open: %v", err)
	}
	if opened.Digest() != artifact.Digest() {
		t.Fatalf("SnapshotHandle.Open digest = %q, want %q", opened.Digest(), artifact.Digest())
	}

	found := false
	handles, err := microsandbox.Snapshot.List(ctx)
	if err != nil {
		t.Fatalf("Snapshot.List: %v", err)
	}
	for _, h := range handles {
		if h.Digest() == artifact.Digest() {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Snapshot.List did not include digest %q", artifact.Digest())
	}

	fork, err := microsandbox.CreateSandbox(ctx, forkName, microsandbox.WithSnapshot(snapshotName))
	if err != nil {
		t.Fatalf("CreateSandbox with WithSnapshot: %v", err)
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = fork.StopAndWait(stopCtx)
		_ = fork.Close()
	}()

	// Verify the fork is a working sandbox sourced from the snapshot:
	// /etc/alpine-release exists in the alpine image's rootfs, so reading
	// it back via the fork confirms WithSnapshot resolved + mounted the
	// snapshot's rootfs rather than handing back an empty fs.
	got, err := fork.FS().ReadString(ctx, "/etc/alpine-release")
	if err != nil {
		t.Fatalf("ReadString /etc/alpine-release from fork: %v", err)
	}
	if got == "" {
		t.Fatalf("/etc/alpine-release empty in fork")
	}

	// TODO: when stop-flush ensures guest writes are persisted into the
	// upper layer before the VM halts, restore a marker write+read here
	// to prove the snapshot captured user data, not just the image.
}

func TestSandboxHandleSnapshotToAndSnapshotDirectoryOps(t *testing.T) {
	ctx := integrationCtx(t)
	baseName := uniqueIntegrationName(t, "go-sdk-snapshotto-base")
	snapshotDir := filepath.Join(t.TempDir(), "artifact")

	t.Cleanup(func() {
		removeSandboxBestEffort(baseName)
		removeSnapshotBestEffort(snapshotDir)
	})

	base, err := microsandbox.CreateSandbox(ctx, baseName, microsandbox.WithImage("alpine:3.19"))
	if err != nil {
		t.Fatalf("CreateSandbox base: %v", err)
	}
	if _, err := base.StopAndWait(ctx); err != nil {
		t.Fatalf("StopAndWait base: %v", err)
	}
	if err := base.Close(); err != nil {
		t.Fatalf("Close base: %v", err)
	}

	baseHandle, err := microsandbox.GetSandbox(ctx, baseName)
	if err != nil {
		t.Fatalf("GetSandbox base: %v", err)
	}
	artifact, err := baseHandle.SnapshotTo(ctx, snapshotDir)
	if err != nil {
		t.Fatalf("SandboxHandle.SnapshotTo: %v", err)
	}
	if artifact.Path() != snapshotDir {
		t.Fatalf("SnapshotTo path = %q, want %q", artifact.Path(), snapshotDir)
	}

	opened, err := microsandbox.Snapshot.Open(ctx, snapshotDir)
	if err != nil {
		t.Fatalf("Snapshot.Open: %v", err)
	}
	if opened.Digest() != artifact.Digest() {
		t.Fatalf("Snapshot.Open digest = %q, want %q", opened.Digest(), artifact.Digest())
	}

	dirEntries, err := microsandbox.Snapshot.ListDir(ctx, filepath.Dir(snapshotDir))
	if err != nil {
		t.Fatalf("Snapshot.ListDir: %v", err)
	}
	found := false
	for _, snap := range dirEntries {
		if snap.Digest() == artifact.Digest() {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Snapshot.ListDir did not include digest %q", artifact.Digest())
	}

	indexed, err := microsandbox.Snapshot.Reindex(ctx, filepath.Dir(snapshotDir))
	if err != nil {
		t.Fatalf("Snapshot.Reindex: %v", err)
	}
	if indexed == 0 {
		t.Fatal("Snapshot.Reindex indexed zero artifacts")
	}

	archivePath := filepath.Join(t.TempDir(), "snapshot.tar")
	if err := microsandbox.Snapshot.Export(ctx, snapshotDir, archivePath,
		microsandbox.SnapshotExportOptions{PlainTar: true}); err != nil {
		t.Fatalf("Snapshot.Export: %v", err)
	}

	importDir := filepath.Join(t.TempDir(), "imported")
	imported, err := microsandbox.Snapshot.Import(ctx, archivePath, importDir)
	if err != nil {
		t.Fatalf("Snapshot.Import: %v", err)
	}
	t.Cleanup(func() {
		removeSnapshotBestEffort(imported.Path())
	})
	if imported.Digest() != artifact.Digest() {
		t.Fatalf("Snapshot.Import digest = %q, want %q", imported.Digest(), artifact.Digest())
	}
}

func uniqueIntegrationName(t *testing.T, prefix string) string {
	t.Helper()
	h := fnv.New32a()
	_, _ = h.Write([]byte(t.Name()))
	return fmt.Sprintf("%s-%08x-%d", prefix, h.Sum32(), time.Now().UnixNano()%1_000_000_000)
}

func removeSandboxBestEffort(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if h, err := microsandbox.GetSandbox(ctx, name); err == nil {
		_ = h.Stop(ctx)
	}
	_ = microsandbox.RemoveSandbox(context.Background(), name)
}

func removeSnapshotBestEffort(pathOrName string) {
	_ = microsandbox.Snapshot.Remove(context.Background(), pathOrName, true)
}
