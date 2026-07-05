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

func TestSandboxHandleSnapshotAndWithFromSnapshotFork(t *testing.T) {
	ctx := integrationCtx(t)
	baseName := uniqueIntegrationName(t, "go-sdk-snapshot-base")
	forkName := uniqueIntegrationName(t, "go-sdk-snapshot-fork")
	snapshotName := uniqueIntegrationName(t, "go-sdk-snapshot")

	t.Cleanup(func() {
		removeSandboxBestEffort(forkName)
		removeSandboxBestEffort(baseName)
		removeSnapshotBestEffort(snapshotName)
	})

	base, err := createSandbox(t, ctx, baseName, microsandbox.WithImage(goIntegrationImage))
	if err != nil {
		t.Fatalf("CreateSandbox base: %v", err)
	}
	if err := base.Stop(ctx); err != nil {
		t.Fatalf("Stop base: %v", err)
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

	fork, err := createSandbox(t, ctx, forkName, microsandbox.WithFromSnapshot(snapshotName))
	if err != nil {
		t.Fatalf("CreateSandbox with WithFromSnapshot: %v", err)
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = fork.Stop(stopCtx)
		_ = fork.Close()
	}()

	// Verify the fork is a working sandbox sourced from the snapshot:
	// /etc/alpine-release exists in the alpine image's rootfs, so reading
	// it back via the fork confirms WithFromSnapshot resolved + mounted the
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

func TestSnapshotCreateAndSnapshotDirectoryOps(t *testing.T) {
	ctx := integrationCtx(t)
	baseName := uniqueIntegrationName(t, "go-sdk-snapcreate-base")
	snapshotName := uniqueIntegrationName(t, "go-sdk-snapcreate")

	t.Cleanup(func() {
		removeSandboxBestEffort(baseName)
		removeSnapshotBestEffort(snapshotName)
	})

	base, err := createSandbox(t, ctx, baseName, microsandbox.WithImage(goIntegrationImage))
	if err != nil {
		t.Fatalf("CreateSandbox base: %v", err)
	}
	if err := base.Stop(ctx); err != nil {
		t.Fatalf("Stop base: %v", err)
	}
	if err := base.Close(); err != nil {
		t.Fatalf("Close base: %v", err)
	}

	artifact, err := microsandbox.Snapshot.Create(ctx, microsandbox.SnapshotCreateOptions{
		Name:        snapshotName,
		FromSandbox: baseName,
	})
	if err != nil {
		t.Fatalf("Snapshot.Create: %v", err)
	}
	snapshotDir := artifact.Path()
	if filepath.Base(snapshotDir) != snapshotName {
		t.Fatalf("Snapshot.Create path = %q, want basename %q", snapshotDir, snapshotName)
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
	if err := microsandbox.Snapshot.Save(ctx, snapshotName, archivePath,
		microsandbox.SnapshotSaveOptions{PlainTar: true}); err != nil {
		t.Fatalf("Snapshot.Save: %v", err)
	}

	importDir := filepath.Join(t.TempDir(), "imported")
	imported, err := microsandbox.Snapshot.Load(ctx, archivePath, importDir)
	if err != nil {
		t.Fatalf("Snapshot.Load: %v", err)
	}
	t.Cleanup(func() {
		removeSnapshotBestEffort(imported.Path())
	})
	if imported.Digest() != artifact.Digest() {
		t.Fatalf("Snapshot.Load digest = %q, want %q", imported.Digest(), artifact.Digest())
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
