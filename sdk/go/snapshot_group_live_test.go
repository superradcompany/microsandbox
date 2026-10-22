//go:build snapshot_live && microsandbox_ffi_path

package microsandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// This scenario needs a fresh MSB_HOME and a native archive for the current host.
// Guest contents, rather than successful launch alone, establish exact selection.
func TestSnapshotGroupsLive(t *testing.T) {
	archive := os.Getenv("MSB_TEST_GROUP_ARCHIVE")
	if archive == "" {
		t.Skip("requires native archive and isolated MSB_HOME")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	imported, err := Snapshot.Load(ctx, "seed", []string{archive, archive})
	if err != nil {
		t.Fatal(err)
	}
	if len(imported.Added) == 0 || len(imported.Reused) != 0 || imported.OperationID == "" || len(imported.Warnings) != 0 {
		t.Fatalf("initial import: %+v", imported)
	}
	retried, err := Snapshot.Load(ctx, "seed", []string{archive})
	if err != nil {
		t.Fatal(err)
	}
	if len(retried.Added) != 0 || len(retried.Reused) != len(imported.Added) || retried.OperationID == imported.OperationID {
		t.Fatalf("retry: %+v", retried)
	}
	if _, err := Checkpoint.LoadMany(ctx, []string{archive}, SnapshotLoadOptions{Group: "seed"}); err != nil {
		t.Fatal(err)
	}
	seed := imported.Snapshot
	if _, err := seed.Checkpoint(ctx); err == nil || !strings.Contains(err.Error(), "unbound") {
		t.Fatalf("unbound capture: %v", err)
	}
	source, err := seed.SpawnSandbox(ctx, "go-source", WithRestoreCPUs(2), WithRestoreMemory(512))
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func(sandbox *Sandbox) {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sandbox.Stop(cleanupCtx)
		_ = RemoveSandbox(cleanupCtx, sandbox.Name())
		_ = sandbox.Close()
	}
	defer cleanup(source)
	write := func(value string) {
		t.Helper()
		output, err := source.Exec(ctx, "sh", []string{"-c", "echo " + value + " > /go-state; sync"})
		if err != nil || !output.Success() {
			t.Fatalf("write guest: %v %+v", err, output)
		}
	}
	sourceHandle, err := GetSandbox(ctx, source.Name())
	if err != nil {
		t.Fatal(err)
	}
	refreshed, err := sourceHandle.Refresh(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := refreshed.Snapshot(ctx, "handle-history"); err != nil {
		t.Fatal(err)
	}
	sources, err := ListSandboxes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, handle := range sources.Sandboxes {
		if handle.ID() == source.ID() {
			found = true
			if _, err := handle.Snapshot(ctx, "listed-history"); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !found {
		t.Fatal("source missing from listing")
	}

	legacy, err := ffi.SandboxHandleSnapshot(ctx, source.Name(), "legacy-member")
	if err != nil {
		t.Fatal(err)
	}
	if legacy.HeadUpdate == nil || legacy.HeadUpdate.Group != source.Name() {
		t.Fatalf("released native capture symbol changed its group/member interpretation: %+v", legacy)
	}

	write("go-A")
	first, err := source.Snapshot(ctx, "history", WithSnapshotCaptureConfig(SnapshotCaptureConfig{Name: "base", RecordIntegrity: true}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Snapshot(ctx, "history"); err == nil {
		t.Fatal("duplicate creation appended")
	}
	write("go-B")
	second, err := first.Snapshot.Checkpoint(ctx, WithSnapshotCaptureConfig(SnapshotCaptureConfig{Name: "next", RecordIntegrity: true}))
	if err != nil {
		t.Fatal(err)
	}
	if first.HeadUpdate.Head == nil || *first.HeadUpdate.Head != first.Checkpoint.ID() {
		t.Fatal("initial result lost its own head outcome")
	}
	if _, err := first.Snapshot.ClearHead(ctx); err != nil {
		t.Fatal(err)
	}
	if head, err := first.Snapshot.Head(ctx); err != nil || head != nil {
		t.Fatalf("headless state: %v %v", head, err)
	}
	if _, err := first.Snapshot.SpawnSandbox(ctx, ""); err == nil {
		t.Fatal("headless spawn succeeded")
	}
	if _, err := first.Snapshot.SetHead(ctx, "base"); err != nil {
		t.Fatal(err)
	}
	if err := first.Checkpoint.Save(ctx, filepath.Join(os.Getenv("MSB_HOME"), "export.msb"), SnapshotSaveOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Checkpoint.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	if err := source.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := RemoveSandbox(ctx, source.Name()); err != nil {
		t.Fatal(err)
	}
	for index, checkpoint := range []*SnapshotArtifact{first.Checkpoint, second.Checkpoint} {
		_, results := checkpoint.SpawnSandboxWithProgress(ctx, "", WithRestoreCPUs(2), WithRestoreMemory(512))
		result := <-results // Deliberately ignore progress: telemetry must never block completion.
		if result.Err != nil {
			t.Fatal(result.Err)
		}
		child := result.Sandbox
		func() {
			defer cleanup(child)
			if child.Name() == "" {
				t.Error("generated name not returned")
			}
			output, err := child.Exec(ctx, "cat", []string{"/go-state"})
			expected := []string{"go-A", "go-B"}[index]
			if err != nil || strings.TrimSpace(output.Stdout()) != expected {
				t.Fatalf("guest contents: %v %+v", err, output)
			}
			t.Logf("verified %s from %s after source deletion", expected, checkpoint.ID())
		}()
	}
	if _, err := first.Snapshot.Checkpoint(ctx); err == nil {
		t.Fatal("orphaned capture succeeded")
	}
	replacement, err := seed.SpawnSandbox(ctx, source.Name(), WithRestoreCPUs(2), WithRestoreMemory(512))
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup(replacement)
	if _, err := sourceHandle.Snapshot(ctx, "stale-history"); !IsKind(err, ErrSandboxReplaced) {
		t.Fatalf("stale source capture: expected replacement refusal, got %v", err)
	}
	if _, err := Snapshot.Get(ctx, "stale-history"); err == nil {
		t.Fatal("stale capture created a group")
	}

}

// The isolated fixture harness installs complete, incomplete, corrupt and future groups.
// This exercises the real native report/error boundary, not a mocked JSON projection.
func TestSnapshotVerificationCoverageLive(t *testing.T) {
	if os.Getenv("MSB_TEST_VERIFY_GROUPS") != "1" {
		t.Skip("requires isolated verification fixture groups")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, name := range []string{"complete", "incomplete", "corrupt", "future"} {
		t.Run(name, func(t *testing.T) {
			group, err := Snapshot.Get(ctx, name)
			if err != nil {
				t.Fatal(err)
			}
			checkpoint, err := group.Head(ctx)
			if err != nil || checkpoint == nil {
				t.Fatalf("head: %v", err)
			}
			report, err := checkpoint.Verify(ctx)
			if name == "corrupt" || name == "future" {
				if err == nil {
					t.Fatalf("verification accepted %s: %+v", name, report)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if report.Coverage.Kind != name {
				t.Fatalf("coverage: %+v", report.Coverage)
			}
			if name == "incomplete" && len(report.Coverage.Unrecorded) == 0 {
				t.Fatal("missing unchecked payload paths")
			}
		})
	}
}

func TestSnapshotGroupVerificationLive(t *testing.T) {
	if os.Getenv("MSB_TEST_VERIFY_GROUPS") != "1" {
		t.Skip("requires isolated verification fixture groups")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, name := range []string{"complete", "incomplete", "corrupt", "future"} {
		t.Run(name, func(t *testing.T) {
			group, err := Snapshot.Get(ctx, name)
			if err != nil {
				t.Fatal(err)
			}
			report, err := group.Verify(ctx)
			if name == "corrupt" || name == "future" {
				var verification *SnapshotVerificationError
				if !errors.As(err, &verification) {
					t.Fatalf("expected structured verification error, got %T: %v", err, err)
				}
				report = verification.Report
				expected := "invalid"
				if name == "future" {
					expected = "incomplete"
				}
				if report.State != expected {
					t.Fatalf("state: %+v", report)
				}
				if len(report.Checkpoints) != 1 || len(report.Checkpoints[0].Findings) == 0 {
					t.Fatalf("missing per-member failures: %+v", report)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if report.State != name || len(report.Checkpoints) != 1 || report.Checkpoints[0].Report == nil {
					t.Fatalf("report: %+v", report)
				}
				if report.Checkpoints[0].Report.Coverage.Kind != name {
					t.Fatalf("coverage: %+v", report.Checkpoints[0].Report)
				}
			}
		})
	}
}

func TestSnapshotGroupFullVerificationLive(t *testing.T) {
	if os.Getenv("MSB_TEST_FULL_VERIFY_GROUPS") != "1" {
		t.Skip("requires isolated fullverify/fullcorrupt fixture groups")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	group, err := Snapshot.Get(ctx, "fullverify")
	if err != nil {
		t.Fatal(err)
	}
	report, err := group.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if report.State != "incomplete" || report.PayloadHashes == 0 || len(report.Checkpoints) != 1 {
		t.Fatalf("full report: %+v", report)
	}
	artifact := report.Checkpoints[0].Report
	if artifact == nil || artifact.Checkpoint == nil || artifact.Checkpoint.Kind != "verified" || artifact.Checkpoint.Root == "" || artifact.Coverage.Kind != "incomplete" {
		t.Fatalf("full artifact: %+v", artifact)
	}
	corrupt, err := Snapshot.Get(ctx, "fullcorrupt")
	if err != nil {
		t.Fatal(err)
	}
	_, err = corrupt.Verify(ctx)
	var verification *SnapshotVerificationError
	if !errors.As(err, &verification) || verification.Report.State != "invalid" {
		t.Fatalf("corrupt full result: %v", err)
	}
	for _, member := range verification.Report.Checkpoints {
		for _, finding := range member.Findings {
			if finding.Kind == "invalid" && strings.Contains(finding.Detail, "integrity mismatch") {
				return
			}
		}
	}
	t.Fatalf("missing corruption finding: %+v", verification.Report)
}
