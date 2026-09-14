//go:build cow_live && microsandbox_ffi_path

package microsandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This exercises the public SDK against a matching development runtime/kernel bundle.
func TestBranchMany(t *testing.T) {
	if os.Getenv("MSB_BATCH_LIVE") != "1" {
		t.Skip("requires matching live bundle")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	name := fmt.Sprintf("batch-go-%d", os.Getpid())
	source, err := CreateSandbox(ctx, name, WithImage("mirror.gcr.io/library/alpine:3.20"), WithRootDisk(RootDisk.Managed(512)), WithMemory(256))
	if err != nil {
		t.Fatal(err)
	}
	children := []*Sandbox{}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		for _, child := range append(children, source) {
			if err := child.Stop(cleanup); err != nil {
				t.Error(err)
			}
			child.Close()
		}
	})
	if _, err := source.Exec(ctx, "sh", []string{"-c", "echo original > /dev/shm/batch-marker"}); err != nil {
		t.Fatal(err)
	}
	handle, err := GetSandbox(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	for _, branch := range []func(context.Context, []string, ...BranchOption) ([]BranchOutcome, error){source.BranchMany, handle.BranchMany} {
		names := []string{fmt.Sprintf("%s-%d-a", name, len(children)), fmt.Sprintf("%s-%d-b", name, len(children))}
		outcomes, err := branch(ctx, names)
		if err != nil {
			t.Fatal(err)
		}
		for _, outcome := range outcomes {
			if outcome.Sandbox != nil {
				children = append(children, outcome.Sandbox)
			}
		}
		if len(outcomes) != len(names) {
			t.Fatal("wrong result count")
		}
		for i, outcome := range outcomes {
			if outcome.Error != nil || outcome.Name != names[i] || outcome.Sandbox == nil {
				t.Fatalf("bad outcome: %+v", outcome)
			}
			if outcome.Sandbox.ID() == "" {
				t.Fatal("batch child lost its persisted identity")
			}
			// These methods use the returned stable identity rather than the native handle.
			observed, err := outcome.Sandbox.WaitForStatus(ctx, SandboxStatusRunning)
			if err != nil {
				t.Fatalf("cannot observe batch child by identity: %v", err)
			}
			if observed.ID() != outcome.Sandbox.ID() {
				t.Fatal("batch child identity differs from persisted sandbox")
			}
			result, err := outcome.Sandbox.Exec(ctx, "cat", []string{"/dev/shm/batch-marker"})
			if err != nil || strings.TrimSpace(result.Stdout()) != "original" {
				t.Fatalf("lost captured RAM: %v", err)
			}
		}
	}
	if _, err := source.BranchMany(ctx, nil); err == nil {
		t.Fatal("empty batch accepted")
	}
	if _, err := source.BranchMany(ctx, []string{"duplicate", "duplicate"}); err == nil {
		t.Fatal("duplicate names accepted")
	}
	if _, err := children[0].Exec(ctx, "sh", []string{"-c", "echo private > /dev/shm/batch-marker"}); err != nil {
		t.Fatal(err)
	}
	for _, other := range append(children[1:], source) {
		result, err := other.Exec(ctx, "cat", []string{"/dev/shm/batch-marker"})
		if err != nil || strings.TrimSpace(result.Stdout()) != "original" {
			t.Fatalf("child write escaped private memory: %v", err)
		}
	}
}

// This exercises the public SDK against a matching development runtime/kernel bundle.
func TestCowResidentCapture(t *testing.T) {
	if os.Getenv("MSB_COW_LIVE") != "1" {
		t.Skip("requires matching live bundle")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	name := fmt.Sprintf("cow8-go-%d", os.Getpid())
	source, err := CreateSandbox(ctx, name, WithImage("alpine"), WithRootDisk(RootDisk.Managed(512)), WithMemory(256))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := source.Stop(context.Background()); err != nil {
			t.Error(err)
		}
	})
	if _, err := source.Exec(ctx, "sh", []string{"-c", "echo source > /dev/shm/sdk-marker"}); err != nil {
		t.Fatal(err)
	}
	if err := source.Pause(ctx); err != nil {
		t.Fatal(err)
	}
	paused, err := GetSandbox(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	if paused.Status() != SandboxStatusPaused {
		t.Fatalf("got status %s", paused.Status())
	}
	branched, err := paused.Branch(ctx, name+"-paused-branch")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := branched.Stop(context.Background()); err != nil {
			t.Error(err)
		}
		branched.Close()
	})
	branchResult, err := branched.Exec(ctx, "cat", []string{"/dev/shm/sdk-marker"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(branchResult.Stdout()) != "source" {
		t.Fatal("branch lost captured RAM")
	}
	snapshot, err := Snapshot.Create(ctx, SnapshotCreateOptions{Name: name + "-full", FromSandbox: name, Full: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(snapshot.Path(), "snapshot.json")); err != nil {
		t.Fatal(err)
	}
	if err := paused.Resume(ctx); err != nil {
		t.Fatal(err)
	}
	// The returned artifact path selects the exact member in its snapshot group.
	child, err := RestoreSandbox(ctx, snapshot.Path(), name+"-child", WithForked())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := child.Stop(context.Background()); err != nil {
			t.Error(err)
		}
	})
	result, err := child.Exec(ctx, "cat", []string{"/dev/shm/sdk-marker"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(result.Stdout()) != "source" {
		t.Fatal("child lost captured memory")
	}
	if _, err := child.Exec(ctx, "sh", []string{"-c", "echo child > /dev/shm/sdk-marker"}); err != nil {
		t.Fatal(err)
	}
	result, err = source.Exec(ctx, "cat", []string{"/dev/shm/sdk-marker"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(result.Stdout()) != "source" {
		t.Fatal("child changed source memory")
	}
	if err := child.Pause(ctx); err != nil {
		t.Fatal(err)
	}
	descendant, err := child.Branch(ctx, name+"-branch")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := descendant.Stop(context.Background()); err != nil {
			t.Error(err)
		}
		descendant.Close()
	})
	branchResult, err = descendant.Exec(ctx, "cat", []string{"/dev/shm/sdk-marker"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(branchResult.Stdout()) != "child" {
		t.Fatal("branch lost private writes")
	}
	if err := child.Resume(ctx); err != nil {
		t.Fatal(err)
	}
}
