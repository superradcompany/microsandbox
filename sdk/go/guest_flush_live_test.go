//go:build cow_live && microsandbox_ffi_path

package microsandbox

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// Run against a fresh MSB_HOME and a matching MSB_PATH/native library. This checks
// public Go options through the dynamic ABI, not just their JSON representation.
func TestGuestFlushLive(t *testing.T) {
	if os.Getenv("MSB_GUEST_FLUSH_LIVE") != "1" {
		t.Skip("requires matching live bundle")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	name := fmt.Sprintf("flush-go-%d", os.Getpid())
	source, err := CreateSandbox(ctx, name, WithImage("alpine"), WithRootDisk(RootDisk.Managed(512)), WithMemory(256))
	if err != nil {
		t.Fatal(err)
	}
	track := func(sandbox *Sandbox) {
		t.Cleanup(func() {
			cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
			defer done()
			if err := sandbox.Stop(cleanup); err != nil {
				t.Error(err)
			}
			sandbox.Close()
		})
	}
	track(source)
	if _, err := source.Exec(ctx, "sh", []string{"-c", "echo retained > /dev/shm/flush-marker; echo disk > /flush-marker"}); err != nil {
		t.Fatal(err)
	}
	handle, err := GetSandbox(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.PauseWithGuestFlush(ctx, GuestFlushRequired); err != nil {
		t.Fatal(err)
	}
	if err := handle.PauseWithGuestFlush(ctx, GuestFlushRequired); err != nil {
		t.Fatal(err)
	}
	if _, err := handle.Snapshot(ctx, "paused-disk"); err != nil {
		t.Fatal(err)
	}
	if err := handle.Resume(ctx); err != nil {
		t.Fatal(err)
	}
	for _, policy := range []GuestFlush{GuestFlushAuto, GuestFlushRequired, GuestFlushSkip} {
		snapshot, err := Snapshot.Create(ctx, SnapshotCreateOptions{
			Name: string(policy), FromSandbox: name, Full: true, GuestFlush: policy,
		})
		if err != nil {
			t.Fatal(err)
		}
		child, err := RestoreSandbox(ctx, snapshot.Reference(), name+"-restored-"+string(policy))
		if err != nil {
			t.Fatal(err)
		}
		track(child)
		result, err := child.Exec(ctx, "cat", []string{"/dev/shm/flush-marker"})
		if err != nil || strings.TrimSpace(result.Stdout()) != "retained" {
			t.Fatalf("%s restore lost RAM: %v", policy, err)
		}
	}
	for i, branch := range []func(context.Context, string, ...BranchOption) (*Sandbox, error){source.Branch, handle.Branch} {
		child, err := branch(ctx, fmt.Sprintf("%s-branch-%d", name, i), WithBranchGuestFlush(GuestFlushRequired))
		if err != nil {
			t.Fatal(err)
		}
		track(child)
		result, err := child.Exec(ctx, "cat", []string{"/dev/shm/flush-marker"})
		if err != nil || strings.TrimSpace(result.Stdout()) != "retained" {
			t.Fatalf("branch lost RAM: %v", err)
		}
	}
}
