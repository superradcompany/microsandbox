//go:build cow_live && microsandbox_ffi_path

package microsandbox

import (
	"context"
	"fmt"
	"os"
	"strconv"
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

// Exercise the public Go options through the native ABI with dirty block pages.
// Timing alone cannot distinguish an ignored policy from incidental kernel writeback.
func TestOwnedDiskGuestFlushLive(t *testing.T) {
	if os.Getenv("MSB_GUEST_FLUSH_LIVE") != "1" {
		t.Skip("requires matching live bundle")
	}
	for _, operation := range []string{"disk", "full", "branch", "pause"} {
		for _, policy := range []GuestFlush{GuestFlushAuto, GuestFlushRequired, GuestFlushSkip} {
			t.Run(operation+"-"+string(policy), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				name := fmt.Sprintf("owned-go-%d-%s-%s", os.Getpid(), operation, policy)
				source, err := CreateSandbox(ctx, name, WithImage("alpine"), WithMemory(1024),
					WithRootDisk(RootDisk.Managed(512)), WithMounts(map[string]MountConfig{
						"/data": Mount.Owned(OwnedVolumeOptions{Kind: VolumeKindDisk, SizeMiB: 512}),
					}))
				if err != nil {
					t.Fatal(err)
				}
				track := func(s *Sandbox) {
					t.Cleanup(func() {
						cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
						defer done()
						if err := s.Stop(cleanup); err != nil {
							t.Error(err)
						}
						s.Close()
					})
				}
				track(source)
				exec := func(s *Sandbox, command string) string {
					result, err := s.Exec(ctx, "sh", []string{"-c", "set -eu; " + command})
					if err != nil {
						t.Fatal(err)
					}
					if !result.Success() {
						t.Fatalf("guest command failed (%d): %s", result.ExitCode(), result.Stderr())
					}
					return strings.TrimSpace(result.Stdout())
				}
				exec(source, "echo 99 > /proc/sys/vm/dirty_background_ratio; echo 99 > /proc/sys/vm/dirty_ratio; "+
					"echo 60000 > /proc/sys/vm/dirty_writeback_centisecs; echo 60000 > /proc/sys/vm/dirty_expire_centisecs; "+
					"dd if=/dev/urandom of=/dirty bs=1M count=64 2>/dev/null; cp /dirty /data/dirty")
				checksum := strings.Fields(exec(source, "sha256sum /dirty"))[0]
				dirty := func() int {
					value, err := strconv.Atoi(exec(source, "awk '/^Dirty:/ {print $2}' /proc/meminfo"))
					if err != nil {
						t.Fatal(err)
					}
					return value
				}
				before := dirty()
				if before < 96*1024 {
					t.Fatalf("fixture not dirty: %d KiB", before)
				}
				var snapshot *SnapshotArtifact
				var child *Sandbox
				switch operation {
				case "pause":
					if policy == GuestFlushAuto {
						err = source.Pause(ctx)
					} else {
						err = source.PauseWithGuestFlush(ctx, policy)
					}
					if err == nil {
						err = source.Resume(ctx)
					}
				case "branch":
					child, err = source.Branch(ctx, name+"-child", WithBranchGuestFlush(policy))
				default:
					snapshot, err = Snapshot.Create(ctx, SnapshotCreateOptions{
						Name: "dirty", FromSandbox: name, Full: operation == "full", GuestFlush: policy,
					})
				}
				if err != nil {
					t.Fatal(err)
				}
				if child != nil {
					track(child)
				}
				after := dirty()
				flush := policy == GuestFlushRequired || (operation == "disk" && policy == GuestFlushAuto)
				if flush && after >= before/4 {
					t.Fatalf("writeback missing: %d -> %d KiB", before, after)
				}
				if !flush && after <= before/2 {
					t.Fatalf("unexpected writeback: %d -> %d KiB", before, after)
				}
				if snapshot != nil {
					child, err = RestoreSandbox(ctx, snapshot.Reference(), name+"-child")
					if err != nil {
						t.Fatal(err)
					}
					track(child)
				}
				if child != nil && (operation != "disk" || flush) {
					for _, path := range []string{"/dirty", "/data/dirty"} {
						if strings.Fields(exec(child, "sha256sum "+path))[0] != checksum {
							t.Fatalf("restored data differs: %s", path)
						}
					}
				}
			})
		}
	}
}
