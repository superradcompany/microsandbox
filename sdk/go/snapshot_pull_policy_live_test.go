//go:build snapshot_live

package microsandbox

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

func TestSnapshotPullPolicyLive(t *testing.T) {
	archive := os.Getenv("MSB_PULL_ARCHIVE")
	if archive == "" || os.Getenv("MSB_BOOT_NATIVE") == "" {
		t.Skip("requires archive, native library and disposable VM home")
	}
	if err := ffi.Load(os.Getenv("MSB_BOOT_NATIVE")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	loaded, err := Snapshot.Load(ctx, "go-pull-history", []string{archive})
	if err != nil {
		t.Fatal(err)
	}
	group := loaded.Snapshot
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		if _, err := group.Remove(cleanup); err != nil {
			t.Error(err)
		}
	}()
	checkpoint, err := group.Head(ctx)
	if err != nil || checkpoint == nil {
		t.Fatalf("head: %v", err)
	}
	for _, policy := range []PullPolicy{PullPolicyNever, PullPolicyIfMissing, PullPolicyAlways} {
		t.Run(string(policy), func(t *testing.T) {
			name := "go-pull-" + string(policy)
			opts := []RestoreOption{WithRestoreConfig(RestoreConfig{Ports: []PortBinding{{HostPort: 0, GuestPort: 18080}}}), WithRestorePullPolicy(policy)}
			var child *Sandbox
			if policy == PullPolicyNever {
				child, err = group.SpawnSandbox(ctx, name, opts...)
			} else {
				_, results := checkpoint.SpawnSandboxWithProgress(ctx, name, opts...)
				result := <-results
				child, err = result.Sandbox, result.Err
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
				defer done()
				if err := child.Stop(cleanup); err != nil {
					t.Error(err)
				}
				if err := child.Close(); err != nil {
					t.Error(err)
				}
				if err := RemoveSandbox(cleanup, name); err != nil {
					t.Error(err)
				}
			}()
			result, err := child.Exec(ctx, "printf", []string{"policy-alive"})
			if err != nil || !result.Success() || result.Stdout() != "policy-alive" {
				t.Fatalf("guest exec: %v", err)
			}
		})
	}
}
