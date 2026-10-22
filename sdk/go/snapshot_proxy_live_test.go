//go:build snapshot_live

package microsandbox

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// The parent harness serves fixed HTTP bytes through a local authenticated SOCKS fixture.
func TestSnapshotProxyLive(t *testing.T) {
	archive, address := os.Getenv("MSB_PROXY_ARCHIVE"), os.Getenv("MSB_PROXY_ADDRESS")
	if archive == "" || address == "" || os.Getenv("MSB_BOOT_NATIVE") == "" {
		t.Skip("requires local proxy fixture, archive, native library and disposable VM home")
	}
	if err := ffi.Load(os.Getenv("MSB_BOOT_NATIVE")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	loaded, err := Snapshot.Load(ctx, "go-proxy-history", []string{archive})
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
	for index, name := range []string{"go-proxy-direct", "go-proxy-progress"} {
		t.Run(name, func(t *testing.T) {
			opts := []RestoreOption{
				WithRestoreConfig(RestoreConfig{Ports: []PortBinding{{HostPort: 0, GuestPort: 18080}}}),
				WithRestoreNetworkPolicy(NetworkPolicy.AllowAll()),
				WithRestoreProxy(SOCKS5Proxy(address).Credentials("fixture", SecretSourceEnv("MSB_SDK_PROXY_FIXTURE_PASSWORD"))),
			}
			var child *Sandbox
			if index == 0 {
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
			result, err := child.Exec(ctx, "wget", []string{"-T", "3", "-qO-", "http://198.51.100.10:19090/probe"})
			if err != nil || !result.Success() || result.Stdout() != "snapshot-destination-proxy\n" {
				t.Fatalf("authenticated proxy response: %v", err)
			}
		})
	}
}
