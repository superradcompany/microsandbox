//go:build integration && microsandbox_ffi_path

package integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

func TestCancelledEphemeralCreateReclaimsState(t *testing.T) {
	home := os.Getenv("MSB_HOME")
	if home == "" {
		t.Skip("requires an isolated MSB_HOME to inspect private storage")
	}
	shared, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(shared, "sentinel")
	if err := os.WriteFile(sentinel, []byte("shared data"), 0600); err != nil {
		t.Fatal(err)
	}
	// The fixture needs no network traffic or newer HTTP denial capabilities.
	network := microsandbox.NetworkPolicy.None()
	network.HTTP = &microsandbox.HTTPConfig{DenyResponseFormat: microsandbox.HTTPDenyResponseText}

	for attempt := 0; attempt < 3; attempt++ {
		t.Run(fmt.Sprint(attempt), func(t *testing.T) {
			name := fmt.Sprintf("cancel-ephemeral-%d-%d", os.Getpid(), attempt)
			t.Cleanup(func() { cleanupFailedCreate(t, name) })
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			opts := []microsandbox.SandboxOption{
				microsandbox.WithImage(goIntegrationImage),
				microsandbox.WithMemory(256),
				microsandbox.WithRootDisk(microsandbox.RootDisk.Managed(256)),
				microsandbox.WithNetwork(network),
				microsandbox.WithEphemeral(true),
				microsandbox.WithMounts(map[string]microsandbox.MountConfig{
					"/shared": microsandbox.Mount.Bind(shared, microsandbox.MountOptions{}),
				}),
			}
			results := make(chan microsandbox.CreationResult, 1)
			go func() {
				sandbox, err := microsandbox.CreateSandbox(ctx, name, opts...)
				results <- microsandbox.CreationResult{Sandbox: sandbox, Err: err}
			}()
			// Wait for the provisional row instead of using a timing-dependent
			// deadline that might cancel the image pull before any state exists.
			for {
				handle, err := microsandbox.GetSandbox(ctx, name)
				if err == nil && handle.Status() == microsandbox.SandboxStatusStarting {
					cancel()
					break
				}
				select {
				case result := <-results:
					if result.Sandbox != nil {
						_ = result.Sandbox.Close()
					}
					t.Fatalf("creation finished before cancellation fixture observed Starting: %v", result.Err)
				case <-ctx.Done():
					t.Fatal("never observed Starting before the test deadline")
				case <-time.After(5 * time.Millisecond):
				}
			}
			result := <-results
			if result.Sandbox != nil {
				_ = result.Sandbox.Close()
			}
			if !errors.Is(result.Err, context.Canceled) {
				t.Fatalf("expected creation cancellation, got %v", result.Err)
			}

			// Cleanup is asynchronous. Observe both catalog and disk without
			// booting another VM, which could hide the bug via startup maintenance.
			observe, stop := context.WithTimeout(context.Background(), 20*time.Second)
			defer stop()
			private := filepath.Join(home, "sandboxes", name)
			for {
				_, lookupErr := microsandbox.GetSandbox(observe, name)
				_, diskErr := os.Stat(private)
				if microsandbox.IsKind(lookupErr, microsandbox.ErrSandboxNotFound) && os.IsNotExist(diskErr) {
					break
				}
				select {
				case <-observe.Done():
					t.Fatalf("cancelled create left state: catalog=%v disk=%v", lookupErr, diskErr)
				case <-time.After(20 * time.Millisecond):
				}
			}
			data, err := os.ReadFile(sentinel)
			if err != nil || string(data) != "shared data" {
				t.Fatalf("cleanup changed external storage: %q %v", data, err)
			}

			retry, stopRetry := context.WithTimeout(context.Background(), time.Minute)
			defer stopRetry()
			replacement, err := microsandbox.CreateSandbox(retry, name, opts...)
			if err != nil {
				t.Fatalf("same-name recreation: %v", err)
			}
			defer replacement.Close()
			output, err := replacement.Shell(retry, "test -f /shared/sentinel")
			if err != nil {
				t.Fatalf("replacement cannot use preserved mount: %v", err)
			}
			if output.ExitCode() != 0 {
				t.Fatalf("replacement lost preserved mount: %s", output.Stderr())
			}
		})
	}
}
