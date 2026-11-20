//go:build integration && microsandbox_ffi_path

package integration

import (
	"context"
	"testing"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

func TestUnifiedReceiverImplicitStartupAndOwnership(t *testing.T) {
	created := newTestSandbox(t)
	ctx := integrationCtx(t)
	if err := created.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	selected, err := microsandbox.GetSandbox(ctx, created.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer selected.Close()
	id := selected.ID()
	if status, err := selected.Status(ctx); err != nil || status != microsandbox.SandboxStatusStopped {
		t.Fatalf("inspection started stopped resource: %s, %v", status, err)
	}
	if _, err := selected.Config(ctx); err != nil {
		t.Fatal(err)
	}
	if owns, err := selected.OwnsLifecycle(); err != nil || owns {
		t.Fatalf("lookup acquired ownership: %v, %v", owns, err)
	}
	// A guest operation prepares the receiver and retains the new attached run.
	if _, err := selected.FS().ReadString(ctx, "/etc/os-release"); err != nil {
		t.Fatal(err)
	}
	if err := selected.EnsureRunning(ctx); err != nil {
		t.Fatal(err)
	}
	if selected.ID() != id {
		t.Fatal("implicit startup changed resource identity")
	}
	if owns, err := selected.OwnsLifecycle(); err != nil || !owns {
		t.Fatalf("started run not retained: %v, %v", owns, err)
	}
	borrower, err := microsandbox.GetRunningSandbox(ctx, created.Name())
	if err != nil {
		t.Fatal(err)
	}
	if owns, err := borrower.OwnsLifecycle(); err != nil || owns {
		t.Fatalf("connection stole ownership: %v, %v", owns, err)
	}
	if err := borrower.Close(); err != nil {
		t.Fatal(err)
	}
	if status, err := selected.Status(ctx); err != nil || status != microsandbox.SandboxStatusRunning {
		t.Fatalf("borrower close stopped owner: %s, %v", status, err)
	}
	observer, err := microsandbox.GetSandbox(ctx, created.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	if err := selected.Close(); err != nil {
		t.Fatal(err)
	}
	stopped, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	// Final-owner cleanup uses the platform watchdog/job fallback. Windows may
	// report a crashed terminal state rather than a graceful stopped state.
	if _, err := observer.WaitUntilStopped(stopped); err != nil {
		t.Fatal(err)
	}
}
