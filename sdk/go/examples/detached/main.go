// Detached-mode example for the microsandbox Go SDK.
//
// Demonstrates the full detached lifecycle:
//  1. Create a detached sandbox (survives the Go process exit).
//  2. Detach the local handle (releases the Rust-side ownership without
//     stopping the VM).
//  3. List sandboxes and confirm it's still there.
//  4. Reattach by name via GetSandbox + Connect.
//  5. Run a command that proves the original VM kept running.
//  6. Stop and remove.
//
// Build: from sdk/go, run
//
//	go run ./examples/detached
package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if err := microsandbox.EnsureInstalled(ctx); err != nil {
		log.Fatalf("EnsureInstalled: %v", err)
	}

	name := fmt.Sprintf("go-sdk-detached-%d", time.Now().Unix())
	log.Printf("creating detached sandbox %q", name)

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithDetached(),
	)
	if err != nil {
		log.Fatalf("CreateSandbox: %v", err)
	}

	// Best-effort cleanup if anything below explodes.
	defer func() {
		_ = microsandbox.RemoveSandbox(context.Background(), name)
	}()

	owns, err := sb.OwnsLifecycle()
	if err != nil {
		log.Fatalf("OwnsLifecycle: %v", err)
	}
	fmt.Printf("  initial OwnsLifecycle()=%v (true: this handle would tear it down on Close)\n", owns)

	// Mark something inside the guest so the reattach below can see it.
	if _, err := sb.Shell(ctx, "echo lived-through-detach > /tmp/witness"); err != nil {
		log.Fatalf("Shell write witness: %v", err)
	}

	// Detach: release the local handle without stopping the VM.
	if err := sb.Detach(ctx); err != nil {
		log.Fatalf("Detach: %v", err)
	}
	fmt.Println("  detached the handle — sandbox keeps running")

	// Confirm via ListSandboxes.
	handles, err := microsandbox.ListSandboxes(ctx)
	if err != nil {
		log.Fatalf("ListSandboxes: %v", err)
	}
	var found *microsandbox.SandboxHandle
	for _, h := range handles {
		if h.Name() == name {
			found = h
			break
		}
	}
	if found == nil {
		log.Fatalf("sandbox %q missing from ListSandboxes after detach", name)
	}
	fmt.Printf("  ListSandboxes: still present (status=%s, created=%s)\n",
		found.Status(), found.CreatedAt().Format(time.RFC3339))

	// Reattach via GetSandbox + Connect.
	h, err := microsandbox.GetSandbox(ctx, name)
	if err != nil {
		log.Fatalf("GetSandbox: %v", err)
	}
	sb2, err := h.Connect(ctx)
	if err != nil {
		log.Fatalf("Connect: %v", err)
	}
	defer func() {
		stopCtx, c := context.WithTimeout(context.Background(), 30*time.Second)
		defer c()
		_, _ = sb2.StopAndWait(stopCtx)
		_ = sb2.Close()
	}()

	owns2, _ := sb2.OwnsLifecycle()
	fmt.Printf("  reattached: OwnsLifecycle()=%v (false: Connect handles don't own the VM)\n", owns2)

	out, err := sb2.Shell(ctx, "cat /tmp/witness")
	if err != nil {
		log.Fatalf("Shell read witness: %v", err)
	}
	if !strings.Contains(out.Stdout(), "lived-through-detach") {
		log.Fatalf("witness missing — VM was actually torn down: stdout=%q", out.Stdout())
	}
	fmt.Println("  VM survived detach: witness file intact ✓")

	fmt.Println("OK — detached-mode example passed")
}
