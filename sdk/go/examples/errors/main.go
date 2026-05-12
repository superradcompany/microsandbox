// Typed-errors example for the microsandbox Go SDK.
//
// Walks through the common error categories and shows two ways to branch
// on them:
//   - microsandbox.IsKind(err, microsandbox.Err...)  ← convenient predicate
//   - errors.As(err, &mErr) and switch mErr.Kind     ← idiomatic Go
//
// Each step deliberately triggers a failure and prints how the SDK
// surfaces it.
//
// Build: from sdk/go, run
//
//	go run ./examples/errors
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if err := microsandbox.EnsureInstalled(ctx); err != nil {
		log.Fatalf("EnsureInstalled: %v", err)
	}

	// 1. ErrSandboxNotFound — looking up a sandbox that doesn't exist.
	if _, err := microsandbox.GetSandbox(ctx, "nope-this-doesnt-exist-go-sdk"); err == nil {
		log.Fatal("expected ErrSandboxNotFound")
	} else {
		report("GetSandbox missing", err, microsandbox.ErrSandboxNotFound)
	}

	// 2. ErrVolumeNotFound + ErrVolumeAlreadyExists.
	name := fmt.Sprintf("go-sdk-errors-vol-%d", time.Now().Unix())
	vol, err := microsandbox.CreateVolume(ctx, name, microsandbox.WithVolumeQuota(16))
	if err != nil {
		log.Fatalf("CreateVolume: %v", err)
	}
	defer vol.Remove(context.Background())

	if _, err := microsandbox.CreateVolume(ctx, name); err == nil {
		log.Fatal("expected ErrVolumeAlreadyExists")
	} else {
		report("duplicate CreateVolume", err, microsandbox.ErrVolumeAlreadyExists)
	}

	// 3. ErrExecTimeout — a per-command timeout.
	sb := boot(ctx, "errors-exec")
	defer teardown(sb)

	if _, err := sb.Shell(ctx, "sleep 60",
		microsandbox.WithExecTimeout(2*time.Second)); err == nil {
		log.Fatal("expected ErrExecTimeout")
	} else {
		report("Shell timeout", err, microsandbox.ErrExecTimeout)
	}

	// 4. ErrFilesystem — reading a path that doesn't exist inside the guest.
	if _, err := sb.FS().Read(ctx, "/never-existed"); err == nil {
		log.Fatal("expected ErrFilesystem / ErrPathNotFound")
	} else {
		// Some runtime versions surface this as ErrFilesystem, others as
		// ErrPathNotFound. Accept either.
		fmt.Printf("\n  Read missing file: %v\n", err)
		fmt.Printf("    IsKind(ErrFilesystem)   = %v\n", microsandbox.IsKind(err, microsandbox.ErrFilesystem))
		fmt.Printf("    IsKind(ErrPathNotFound) = %v\n", microsandbox.IsKind(err, microsandbox.ErrPathNotFound))
	}

	// 5. ErrInvalidHandle — closing the same sandbox twice.
	tmp := boot(ctx, "errors-handle")
	stopCtx, c := context.WithTimeout(context.Background(), 30*time.Second)
	_, _ = tmp.StopAndWait(stopCtx)
	c()
	if err := tmp.Close(); err != nil {
		log.Fatalf("first Close: %v", err)
	}
	if err := tmp.Close(); err == nil {
		log.Fatal("expected ErrInvalidHandle on second Close")
	} else {
		report("second Close", err, microsandbox.ErrInvalidHandle)
	}
	_ = microsandbox.RemoveSandbox(context.Background(), tmp.Name())

	// 6. errors.As to inspect the typed *Error.
	_, err = microsandbox.GetSandbox(ctx, "still-doesnt-exist")
	var me *microsandbox.Error
	if !errors.As(err, &me) {
		log.Fatalf("errors.As failed for %v", err)
	}
	fmt.Printf("\n  errors.As: Kind=%s Message=%q\n", me.Kind, me.Message)
	switch me.Kind {
	case microsandbox.ErrSandboxNotFound:
		fmt.Println("    → exact category match via switch")
	default:
		fmt.Println("    → fallback")
	}

	fmt.Println("\nOK — errors example passed")
}

func report(label string, err error, want microsandbox.ErrorKind) {
	fmt.Printf("\n  %s\n    err           = %v\n    IsKind(%s) = %v\n",
		label, err, want, microsandbox.IsKind(err, want))
	if !microsandbox.IsKind(err, want) {
		log.Fatalf("    expected IsKind(%s) to be true", want)
	}
}

func boot(ctx context.Context, suffix string) *microsandbox.Sandbox {
	name := fmt.Sprintf("go-sdk-%s-%d", suffix, time.Now().UnixNano())
	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithMemory(256),
	)
	if err != nil {
		log.Fatalf("CreateSandbox %s: %v", name, err)
	}
	return sb
}

func teardown(sb *microsandbox.Sandbox) {
	stopCtx, c := context.WithTimeout(context.Background(), 30*time.Second)
	defer c()
	_, _ = sb.StopAndWait(stopCtx)
	_ = sb.Close()
	_ = microsandbox.RemoveSandbox(context.Background(), sb.Name())
}
