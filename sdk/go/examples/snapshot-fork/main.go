// Snapshot/fork example for the microsandbox Go SDK.
//
// Exercises creating a snapshot from a stopped sandbox, opening it through the
// snapshot index, verifying the artifact, and booting a second sandbox from it.
//
// Build: from sdk/go, run
//
//	go run ./examples/snapshot-fork
package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

const markerPath = "/tmp/snapshot-marker.txt"

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := microsandbox.EnsureInstalled(ctx); err != nil {
		log.Fatalf("EnsureInstalled: %v", err)
	}

	suffix := time.Now().Unix()
	baseName := fmt.Sprintf("go-sdk-snapshot-base-%d", suffix)
	forkName := fmt.Sprintf("go-sdk-snapshot-fork-%d", suffix)
	snapshotName := fmt.Sprintf("go-sdk-snapshot-%d", suffix)

	base, err := microsandbox.CreateSandbox(ctx, baseName, microsandbox.WithImage("alpine:3.19"))
	if err != nil {
		log.Fatalf("CreateSandbox base: %v", err)
	}
	defer cleanupSandbox(baseName)
	defer cleanupSnapshot(snapshotName)

	payload := fmt.Sprintf("created by %s\n", baseName)
	if err := base.FS().WriteString(ctx, markerPath, payload); err != nil {
		log.Fatalf("WriteString marker: %v", err)
	}

	if _, err := base.StopAndWait(ctx); err != nil {
		log.Fatalf("StopAndWait base: %v", err)
	}
	if err := base.Close(); err != nil {
		log.Fatalf("Close base: %v", err)
	}

	baseHandle, err := microsandbox.GetSandbox(ctx, baseName)
	if err != nil {
		log.Fatalf("GetSandbox base: %v", err)
	}
	artifact, err := baseHandle.Snapshot(ctx, snapshotName)
	if err != nil {
		log.Fatalf("Snapshot: %v", err)
	}
	fmt.Printf("snapshot created: digest=%s size=%d bytes\n", artifact.Digest(), artifact.SizeBytes())

	report, err := artifact.Verify(ctx)
	if err != nil {
		log.Fatalf("Snapshot Verify: %v", err)
	}
	fmt.Printf("snapshot verified: upper=%s\n", report.Upper.Kind)

	handle, err := microsandbox.Snapshot.Get(ctx, snapshotName)
	if err != nil {
		log.Fatalf("Snapshot.Get: %v", err)
	}
	name := "(unnamed)"
	if indexedName := handle.Name(); indexedName != nil {
		name = *indexedName
	}
	fmt.Printf("snapshot index entry: name=%s digest=%s\n", name, handle.Digest())

	fork, err := microsandbox.CreateSandbox(ctx, forkName, microsandbox.WithSnapshot(snapshotName))
	if err != nil {
		log.Fatalf("CreateSandbox fork: %v", err)
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = fork.StopAndWait(stopCtx)
		_ = fork.Close()
		_ = microsandbox.RemoveSandbox(context.Background(), forkName)
	}()

	got, err := fork.FS().ReadString(ctx, markerPath)
	if err != nil {
		log.Fatalf("ReadString marker from fork: %v", err)
	}
	if got != payload {
		log.Fatalf("fork marker mismatch: got %q want %q", got, payload)
	}
	fmt.Printf("fork preserved marker: %q\n", strings.TrimSpace(got))

	fmt.Println("OK - snapshot-fork example passed")
}

func cleanupSandbox(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sb, err := microsandbox.GetSandbox(ctx, name)
	if err != nil {
		return
	}
	_ = sb.Stop(ctx)
	_ = microsandbox.RemoveSandbox(context.Background(), name)
}

func cleanupSnapshot(name string) {
	_ = microsandbox.Snapshot.Remove(context.Background(), name, true)
}
