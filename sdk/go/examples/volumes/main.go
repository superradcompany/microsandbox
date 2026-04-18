// Volumes example for the microsandbox Go SDK.
//
// Exercises: NewVolume, ListVolumes, RemoveVolume, and the duplicate-create
// error path (ErrVolumeAlreadyExists).
//
// Build: from sdk/go, run
//
//	go run ./examples/volumes
//
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := microsandbox.EnsureInstalled(ctx); err != nil {
		log.Fatalf("EnsureInstalled: %v", err)
	}

	name := fmt.Sprintf("go-sdk-vol-%d", time.Now().Unix())
	log.Printf("creating volume %q (64 MiB quota)", name)

	vol, err := microsandbox.NewVolume(ctx, name, microsandbox.WithVolumeQuota(64))
	if err != nil {
		log.Fatalf("NewVolume: %v", err)
	}
	// Remove on exit so reruns stay clean.
	defer func() {
		if err := microsandbox.RemoveVolume(context.Background(), name); err != nil {
			// If the volume was already removed during the happy path, this is fine.
			if !microsandbox.IsKind(err, microsandbox.ErrVolumeNotFound) {
				log.Printf("cleanup RemoveVolume: %v", err)
			}
		}
	}()

	if vol.Name() != name {
		log.Fatalf("Name() mismatch: got %q want %q", vol.Name(), name)
	}

	// 1. Volume should appear in the list.
	vols, err := microsandbox.ListVolumes(ctx)
	if err != nil {
		log.Fatalf("ListVolumes: %v", err)
	}
	if !containsVolume(vols, name) {
		log.Fatalf("volume %q not in ListVolumes result (%d volumes)", name, len(vols))
	}
	fmt.Printf("  volume visible in list (%d total)\n", len(vols))

	// 2. Creating the same name again must return ErrVolumeAlreadyExists.
	_, err = microsandbox.NewVolume(ctx, name)
	if err == nil {
		log.Fatalf("expected ErrVolumeAlreadyExists on duplicate create")
	}
	if !microsandbox.IsKind(err, microsandbox.ErrVolumeAlreadyExists) {
		log.Fatalf("want ErrVolumeAlreadyExists, got %v", err)
	}
	fmt.Printf("  duplicate create correctly rejected: %v\n", err)

	// 3. Remove, then verify it is gone.
	if err := vol.Remove(ctx); err != nil {
		log.Fatalf("Remove: %v", err)
	}
	vols, err = microsandbox.ListVolumes(ctx)
	if err != nil {
		log.Fatalf("ListVolumes after remove: %v", err)
	}
	if containsVolume(vols, name) {
		log.Fatalf("volume %q still present after Remove", name)
	}
	fmt.Println("  volume removed and no longer listed")

	fmt.Println("OK — volumes example passed")
}

func containsVolume(vols []*microsandbox.Volume, name string) bool {
	for _, v := range vols {
		if v.Name() == name {
			return true
		}
	}
	return false
}
