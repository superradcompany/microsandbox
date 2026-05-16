// Image cache example for the microsandbox Go SDK.
//
// Walks the Image cache surface end-to-end:
//   - Image.List   — every cached image, newest first
//   - Image.Get    — lookup by reference
//   - Image.Inspect — full detail (config + layers)
//   - Image.Remove — delete by reference
//   - Image.GCLayers / Image.GC — reclaim orphaned blobs
//
// We boot a sandbox first to make sure at least one image is in the cache
// for the listing demo to be useful.
//
// Build: from sdk/go, run
//
//	go run ./examples/image-cache
package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

const targetImage = "alpine:3.19"

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := microsandbox.EnsureInstalled(ctx); err != nil {
		log.Fatalf("EnsureInstalled: %v", err)
	}

	// Seed the cache with at least one image by booting a throwaway sandbox.
	name := fmt.Sprintf("go-sdk-imagecache-seed-%d", time.Now().Unix())
	log.Printf("seeding image cache via sandbox %q (%s)", name, targetImage)
	sb, err := microsandbox.CreateSandbox(ctx, name, microsandbox.WithImage(targetImage))
	if err != nil {
		log.Fatalf("CreateSandbox: %v", err)
	}
	if _, err := sb.StopAndWait(ctx); err != nil {
		log.Printf("StopAndWait: %v", err)
	}
	if err := sb.Close(); err != nil {
		log.Printf("Close: %v", err)
	}
	if err := microsandbox.RemoveSandbox(ctx, name); err != nil {
		log.Printf("RemoveSandbox: %v", err)
	}

	// 1. List everything in the cache.
	all, err := microsandbox.Image.List(ctx)
	if err != nil {
		log.Fatalf("Image.List: %v", err)
	}
	fmt.Printf("\nImage.List → %d cached image(s):\n", len(all))
	for _, h := range all {
		size := "—"
		if h.SizeBytes() != nil {
			size = fmt.Sprintf("%.1f MiB", float64(*h.SizeBytes())/(1024*1024))
		}
		fmt.Printf("  %-50s arch=%-8s os=%-7s layers=%d size=%s\n",
			h.Reference(), defaultStr(h.Architecture()),
			defaultStr(h.OS()), h.LayerCount(), size)
	}
	if len(all) == 0 {
		log.Fatal("expected at least one cached image after seeding")
	}

	// 2. Look up the seeded image and print its handle metadata.
	target := pickReference(all, targetImage)
	h, err := microsandbox.Image.Get(ctx, target)
	if err != nil {
		log.Fatalf("Image.Get(%s): %v", target, err)
	}
	fmt.Printf("\nImage.Get(%s):\n", target)
	fmt.Printf("  manifest_digest=%s\n", defaultStr(h.ManifestDigest()))
	fmt.Printf("  created_at=%s last_used_at=%s\n",
		fmtTime(h.CreatedAt()), fmtTime(h.LastUsedAt()))

	// 3. Full inspect.
	d, err := microsandbox.Image.Inspect(ctx, target)
	if err != nil {
		log.Fatalf("Image.Inspect: %v", err)
	}
	fmt.Printf("\nImage.Inspect(%s):\n", target)
	if d.Config != nil {
		fmt.Printf("  config.entrypoint=%v\n", d.Config.Entrypoint)
		fmt.Printf("  config.cmd=%v\n", d.Config.Cmd)
		fmt.Printf("  config.working_dir=%q\n", d.Config.WorkingDir)
		fmt.Printf("  config.user=%q\n", d.Config.User)
		fmt.Printf("  config.env (%d entries):\n", len(d.Config.Env))
		for _, e := range d.Config.Env {
			fmt.Printf("    %s\n", e)
		}
	}
	fmt.Printf("  layers (%d):\n", len(d.Layers))
	for _, l := range d.Layers {
		size := "—"
		if l.CompressedSizeBytes != nil {
			size = fmt.Sprintf("%d", *l.CompressedSizeBytes)
		}
		fmt.Printf("    [%2d] %s blob=%s size=%s\n",
			l.Position, shortHash(l.DiffID), shortHash(l.BlobDigest), size)
	}

	// 4. GC orphaned layers (no manifest references). Safe to call any
	// time; returns the count of layers reclaimed.
	removed, err := microsandbox.Image.GCLayers(ctx)
	if err != nil {
		log.Fatalf("Image.GCLayers: %v", err)
	}
	fmt.Printf("\nImage.GCLayers reclaimed %d orphaned layer(s)\n", removed)

	// We deliberately don't call Image.Remove on `targetImage` because the
	// next sandbox creation would have to re-pull. The API is wired up
	// symmetrically: `microsandbox.Image.Remove(ctx, "old:tag", true)`.
	fmt.Println("\nOK — image-cache example passed")
}

func pickReference(all []*microsandbox.ImageHandle, want string) string {
	// Prefer an exact match if one is present.
	for _, h := range all {
		if h.Reference() == want {
			return h.Reference()
		}
	}
	for _, h := range all {
		if strings.Contains(h.Reference(), want) {
			return h.Reference()
		}
	}
	return all[0].Reference()
}

func defaultStr(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Format(time.RFC3339)
}

func shortHash(s string) string {
	if len(s) > 19 {
		return s[:19]
	}
	return s
}
