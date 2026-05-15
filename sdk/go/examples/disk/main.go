// Disk-image volume example for the microsandbox Go SDK.
//
// The runtime accepts raw / qcow2 / etc. disk images mounted at a guest
// path. This example builds a tiny ext4 image at runtime (so the example
// is self-contained — no fixtures needed) by:
//
//  1. Booting an Alpine sandbox with a host-bind on a temp dir.
//  2. Running `dd` + `mkfs.ext4` inside it to create `disk.img`.
//  3. Stopping that sandbox.
//  4. Booting a fresh sandbox that mounts the image via Mount.Disk.
//  5. Writing a marker file via the disk volume, then verifying it.
//
// Build: from sdk/go, run
//
//	go run ./examples/disk
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := microsandbox.EnsureInstalled(ctx); err != nil {
		log.Fatalf("EnsureInstalled: %v", err)
	}

	// Stage a host directory for the bind + disk image.
	hostDir, err := os.MkdirTemp("", "go-sdk-disk-")
	if err != nil {
		log.Fatalf("TempDir: %v", err)
	}
	defer os.RemoveAll(hostDir)
	imgPath := filepath.Join(hostDir, "disk.img")

	// 1) Build the disk image from inside an alpine sandbox so we don't
	//    depend on mkfs.ext4 being installed on the host.
	build := boot(ctx, "disk-builder", microsandbox.WithMounts(map[string]microsandbox.MountConfig{
		"/host": microsandbox.Mount.Bind(hostDir, microsandbox.MountOptions{}),
	}))
	defer teardown(build)

	const sizeMiB = 16
	cmd := fmt.Sprintf(
		"set -e; "+
			"apk add --no-cache e2fsprogs >/dev/null; "+
			"dd if=/dev/zero of=/host/disk.img bs=1M count=%d status=none; "+
			"mkfs.ext4 -F -q /host/disk.img >/dev/null; "+
			"echo built", sizeMiB)
	out, err := build.Shell(ctx, cmd, microsandbox.WithExecTimeout(2*time.Minute))
	if err != nil {
		log.Fatalf("build disk: %v", err)
	}
	if !out.Success() {
		log.Fatalf("mkfs failed:\nstdout=%q\nstderr=%q", out.Stdout(), out.Stderr())
	}
	if !strings.Contains(out.Stdout(), "built") {
		log.Fatalf("mkfs did not report success: %q", out.Stdout())
	}

	stat, err := os.Stat(imgPath)
	if err != nil {
		log.Fatalf("disk.img missing on host: %v", err)
	}
	fmt.Printf("  built %s (%d MiB ext4)\n", imgPath, stat.Size()>>20)

	// 2) Mount the disk in a new sandbox and verify it's writable.
	mount := boot(ctx, "disk-mount", microsandbox.WithMounts(map[string]microsandbox.MountConfig{
		"/data": microsandbox.Mount.Disk(imgPath, microsandbox.DiskOptions{
			Format: "raw",
			Fstype: "ext4",
		}),
	}))
	defer teardown(mount)

	out, err = mount.Shell(ctx,
		"echo hello-from-disk-volume > /data/marker.txt && cat /data/marker.txt && stat -c '%n %s' /data/marker.txt")
	if err != nil {
		log.Fatalf("write+read on /data: %v", err)
	}
	if !strings.Contains(out.Stdout(), "hello-from-disk-volume") {
		log.Fatalf("disk volume content: got %q", out.Stdout())
	}
	fmt.Printf("  guest /data:\n")
	for _, line := range strings.Split(strings.TrimSpace(out.Stdout()), "\n") {
		fmt.Printf("    %s\n", line)
	}

	// 3) Read-only mount — same image, but writes should fail.
	ro := boot(ctx, "disk-readonly", microsandbox.WithMounts(map[string]microsandbox.MountConfig{
		"/seed": microsandbox.Mount.Disk(imgPath, microsandbox.DiskOptions{
			Format:   "raw",
			Fstype:   "ext4",
			Readonly: true,
		}),
	}))
	defer teardown(ro)

	out, err = ro.Shell(ctx, "cat /seed/marker.txt; touch /seed/probe 2>&1; echo done")
	if err != nil {
		log.Fatalf("readonly probe: %v", err)
	}
	combined := out.Stdout() + out.Stderr()
	if !strings.Contains(combined, "hello-from-disk-volume") {
		log.Fatalf("readonly mount didn't expose marker: %q", combined)
	}
	if !strings.Contains(combined, "Read-only") &&
		!strings.Contains(combined, "read-only") {
		log.Fatalf("readonly mount accepted a write: %q", combined)
	}
	fmt.Println("  readonly mount: data visible, writes rejected ✓")

	fmt.Println("\nOK — disk-volume example passed")
}

func boot(ctx context.Context, suffix string, opts ...microsandbox.SandboxOption) *microsandbox.Sandbox {
	all := append([]microsandbox.SandboxOption{
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithMemory(256),
	}, opts...)
	name := fmt.Sprintf("go-sdk-%s-%d", suffix, time.Now().UnixNano())
	sb, err := microsandbox.CreateSandbox(ctx, name, all...)
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
