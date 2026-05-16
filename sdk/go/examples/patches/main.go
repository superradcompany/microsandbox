// Rootfs patches example for the microsandbox Go SDK.
//
// Applies one of every Patch kind (Text, Append, Mkdir, Symlink, CopyFile,
// CopyDir, Remove) to the guest rootfs before the VM boots, then verifies
// each patch from inside the sandbox.
//
// Build: from sdk/go, run
//
//	go run ./examples/patches
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
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if err := microsandbox.EnsureInstalled(ctx); err != nil {
		log.Fatalf("EnsureInstalled: %v", err)
	}

	// Stage host artefacts that the patches will copy into the rootfs.
	hostDir, err := os.MkdirTemp("", "go-sdk-patches-")
	if err != nil {
		log.Fatalf("TempDir: %v", err)
	}
	defer os.RemoveAll(hostDir)
	if err := os.WriteFile(filepath.Join(hostDir, "config.toml"),
		[]byte("staged = true\n"), 0o644); err != nil {
		log.Fatalf("WriteFile config: %v", err)
	}
	scriptsDir := filepath.Join(hostDir, "scripts")
	if err := os.MkdirAll(scriptsDir, 0o755); err != nil {
		log.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(scriptsDir, "hello.sh"),
		[]byte("#!/bin/sh\necho hello-from-script\n"), 0o755); err != nil {
		log.Fatalf("WriteFile script: %v", err)
	}

	mode := uint32(0o755)
	name := fmt.Sprintf("go-sdk-patches-%d", time.Now().Unix())
	log.Printf("creating sandbox %q with seven rootfs patches", name)

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithPatches(
			microsandbox.Patch.Text("/etc/greeting.txt", "hello from a patched rootfs\n",
				microsandbox.PatchOptions{}),
			microsandbox.Patch.Append("/etc/profile",
				"\n# go-sdk-patches-example\nexport PATCHED=1\n"),
			microsandbox.Patch.Mkdir("/opt/go-sdk", microsandbox.PatchOptions{Mode: &mode}),
			microsandbox.Patch.Symlink("/etc/greeting.txt", "/etc/greeting.link",
				microsandbox.PatchOptions{}),
			microsandbox.Patch.CopyFile(filepath.Join(hostDir, "config.toml"),
				"/etc/go-sdk-config.toml", microsandbox.PatchOptions{Mode: &mode}),
			microsandbox.Patch.CopyDir(scriptsDir, "/opt/go-sdk/scripts",
				microsandbox.PatchOptions{}),
			microsandbox.Patch.Remove("/etc/motd"),
		),
	)
	if err != nil {
		log.Fatalf("CreateSandbox: %v", err)
	}
	defer func() {
		stopCtx, c := context.WithTimeout(context.Background(), 30*time.Second)
		defer c()
		_, _ = sb.StopAndWait(stopCtx)
		_ = sb.Close()
		_ = microsandbox.RemoveSandbox(context.Background(), name)
	}()

	check(ctx, sb, "Text",
		"cat /etc/greeting.txt", "hello from a patched rootfs")
	check(ctx, sb, "Append",
		"grep go-sdk-patches-example /etc/profile", "go-sdk-patches-example")
	check(ctx, sb, "Mkdir",
		"test -d /opt/go-sdk && echo dir-exists", "dir-exists")
	check(ctx, sb, "Symlink",
		"readlink /etc/greeting.link", "/etc/greeting.txt")
	check(ctx, sb, "CopyFile",
		"cat /etc/go-sdk-config.toml", "staged = true")
	check(ctx, sb, "CopyDir",
		"/opt/go-sdk/scripts/hello.sh", "hello-from-script")
	check(ctx, sb, "Remove",
		"test -e /etc/motd && echo motd-still-there || echo motd-gone", "motd-gone")

	fmt.Println("OK — patches example passed")
}

func check(ctx context.Context, sb *microsandbox.Sandbox, label, cmd, marker string) {
	out, err := sb.Shell(ctx, cmd)
	if err != nil {
		log.Fatalf("[%s] Shell: %v", label, err)
	}
	combined := out.Stdout() + out.Stderr()
	if !strings.Contains(combined, marker) {
		log.Fatalf("[%s] missing %q in output:\nstdout=%q\nstderr=%q",
			label, marker, out.Stdout(), out.Stderr())
	}
	fmt.Printf("  %-9s OK (%q)\n", label, marker)
}
