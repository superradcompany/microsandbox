// Basic end-to-end smoke test for the microsandbox Go SDK.
//
// Exercises: CreateSandbox, Exec (success + non-zero), Shell, FS read/write,
// Metrics, StopAndWait, RemoveSandbox.
//
// Build: from sdk/go, run
//
//	go run ./examples/basic
//
package main

import (
	"context"
	"fmt"
	"log"
	"os"
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

	name := fmt.Sprintf("go-sdk-basic-%d", time.Now().Unix())
	log.Printf("creating sandbox %q (alpine:3.19)", name)

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithMemory(256),
		microsandbox.WithCPUs(1),
		microsandbox.WithEnv(map[string]string{"GREETING": "hello-from-go-sdk"}),
	)
	if err != nil {
		log.Fatalf("CreateSandbox: %v", err)
	}
	defer func() {
		stopCtx, c := context.WithTimeout(context.Background(), 30*time.Second)
		defer c()
		if _, err := sb.StopAndWait(stopCtx); err != nil {
			log.Printf("StopAndWait: %v", err)
		}
		if err := sb.Close(); err != nil {
			log.Printf("Close: %v", err)
		}
		if err := microsandbox.RemoveSandbox(context.Background(), name); err != nil {
			log.Printf("RemoveSandbox: %v", err)
		}
	}()

	// 1. Exec that exits 0.
	out, err := sb.Exec(ctx, "echo", []string{"hello", "world"})
	must("Exec echo", err)
	if !out.Success() || !strings.Contains(out.Stdout(), "hello world") {
		log.Fatalf("echo: unexpected output %q (exit %d)", out.Stdout(), out.ExitCode())
	}
	fmt.Printf("  echo stdout: %q\n", strings.TrimSpace(out.Stdout()))

	// 2. Shell that reads the env var we passed in.
	out, err = sb.Shell(ctx, "echo $GREETING")
	must("Shell echo $GREETING", err)
	if !strings.Contains(out.Stdout(), "hello-from-go-sdk") {
		log.Fatalf("env var not visible: %q", out.Stdout())
	}
	fmt.Printf("  env var visible: %q\n", strings.TrimSpace(out.Stdout()))

	// 3. Exec that exits non-zero — must NOT be a Go error.
	out, err = sb.Shell(ctx, "exit 42")
	must("Shell exit 42", err)
	if out.ExitCode() != 42 || out.Success() {
		log.Fatalf("want exit 42, got exit=%d success=%v", out.ExitCode(), out.Success())
	}
	fmt.Printf("  non-zero exit correctly surfaced: code=%d\n", out.ExitCode())

	// 4. FS round-trip.
	fs := sb.FS()
	payload := "microsandbox go sdk — filesystem works\n"
	must("FS.Write", fs.WriteString(ctx, "/tmp/go-sdk.txt", payload))
	got, err := fs.ReadString(ctx, "/tmp/go-sdk.txt")
	must("FS.Read", err)
	if got != payload {
		log.Fatalf("fs round-trip mismatch: got %q want %q", got, payload)
	}
	fmt.Printf("  fs round-trip ok: %d bytes\n", len(got))

	// 5. FS list.
	entries, err := fs.List(ctx, "/tmp")
	must("FS.List", err)
	fmt.Printf("  /tmp has %d entries\n", len(entries))

	// 6. Metrics.
	m, err := sb.Metrics(ctx)
	must("Metrics", err)
	fmt.Printf("  metrics: uptime=%s mem=%d bytes cpu=%.1f%%\n",
		m.Uptime, m.MemoryBytes, m.CPUPercent)

	fmt.Println("OK — basic example passed")
}

func must(what string, err error) {
	if err != nil {
		log.Printf("%s: %v", what, err)
		os.Exit(1)
	}
}
