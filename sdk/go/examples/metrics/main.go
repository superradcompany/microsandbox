// Metrics example for the microsandbox Go SDK.
//
// Demonstrates the three metrics surfaces:
//   - Sandbox.Metrics(ctx)         — point-in-time snapshot for one sandbox.
//   - Sandbox.MetricsStream(...)   — repeated snapshots at a fixed cadence.
//   - AllSandboxMetrics(ctx)       — point-in-time snapshot for every
//                                     running sandbox, keyed by name.
//
// The example boots two sandboxes so AllSandboxMetrics has more than one
// entry to print.
//
// Build: from sdk/go, run
//
//	go run ./examples/metrics
package main

import (
	"context"
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

	a, b := boot(ctx, "metrics-a"), boot(ctx, "metrics-b")
	defer teardown(a)
	defer teardown(b)

	// Generate a tiny bit of CPU + I/O so the samples aren't all zero.
	for _, sb := range []*microsandbox.Sandbox{a, b} {
		if _, err := sb.Shell(ctx, "for i in 1 2 3; do sleep 0.1; echo ok; done"); err != nil {
			log.Fatalf("Shell: %v", err)
		}
	}

	// 1. Single snapshot for one sandbox.
	m, err := a.Metrics(ctx)
	if err != nil {
		log.Fatalf("Metrics: %v", err)
	}
	fmt.Printf("\n%-12s cpu=%5.1f%%  mem=%6dKiB / %6dKiB  uptime=%s\n",
		a.Name(), m.CPUPercent, m.MemoryBytes>>10, m.MemoryLimitBytes>>10, m.Uptime)

	// 2. Stream snapshots at 250 ms cadence.
	stream, err := a.MetricsStream(ctx, 250*time.Millisecond)
	if err != nil {
		log.Fatalf("MetricsStream: %v", err)
	}
	defer stream.Close()
	fmt.Printf("\nstreaming three snapshots (250ms cadence):\n")
	for i := 0; i < 3; i++ {
		recvCtx, c := context.WithTimeout(ctx, 5*time.Second)
		s, err := stream.Recv(recvCtx)
		c()
		if err != nil {
			log.Fatalf("Recv #%d: %v", i, err)
		}
		if s == nil {
			log.Fatalf("stream ended early at #%d", i)
		}
		fmt.Printf("  #%d cpu=%5.1f%%  rx=%d tx=%d uptime=%s\n",
			i+1, s.CPUPercent, s.NetRxBytes, s.NetTxBytes, s.Uptime)
	}

	// 3. All sandboxes at once, keyed by name.
	all, err := microsandbox.AllSandboxMetrics(ctx)
	if err != nil {
		log.Fatalf("AllSandboxMetrics: %v", err)
	}
	fmt.Printf("\nAllSandboxMetrics returned %d sandboxes:\n", len(all))
	for name, m := range all {
		fmt.Printf("  %-30s cpu=%5.1f%%  mem=%6dKiB  uptime=%s\n",
			name, m.CPUPercent, m.MemoryBytes>>10, m.Uptime)
	}

	fmt.Println("\nOK — metrics example passed")
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
