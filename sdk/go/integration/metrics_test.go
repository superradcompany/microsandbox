//go:build integration && microsandbox_ffi_path

package integration

import (
	"context"
	"testing"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

// TestMetricsStreamRecv subscribes to a 100ms metrics stream and pulls a
// few snapshots. Each must carry a non-decreasing uptime and a
// sandbox-attached memory limit.
func TestMetricsStreamRecv(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)

	stream, err := sb.MetricsStream(ctx, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("MetricsStream: %v", err)
	}
	defer stream.Close()

	var lastUptime time.Duration
	for i := 0; i < 3; i++ {
		recvCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		m, err := stream.Recv(recvCtx)
		cancel()
		if err != nil {
			t.Fatalf("Recv #%d: %v", i, err)
		}
		if m == nil {
			t.Fatalf("Recv #%d: stream closed early", i)
		}
		if m.Uptime < lastUptime {
			t.Errorf("Uptime non-monotonic: %v < %v", m.Uptime, lastUptime)
		}
		lastUptime = m.Uptime
		if m.MemoryLimitBytes == 0 {
			t.Errorf("MemoryLimitBytes: 0 (sandbox should have a memory cap)")
		}
	}
}

// TestMetricsStreamCloseStopsBackgroundTask verifies that Close releases
// resources and a subsequent Recv on the closed stream returns an error
// promptly rather than hanging.
func TestMetricsStreamCloseStopsBackgroundTask(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)

	stream, err := sb.MetricsStream(ctx, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("MetricsStream: %v", err)
	}

	// Pull at least one snapshot before closing.
	if _, err := stream.Recv(ctx); err != nil {
		t.Fatalf("Recv before close: %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// After Close, Recv must not hang. We allow either an error or a nil
	// snapshot (some runtimes signal end-of-stream rather than an error).
	recvCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	done := make(chan struct{}, 1)
	go func() {
		_, _ = stream.Recv(recvCtx)
		done <- struct{}{}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Recv after Close did not return within 5s")
	}
}

// TestAllSandboxMetricsCoversMultipleSandboxes spins up two sandboxes and
// verifies that AllSandboxMetrics returns an entry for each, keyed by name.
func TestAllSandboxMetricsCoversMultipleSandboxes(t *testing.T) {
	ctx := integrationCtx(t)
	a := "go-sdk-allmetrics-a-" + t.Name()
	b := "go-sdk-allmetrics-b-" + t.Name()

	sbA, err := microsandbox.CreateSandbox(ctx, a, microsandbox.WithImage("alpine:3.19"))
	if err != nil {
		t.Fatalf("CreateSandbox a: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sbA.Stop(stopCtx)
		_ = sbA.Close()
	})

	sbB, err := microsandbox.CreateSandbox(ctx, b, microsandbox.WithImage("alpine:3.19"))
	if err != nil {
		t.Fatalf("CreateSandbox b: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sbB.Stop(stopCtx)
		_ = sbB.Close()
	})

	// Touch each so the metrics sampler picks them up.
	if _, err := sbA.Shell(ctx, "true"); err != nil {
		t.Fatalf("Shell a: %v", err)
	}
	if _, err := sbB.Shell(ctx, "true"); err != nil {
		t.Fatalf("Shell b: %v", err)
	}
	time.Sleep(1500 * time.Millisecond)

	all, err := microsandbox.AllSandboxMetrics(ctx)
	if err != nil {
		t.Fatalf("AllSandboxMetrics: %v", err)
	}
	if _, ok := all[a]; !ok {
		t.Errorf("missing entry for %q in AllSandboxMetrics: %d entries", a, len(all))
	}
	if _, ok := all[b]; !ok {
		t.Errorf("missing entry for %q in AllSandboxMetrics", b)
	}
}
