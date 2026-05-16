//go:build integration && microsandbox_ffi_path

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

func TestSandboxLogs(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)

	if _, err := sb.Shell(ctx, "echo log-out; echo log-err >&2"); err != nil {
		t.Fatalf("Shell: %v", err)
	}

	entries, err := sb.Logs(ctx, microsandbox.LogOptions{
		Sources: []microsandbox.LogSource{
			microsandbox.LogSourceStdout,
			microsandbox.LogSourceStderr,
		},
	})
	if err != nil {
		t.Fatalf("Logs: %v", err)
	}

	var combined strings.Builder
	for _, entry := range entries {
		combined.WriteString(entry.Text())
		if entry.Timestamp.IsZero() {
			t.Error("log entry timestamp is zero")
		}
	}
	got := combined.String()
	if !strings.Contains(got, "log-out") || !strings.Contains(got, "log-err") {
		t.Fatalf("logs missing shell output: %q", got)
	}
}

func TestSandboxHandleLogsWithFilters(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)

	if _, err := sb.Shell(ctx, "echo old-log-line"); err != nil {
		t.Fatalf("Shell old: %v", err)
	}
	since := time.Now().Add(-1 * time.Second)
	if _, err := sb.Shell(ctx, "echo recent-log-line"); err != nil {
		t.Fatalf("Shell recent: %v", err)
	}

	handle, err := microsandbox.GetSandbox(ctx, sb.Name())
	if err != nil {
		t.Fatalf("GetSandbox: %v", err)
	}
	entries, err := handle.Logs(ctx, microsandbox.LogOptions{
		Tail:    1,
		Since:   since,
		Sources: []microsandbox.LogSource{microsandbox.LogSourceStdout},
	})
	if err != nil {
		t.Fatalf("Handle Logs: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}
	if !strings.Contains(entries[0].Text(), "recent-log-line") {
		t.Fatalf("tail/since log entry = %q, want recent-log-line", entries[0].Text())
	}
}

func TestSandboxHandleLogsWorksAfterStop(t *testing.T) {
	sb := newTestSandbox(t)
	ctx := integrationCtx(t)

	if _, err := sb.Shell(ctx, "echo stopped-log-line"); err != nil {
		t.Fatalf("Shell: %v", err)
	}
	name := sb.Name()
	if err := sb.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	_ = sb.Close()

	handle, err := microsandbox.GetSandbox(ctx, name)
	if err != nil {
		t.Fatalf("GetSandbox: %v", err)
	}
	entries, err := handle.Logs(context.Background(), microsandbox.LogOptions{
		Sources: []microsandbox.LogSource{microsandbox.LogSourceStdout},
	})
	if err != nil {
		t.Fatalf("Handle Logs after stop: %v", err)
	}
	var combined strings.Builder
	for _, entry := range entries {
		combined.WriteString(entry.Text())
	}
	if !strings.Contains(combined.String(), "stopped-log-line") {
		t.Fatalf("logs after stop missing output: %q", combined.String())
	}
}
