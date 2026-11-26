//go:build snapshot_live && microsandbox_ffi_path

package microsandbox

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Exercise policy inheritance through a second capture, including a stopped disk source.
func TestSnapshotGuestClockLive(t *testing.T) {
	if os.Getenv("MSB_CLOCK_LIVE") != "1" {
		t.Skip("requires disposable native VM home")
	}
	full := os.Getenv("MSB_CLOCK_FULL") == "1"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var names []string
	var groups []*SnapshotGroup
	defer func() {
		for i := len(names) - 1; i >= 0; i-- {
			h, err := GetSandbox(context.Background(), names[i])
			if err != nil {
				continue
			}
			_ = h.Stop(context.Background())
			_ = RemoveSandbox(context.Background(), names[i])
		}
		for i := len(groups) - 1; i >= 0; i-- {
			if _, err := groups[i].Remove(context.Background()); err != nil {
				t.Error(err)
			}
		}
	}()
	check := func(sb *Sandbox, expected string) {
		t.Helper()
		config, err := sb.Config(ctx)
		if err != nil {
			t.Fatal(err)
		}
		actual := "sync"
		if clock := config.Spec.Runtime.GuestClock; clock != nil {
			actual = *clock
		}
		if actual != expected {
			t.Fatalf("guest clock = %q, want %q", actual, expected)
		}
		out, err := sb.Exec(ctx, "cat", []string{"/root/clock-marker"})
		if err != nil || out.Stdout() != "clock-marker" {
			t.Fatalf("guest marker: %v %+v", err, out)
		}
	}
	names = append(names, "clock-source")
	source, err := CreateSandbox(ctx, "clock-source", WithImage("alpine:3.19"), WithCPUs(1), WithMemory(256))
	if err != nil {
		t.Fatal(err)
	}
	out, err := source.Exec(ctx, "sh", []string{"-c", "printf clock-marker > /root/clock-marker"})
	if err != nil || !out.Success() {
		t.Fatalf("seed marker: %v", err)
	}
	if err := source.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	_ = source.Close()
	handle, err := GetSandbox(ctx, source.Name())
	if err != nil {
		t.Fatal(err)
	}
	created, err := handle.Snapshot(ctx, "clock-base")
	if err != nil {
		t.Fatal(err)
	}
	groups = append(groups, created.Snapshot)
	names = append(names, "clock-off")
	progress, result := created.Checkpoint.SpawnSandboxWithProgress(ctx, "clock-off", WithRestoreGuestClock(GuestClockOff))
	for range progress {
	}
	completed := <-result
	if completed.Err != nil {
		t.Fatal(completed.Err)
	}
	off := completed.Sandbox
	check(off, "off")
	offHandle, err := GetSandbox(ctx, off.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !full {
		if err := off.Stop(ctx); err != nil {
			t.Fatal(err)
		}
		_ = off.Close()
	}
	saved, err := offHandle.Snapshot(ctx, "clock-recorded", WithSnapshotCaptureConfig(SnapshotCaptureConfig{Full: full}))
	if err != nil {
		t.Fatal(err)
	}
	groups = append(groups, saved.Snapshot)
	if full {
		if err := off.Stop(ctx); err != nil {
			t.Fatal(err)
		}
		_ = off.Close()
	}
	archive := os.Getenv("MSB_CLOCK_EXPORT")
	if archive == "" {
		archive = filepath.Join(t.TempDir(), "off.msb")
	}
	if err := saved.Checkpoint.Save(ctx, archive, SnapshotSaveOptions{WithImage: true}); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct {
		name     string
		opts     []RestoreOption
		expected string
	}{
		{"clock-inherit", nil, "off"}, {"clock-sync", []RestoreOption{WithRestoreGuestClock(GuestClockSync)}, "sync"},
	} {
		names = append(names, scenario.name)
		child, err := saved.Snapshot.SpawnSandbox(ctx, scenario.name, scenario.opts...)
		if err != nil {
			t.Fatal(err)
		}
		check(child, scenario.expected)
		if err := child.Stop(ctx); err != nil {
			t.Fatal(err)
		}
		_ = child.Close()
	}
}
