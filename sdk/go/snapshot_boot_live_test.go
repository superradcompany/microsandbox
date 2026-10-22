//go:build snapshot_live

package microsandbox

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// A real guest must see the requested boot policy through both receiver/progress paths.
func TestSnapshotBootOptionsLive(t *testing.T) {
	library, archive := os.Getenv("MSB_BOOT_NATIVE"), os.Getenv("MSB_BOOT_ARCHIVE")
	if library == "" || archive == "" {
		t.Skip("requires native library, archive and disposable VM home")
	}
	if err := ffi.Load(library); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	imported, err := Snapshot.Load(ctx, "go-boot", []string{archive})
	if err != nil {
		t.Fatal(err)
	}
	group := imported.Snapshot
	checkpoint, err := group.Head(ctx)
	if err != nil || checkpoint == nil {
		t.Fatalf("head: %v", err)
	}
	names := []string{"go-boot-child", "go-boot-progress", "go-boot-refused"}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		for _, name := range names {
			if child, err := GetSandbox(cleanup, name); err == nil {
				_ = child.Kill(cleanup)
			}
			_ = RemoveSandbox(cleanup, name)
		}
		if _, err := group.Remove(cleanup); err != nil {
			t.Error(err)
		}
	}()
	full := os.Getenv("MSB_BOOT_FULL") == "1"
	if full {
		for _, option := range []RestoreOption{WithRestoreInit(Init.Auto()), WithRestoreHostname("child")} {
			child, err := checkpoint.SpawnSandbox(ctx, names[2], option)
			if err == nil {
				_ = child.Close()
				t.Fatal("full-memory boot override accepted")
			}
			if !strings.Contains(err.Error(), "disk-only") {
				t.Fatal(err)
			}
		}
	}
	for index, name := range names[:2] {
		opts := []RestoreOption{
			WithRestoreWorkdir("/root"), WithRestoreShell("/bin/ash"), WithRestoreEnv("DEST_VALUE", "go-value"),
			WithRestoreEntrypoint("/bin/sh", "-c"), WithRestoreCmd("touch /root/default-ran"),
			WithRestoreHostname("go-child"),
			WithRestoreCPUs(1), WithRestoreMemory(256),
			WithRestoreMaxCPUs(2), WithRestoreMaxMemory(512),
			WithRestoreLabel("destination", "go-child"),
			WithRestoreInit(Init.Cmd("/bin/sh", InitOptions{
				Args: []string{"-c", `printf "%s" "$BOOT_VALUE" > /root/go-boot; exec sleep 300`},
				Env:  map[string]string{"BOOT_VALUE": "go-init"},
			})),
		}
		if full {
			opts = append(opts, WithSnapshotDiskOnly())
		}
		var child *Sandbox
		if index == 0 {
			child, err = group.SpawnSandbox(ctx, name, opts...)
		} else {
			_, results := checkpoint.SpawnSandboxWithProgress(ctx, name, opts...)
			result := <-results
			child, err = result.Sandbox, result.Err
		}
		if err != nil {
			t.Fatal(err)
		}
		defaults, err := child.Exec(ctx, "/bin/sh", []string{"-c", `test ! -e /root/default-ran && printf "%s:%s" "$PWD" "$DEST_VALUE"`})
		if err != nil || !defaults.Success() || defaults.Stdout() != "/root:go-value" {
			t.Fatalf("command defaults: %v %+v", err, defaults)
		}
		handle, err := GetSandbox(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		config, err := handle.Config()
		if err != nil || config.MaxCPUs != 2 || config.MaxMemoryMiB != 512 {
			t.Fatalf("resource ceilings: %v %+v", err, config)
		}
		if config.Workdir != "/root" || config.Shell != "/bin/ash" || strings.Join(config.Entrypoint, "|") != "/bin/sh|-c" || len(config.Cmd) != 1 || config.Cmd[0] != "touch /root/default-ran" {
			t.Fatalf("command defaults missing from retained child configuration: %+v", config)
		}
		if config.Labels["destination"] != "go-child" {
			t.Fatalf("destination policy lost: %+v", config)
		}
		capacity, err := child.Exec(ctx, "sh", []string{"-c", "nproc; cat /sys/devices/system/cpu/possible"})
		if err != nil || !capacity.Success() || strings.TrimSpace(capacity.Stdout()) != "1\n0-1" {
			t.Fatalf("guest CPU geometry: %v %+v", err, capacity)
		}
		output, err := child.Exec(ctx, "sh", []string{"-c", `for i in $(seq 1 50); do test -s /root/go-boot && break; sleep 0.1; done; test "$(cat /root/go-boot)" = go-init && test "$(hostname)" = go-child && cat /proc/1/comm`})
		if err != nil || !output.Success() || strings.TrimSpace(output.Stdout()) != "sleep" {
			t.Fatalf("boot policy: %v %+v", err, output)
		}
		// sleep has no production init shutdown handler; force-stop this test-only PID 1.
		if err := child.Kill(ctx); err != nil {
			t.Fatal(err)
		}
		if err := child.Close(); err != nil {
			t.Fatal(err)
		}
		if err := RemoveSandbox(ctx, name); err != nil {
			t.Fatal(err)
		}
	}
}
