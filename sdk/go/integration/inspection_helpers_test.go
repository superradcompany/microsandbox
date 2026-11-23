//go:build integration && microsandbox_ffi_path

package integration

import (
	"context"
	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
	"testing"
)

func liveConfigJSON(t *testing.T, ctx context.Context, sandbox *microsandbox.Sandbox) string {
	t.Helper()
	value, err := sandbox.ConfigJSON(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func liveSandboxInfo(t *testing.T, ctx context.Context, sandbox *microsandbox.Sandbox) *microsandbox.SandboxInfo {
	t.Helper()
	value, err := sandbox.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func liveVolumeInfo(t *testing.T, ctx context.Context, volume *microsandbox.Volume) *microsandbox.VolumeInfo {
	t.Helper()
	value, err := volume.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func liveSnapshotInfo(t *testing.T, ctx context.Context, snapshot *microsandbox.Checkpoint) *microsandbox.SnapshotInfo {
	t.Helper()
	value, err := snapshot.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func localSnapshotPath(t *testing.T, snapshot *microsandbox.Checkpoint) string {
	t.Helper()
	path, err := snapshot.Path()
	if err != nil {
		t.Fatal(err)
	}
	return path
}
