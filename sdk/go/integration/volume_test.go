//go:build integration && microsandbox_ffi_path

package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

// TestCreateVolumePopulatesPath verifies that CreateVolume returns a Volume
// with a non-empty host path (a regression — earlier the FFI returned only
// the name and Path was always empty).
func TestCreateVolumePopulatesPath(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-volpath-" + t.Name()

	vol, err := microsandbox.CreateVolume(ctx, name)
	if err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	t.Cleanup(func() { _ = microsandbox.RemoveVolume(context.Background(), name) })

	if vol.Path() == "" {
		t.Error("Volume.Path: empty after create")
	}
	if !strings.Contains(vol.Path(), name) {
		t.Errorf("Volume.Path: %q does not include volume name", vol.Path())
	}
}

// TestVolumeWithLabels verifies that labels round-trip through CreateVolume
// → GetVolume.
func TestVolumeWithLabels(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-vollabels-" + t.Name()

	vol, err := microsandbox.CreateVolume(ctx, name,
		microsandbox.WithVolumeQuota(64),
		microsandbox.WithVolumeLabels(map[string]string{"team": "agents", "tier": "test"}),
	)
	if err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	t.Cleanup(func() { _ = vol.Remove(context.Background()) })

	h, err := microsandbox.GetVolume(ctx, name)
	if err != nil {
		t.Fatalf("GetVolume: %v", err)
	}
	labels := h.Labels()
	if labels["team"] != "agents" {
		t.Errorf("labels[team]: got %q want agents", labels["team"])
	}
	if labels["tier"] != "test" {
		t.Errorf("labels[tier]: got %q want test", labels["tier"])
	}
	if h.QuotaMiB() == nil || *h.QuotaMiB() != 64 {
		t.Errorf("QuotaMiB: got %v want 64", h.QuotaMiB())
	}
	if h.Path() == "" {
		t.Error("VolumeHandle.Path: empty")
	}
}

// TestListVolumesRichMetadata verifies that ListVolumes returns
// fully-populated VolumeHandle values.
func TestListVolumesRichMetadata(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-vollist-" + t.Name()

	vol, err := microsandbox.CreateVolume(ctx, name,
		microsandbox.WithVolumeLabels(map[string]string{"key": "value"}),
	)
	if err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	t.Cleanup(func() { _ = vol.Remove(context.Background()) })

	vols, err := microsandbox.ListVolumes(ctx)
	if err != nil {
		t.Fatalf("ListVolumes: %v", err)
	}
	var found *microsandbox.VolumeHandle
	for _, v := range vols {
		if v.Name() == name {
			found = v
			break
		}
	}
	if found == nil {
		t.Fatalf("volume %q missing from ListVolumes (%d entries)", name, len(vols))
	}
	if found.Path() == "" {
		t.Error("Path: empty in list result")
	}
	if found.Labels()["key"] != "value" {
		t.Errorf("Labels: got %v", found.Labels())
	}
	if found.CreatedAt().IsZero() {
		t.Error("CreatedAt: zero")
	}
}

// TestVolumeFsHostSideOps verifies that VolumeFs Read/Write/Mkdir/Exists/
// Remove/RemoveAll all work on a real volume directory.
func TestVolumeFsHostSideOps(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-volfs-" + t.Name()

	vol, err := microsandbox.CreateVolume(ctx, name)
	if err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	t.Cleanup(func() { _ = microsandbox.RemoveVolume(context.Background(), name) })

	fs := vol.FS()
	if err := fs.Mkdir("nested/deep"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := fs.WriteString("nested/deep/file.txt", "vol-data"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := fs.ReadString("nested/deep/file.txt")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got != "vol-data" {
		t.Errorf("Read: got %q want %q", got, "vol-data")
	}
	ok, err := fs.Exists("nested/deep/file.txt")
	if err != nil || !ok {
		t.Fatalf("Exists: got ok=%v err=%v", ok, err)
	}
	missing, err := fs.Exists("not-there")
	if err != nil {
		t.Fatalf("Exists missing: %v", err)
	}
	if missing {
		t.Error("Exists on missing path: got true")
	}
	if err := fs.Remove("nested/deep/file.txt"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := fs.RemoveAll("nested"); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	_ = ctx // keep parameter usage consistent across tests
}

// TestVolumeFsRejectsPathEscape complements the unit test by exercising the
// real volume directory.
func TestVolumeFsRejectsPathEscape(t *testing.T) {
	name := "go-sdk-volesc-" + t.Name()
	ctx := integrationCtx(t)

	vol, err := microsandbox.CreateVolume(ctx, name)
	if err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	t.Cleanup(func() { _ = microsandbox.RemoveVolume(context.Background(), name) })

	fs := vol.FS()
	for _, bad := range []string{"../../etc/passwd", "/etc/hosts", "a/../../escape"} {
		if _, err := fs.Read(bad); !errors.Is(err, microsandbox.ErrPathEscape) {
			t.Errorf("Read(%q): want ErrPathEscape, got %v", bad, err)
		}
	}
}

// TestNamedVolumeMountIntoSandbox verifies that a named volume created on
// the host shows up at the configured guest path inside the sandbox, and
// that data written on the host side via VolumeFs is visible inside.
func TestNamedVolumeMountIntoSandbox(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-namedmnt-" + t.Name()

	vol, err := microsandbox.CreateVolume(ctx, name)
	if err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	t.Cleanup(func() { _ = microsandbox.RemoveVolume(context.Background(), name) })

	if err := vol.FS().WriteString("greeting.txt", "hello-from-host\n"); err != nil {
		t.Fatalf("Volume Write: %v", err)
	}

	sb, err := microsandbox.CreateSandbox(ctx, "sb-"+name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithMounts(map[string]microsandbox.MountConfig{
			"/data": microsandbox.Mount.Named(name, microsandbox.MountOptions{}),
		}),
	)
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})

	out, err := sb.Shell(ctx, "cat /data/greeting.txt")
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	if !strings.Contains(out.Stdout(), "hello-from-host") {
		t.Errorf("guest read of host-written file: got %q", out.Stdout())
	}
}

// TestNamedVolumeReadonlyMount verifies that MountOptions.Readonly produces
// a guest mount that rejects writes.
func TestNamedVolumeReadonlyMount(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-volro-" + t.Name()

	if _, err := microsandbox.CreateVolume(ctx, name); err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	t.Cleanup(func() { _ = microsandbox.RemoveVolume(context.Background(), name) })

	sb, err := microsandbox.CreateSandbox(ctx, "sb-"+name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithMounts(map[string]microsandbox.MountConfig{
			"/ro": microsandbox.Mount.Named(name, microsandbox.MountOptions{Readonly: true}),
		}),
	)
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})

	out, err := sb.Shell(ctx, "echo nope > /ro/test.txt 2>&1; echo done")
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	combined := out.Stdout() + out.Stderr()
	if !strings.Contains(combined, "Read-only") &&
		!strings.Contains(combined, "read-only") {
		t.Errorf("expected read-only error, got %q", combined)
	}
}

// TestTmpfsMountWithSizeLimit creates a tmpfs mount with a 4 MiB cap and
// verifies that writing more than that fails.
func TestTmpfsMountWithSizeLimit(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-tmpfs-" + t.Name()

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithMounts(map[string]microsandbox.MountConfig{
			"/scratch": microsandbox.Mount.Tmpfs(microsandbox.TmpfsOptions{SizeMiB: 4}),
		}),
	)
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})

	// 1 MiB write — should succeed.
	out, err := sb.Shell(ctx, "dd if=/dev/zero of=/scratch/small bs=1M count=1 status=none && echo small-ok")
	if err != nil {
		t.Fatalf("Shell small write: %v", err)
	}
	if !strings.Contains(out.Stdout(), "small-ok") {
		t.Errorf("small write should succeed; got %q / %q", out.Stdout(), out.Stderr())
	}

	// 8 MiB write — must fail (cap is 4 MiB).
	out, err = sb.Shell(ctx, "dd if=/dev/zero of=/scratch/big bs=1M count=8 status=none 2>&1; echo done")
	if err != nil {
		t.Fatalf("Shell big write: %v", err)
	}
	combined := out.Stdout() + out.Stderr()
	if !strings.Contains(combined, "No space left") &&
		!strings.Contains(combined, "no space") {
		t.Errorf("expected ENOSPC for 8M write into 4M tmpfs; got %q", combined)
	}
}

// TestBindMountReadonly verifies that a host bind mount marked Readonly
// rejects guest writes. We bind /tmp because every host has it.
//
// Skipped pending #707 (fix(runtime): skip xattr-strict probe for user
// bind mounts). Without that fix, PassthroughFs::build() in strict mode
// writes setxattr user.containers._probe on the source directory; Linux
// requires the caller to own the file (or hold CAP_SYS_ADMIN) to write
// a user.* xattr, so binding root-owned /tmp fails with EPERM before
// the VM boots. Unskip once #707 lands.
func TestBindMountReadonly(t *testing.T) {
	t.Skip("pending superradcompany/microsandbox#707 (xattr-strict probe blocks bind of foreign-owned dirs)")
	ctx := integrationCtx(t)
	name := "go-sdk-bindro-" + t.Name()

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithMounts(map[string]microsandbox.MountConfig{
			"/host-tmp": microsandbox.Mount.Bind("/tmp", microsandbox.MountOptions{Readonly: true}),
		}),
	)
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = sb.Stop(stopCtx)
		_ = sb.Close()
	})

	out, err := sb.Shell(ctx, "touch /host-tmp/probe.go-sdk 2>&1; echo done")
	if err != nil {
		t.Fatalf("Shell: %v", err)
	}
	combined := out.Stdout() + out.Stderr()
	if !strings.Contains(combined, "Read-only") &&
		!strings.Contains(combined, "read-only") {
		t.Errorf("expected read-only error on bind mount; got %q", combined)
	}
}
