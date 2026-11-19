//go:build snapshot_compat

package ffi

import (
	"context"
	"errors"
	"os"
	"testing"
)

// Run separately: loading a native library predating group receivers must still
// work, while the new calls refuse rather than treating a missing symbol as success.
func TestSnapshotObjectsRefuseOlderNativeLibrary(t *testing.T) {
	path := os.Getenv("MSB_OLD_SNAPSHOT_NATIVE")
	if path == "" {
		t.Skip("requires a pre-group-receiver native library")
	}
	if err := Load(path); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"get", "list", "head", "capture", "archive_compatibility", "restore_guest_clock"} {
		_, err := SnapshotObjectCall(context.Background(), 0, map[string]any{"op": op})
		var native *Error
		if !errors.As(err, &native) || native.Kind != KindUnsupportedOperation {
			t.Fatalf("%s: expected unsupported before dispatch, got %v", op, err)
		}
	}
	if err := CheckArchiveCompatibility(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if err := CheckRestoreGuestClock(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	for _, policy := range []string{"sync", "off"} {
		var unsupported *Error
		err := CheckRestoreGuestClock(context.Background(), policy)
		if !errors.As(err, &unsupported) || unsupported.Kind != KindUnsupportedOperation {
			t.Fatalf("guest clock %s was not refused: %v", policy, err)
		}
	}

	hostname := "child"
	for _, options := range []RestoreOptions{{Init: &InitOptions{Cmd: "auto"}}, {Hostname: &hostname}} {
		var unsupported *Error
		err := CheckRestoreBootOptions(context.Background(), options)
		if !errors.As(err, &unsupported) || unsupported.Kind != KindUnsupportedOperation {
			t.Fatalf("boot option was not refused before dispatch: %v", err)
		}
	}

	var native *Error
	err := CheckArchiveCompatibility(context.Background(), "0.7.8")
	if !errors.As(err, &native) || native.Kind != KindUnsupportedOperation {
		t.Fatalf("explicit archive target was not refused before an old decoder: %v", err)
	}

}

// Supports libraries with group receivers as well as releases predating them.
// The only requirement is that the selected library predates boot-option admission.
func TestRestoreBootOptionsRefuseOlderNativeLibrary(t *testing.T) {
	path := os.Getenv("MSB_OLD_SNAPSHOT_NATIVE")
	if path == "" {
		t.Skip("requires a pre-boot-option native library")
	}
	if err := Load(path); err != nil {
		t.Fatal(err)
	}
	if err := CheckRestoreBootOptions(context.Background(), RestoreOptions{}); err != nil {
		t.Fatal(err)
	}
	hostname := "child"
	for _, options := range []RestoreOptions{{Init: &InitOptions{Cmd: "auto"}}, {Hostname: &hostname}} {
		var unsupported *Error
		err := CheckRestoreBootOptions(context.Background(), options)
		if !errors.As(err, &unsupported) || unsupported.Kind != KindUnsupportedOperation {
			t.Fatalf("boot option was not refused before dispatch: %v", err)
		}
	}
}

// A library may support init/hostname but predate ceilings. Acknowledgement of
// one boot option must never authorize a different, silently ignored option.
func TestRestoreCeilingsRefuseOlderNativeLibrary(t *testing.T) {
	path := os.Getenv("MSB_OLD_SNAPSHOT_NATIVE")
	if path == "" {
		t.Skip("requires a pre-ceiling native library")
	}
	if err := Load(path); err != nil {
		t.Fatal(err)
	}
	if err := CheckRestoreBootOptions(context.Background(), RestoreOptions{}); err != nil {
		t.Fatal(err)
	}
	cpus, memory := uint8(2), uint32(512)
	policy := "inherit"
	for _, options := range []RestoreOptions{{MaxCPUs: &cpus}, {MaxMemoryMiB: &memory}, {Labels: map[string]string{"team": "dev"}}, {Workdir: &policy}, {Shell: &policy}, {Entrypoint: &[]string{}}, {Cmd: &[]string{}}, {Env: map[string]string{"KEY": ""}}} {
		var unsupported *Error
		err := CheckRestoreBootOptions(context.Background(), options)
		if !errors.As(err, &unsupported) || unsupported.Kind != KindUnsupportedOperation {
			t.Fatalf("ceiling not refused before dispatch: %v", err)
		}
	}
}

// A native library that supports ordinary creation proxies does not necessarily
// support restore proxies. Require restore-option admission before mutation.
func TestRestoreProxyRefusesOlderNativeLibrary(t *testing.T) {
	path := os.Getenv("MSB_OLD_SNAPSHOT_NATIVE")
	if path == "" {
		t.Skip("requires a native library predating restore proxy admission")
	}
	if err := Load(path); err != nil {
		t.Fatal(err)
	}
	if err := CheckRestoreBootOptions(context.Background(), RestoreOptions{}); err != nil {
		t.Fatal(err)
	}
	options := RestoreOptions{Proxy: &OutboundProxyOptions{Protocol: "socks5", Address: "127.0.0.1:1080"}}
	err := CheckRestoreBootOptions(context.Background(), options)
	var unsupported *Error
	if !errors.As(err, &unsupported) || unsupported.Kind != KindUnsupportedOperation {
		t.Fatalf("proxy not refused before dispatch: %v", err)
	}
}

// Explicit pull selection must not be silently ignored by a pre-option native library.
func TestRestorePullPolicyRefusesOlderNativeLibrary(t *testing.T) {
	path := os.Getenv("MSB_OLD_SNAPSHOT_NATIVE")
	if path == "" {
		t.Skip("requires an older native library")
	}
	if err := Load(path); err != nil {
		t.Fatal(err)
	}
	if err := CheckRestoreBootOptions(context.Background(), RestoreOptions{}); err != nil {
		t.Fatal(err)
	}
	var unsupported *Error
	err := CheckRestoreBootOptions(context.Background(), RestoreOptions{PullPolicy: "never"})
	if !errors.As(err, &unsupported) || unsupported.Kind != KindUnsupportedOperation {
		t.Fatalf("pull policy not refused before dispatch: %v", err)
	}
}
