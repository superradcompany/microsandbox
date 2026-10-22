package ffi

import (
	"context"
	"errors"
	"testing"
)

func TestRestoreGuestClockCancellationDoesNotRequireNativeLibrary(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := CheckRestoreGuestClock(ctx, "off"); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost cancellation: %v", err)
	}
	if err := CheckRestoreGuestClock(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreBootOptionsPreserveOmissionAndCancellation(t *testing.T) {
	if err := CheckRestoreBootOptions(context.Background(), RestoreOptions{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	hostname := "child"
	cpus, memory := uint8(0), uint32(0)
	policy := "inherit"
	for _, options := range []RestoreOptions{{PullPolicy: "never"}, {Proxy: &OutboundProxyOptions{Protocol: "socks5", Address: "127.0.0.1:1080"}}, {Init: &InitOptions{Cmd: "auto"}}, {Hostname: &hostname}, {MaxCPUs: &cpus}, {MaxMemoryMiB: &memory}, {Labels: map[string]string{"team": "dev"}}, {Workdir: &policy}, {Shell: &policy}, {Entrypoint: &[]string{}}, {Cmd: &[]string{}}, {Env: map[string]string{"KEY": ""}}} {
		if err := CheckRestoreBootOptions(ctx, options); !errors.Is(err, context.Canceled) {
			t.Fatalf("lost cancellation: %v", err)
		}
	}
}
