//go:build microsandbox_ffi_path

package microsandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

func runtimeFixture(t *testing.T, home string) ResolvedRuntime {
	t.Helper()
	executable, library := "msb", "libkrunfw.so.5.6.1"
	if runtime.GOOS == "darwin" {
		library = "libkrunfw.5.dylib"
	}
	if runtime.GOOS == "windows" {
		executable, library = "msb.exe", "libkrunfw.dll"
	}
	pair := ResolvedRuntime{MSBPath: filepath.Join(home, "bin", executable), LibkrunfwPath: filepath.Join(home, "lib", library), Origin: RuntimeOriginHome}
	for _, path := range []string{pair.MSBPath, pair.LibkrunfwPath} {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("older runtime; do not execute"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	return pair
}

func setupNative(t *testing.T) {
	t.Helper()
	path := os.Getenv("MICROSANDBOX_FFI_PATH")
	if path == "" {
		t.Fatal("MICROSANDBOX_FFI_PATH must point to the freshly built native SDK")
	}
	if err := ffi.Load(path); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeSetupResolveAndEnsure(t *testing.T) {
	setupNative(t)
	home := t.TempDir()
	expected := runtimeFixture(t, home)
	config := RuntimeConfig{Home: home}
	resolved, err := ResolveRuntime(config)
	if err != nil || resolved != expected {
		t.Fatalf("got %+v, %v; want %+v", resolved, err, expected)
	}
	if !IsRuntimeInstalled(config) {
		t.Fatal("complete pair must resolve")
	}
	ensured, err := EnsureRuntime(context.Background(), config, InstallOptions{Source: InstallSourceDirectory, SourcePath: "/absent", Force: true})
	if err != nil || ensured != expected {
		t.Fatalf("got %+v, %v", ensured, err)
	}
	// No process-wide completion cache: a later call must honor its own config.
	other := t.TempDir()
	if IsRuntimeInstalled(RuntimeConfig{Home: other}) {
		t.Fatal("old successful setup masked a missing home")
	}
	explicit := runtimeFixture(t, t.TempDir())
	resolved, err = ResolveRuntime(RuntimeConfig{Home: other, MSBPath: explicit.MSBPath})
	if err != nil || resolved.MSBPath != explicit.MSBPath || resolved.Origin != RuntimeOriginConfiguration {
		t.Fatalf("explicit path: %+v, %v", resolved, err)
	}
}

func TestRuntimeSetupAbsentAndPartial(t *testing.T) {
	setupNative(t)
	missing := filepath.Join(t.TempDir(), "missing")
	_, err := ResolveRuntime(RuntimeConfig{Home: missing})
	var sdkErr *Error
	if !errors.As(err, &sdkErr) || sdkErr.Kind != ErrRuntimeNotInstalled {
		t.Fatalf("missing: %v", err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("resolution wrote runtime home: %v", err)
	}
	for _, removeMSB := range []bool{false, true} {
		home := t.TempDir()
		pair := runtimeFixture(t, home)
		path := pair.LibkrunfwPath
		if removeMSB {
			path = pair.MSBPath
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		_, err := EnsureRuntime(context.Background(), RuntimeConfig{Home: home}, InstallOptions{})
		if !errors.As(err, &sdkErr) || sdkErr.Kind != ErrRuntimeIncomplete {
			t.Fatalf("partial: %v", err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("partial pair was repaired")
		}
	}
}

func TestRuntimeSetupInstall(t *testing.T) {
	setupNative(t)
	source := t.TempDir()
	pair := runtimeFixture(t, source)
	for _, path := range []string{pair.MSBPath, pair.LibkrunfwPath} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(source, filepath.Base(path)), data, 0755); err != nil {
			t.Fatal(err)
		}
	}
	verify := false
	options := InstallOptions{Source: InstallSourceDirectory, SourcePath: source, Verify: &verify}
	for _, ensure := range []bool{false, true} {
		home := filepath.Join(t.TempDir(), "destination")
		config := RuntimeConfig{Home: home}
		var installed ResolvedRuntime
		var err error
		if ensure {
			installed, err = EnsureRuntime(context.Background(), config, options)
		} else {
			installed, err = InstallRuntime(context.Background(), config, options)
		}
		if err != nil {
			t.Fatal(err)
		}
		if installed.Origin != RuntimeOriginInstalled {
			t.Fatalf("origin: %v", installed.Origin)
		}
		resolved, err := ResolveRuntime(config)
		if err != nil || resolved.MSBPath != installed.MSBPath || resolved.LibkrunfwPath != installed.LibkrunfwPath {
			t.Fatalf("resolved %+v, %v", resolved, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := InstallRuntime(ctx, RuntimeConfig{Home: t.TempDir()}, options)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
}
