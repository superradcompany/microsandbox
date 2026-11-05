package ffi

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// Exercise the dynamic loader in a subprocess so its process-global load-once state cannot
// affect other tests. The fixture exports the established required ABI but neither new symbol.
// Every exported function aborts if called: unsupported detection must precede native dispatch.
func TestStorageMissingOptionalSymbols(t *testing.T) {
	if path := os.Getenv("MSB_STORAGE_TEST_LIBRARY"); path != "" {
		if err := Load(path); err != nil {
			t.Fatal(err)
		}
		sandbox := &Sandbox{}
		sandbox.handle.Store(42)
		for name, operation := range map[string]func() error{
			"usage":         func() error { _, err := StorageUsage(context.Background()); return err },
			"prune":         func() error { _, err := PruneStorage(context.Background(), StoragePruneOptions{}); return err },
			"sandbox usage": func() error { _, err := sandbox.StorageUsage(context.Background()); return err },
		} {
			var nativeError *Error
			if err := operation(); !errors.As(err, &nativeError) || nativeError.Kind != KindUnsupportedOperation {
				t.Fatalf("%s did not return unsupported before dispatch: %v", name, err)
			}
		}
		return
	}
	if runtime.GOOS == "windows" {
		t.Skip("fixture compiler currently targets Unix shared libraries")
	}
	compiler, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("requires a C compiler for the optional-symbol loader fixture")
	}
	loader, err := os.ReadFile("ffi.go")
	if err != nil {
		t.Fatal(err)
	}
	required := regexp.MustCompile(`(?m)^\s*RESOLVE\((msb_[a-z_]+)\);`).FindAllSubmatch(loader, -1)
	if len(required) == 0 {
		t.Fatal("did not find the established required native ABI")
	}
	var source strings.Builder
	source.WriteString("#include <stdlib.h>\n")
	for _, match := range required {
		source.WriteString("void " + string(match[1]) + "(void) { abort(); }\n")
	}
	directory := t.TempDir()
	cPath := filepath.Join(directory, "without_storage.c")
	if err := os.WriteFile(cPath, []byte(source.String()), 0600); err != nil {
		t.Fatal(err)
	}
	library := filepath.Join(directory, "without_storage.so")
	flag := "-shared"
	if runtime.GOOS == "darwin" {
		flag = "-dynamiclib"
	}
	if output, err := exec.Command(compiler, flag, "-fPIC", cPath, "-o", library).CombinedOutput(); err != nil {
		t.Fatalf("compile old-ABI fixture: %v\n%s", err, output)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestStorageMissingOptionalSymbols$", "-test.count=1")
	child.Env = append(os.Environ(), "MSB_STORAGE_TEST_LIBRARY="+library)
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("optional-symbol fixture: %v\n%s", err, output)
	}
}

func TestSandboxStorageUsageRejectsClosedOrCancelledWithoutDispatch(t *testing.T) {
	sandbox := &Sandbox{}
	var nativeError *Error
	if _, err := sandbox.StorageUsage(context.Background()); !errors.As(err, &nativeError) || nativeError.Kind != KindInvalidHandle {
		t.Fatalf("closed sandbox did not retain invalid-handle semantics: %v", err)
	}
	sandbox.handle.Store(42)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sandbox.StorageUsage(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled sandbox observation dispatched: %v", err)
	}
}
