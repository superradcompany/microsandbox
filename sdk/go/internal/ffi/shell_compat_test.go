//go:build shell_compat

package ffi

import (
	"context"
	"errors"
	"os"
	"testing"
)

// Use an actual old native library in a separate process because dlopen is global.
func TestConfiguredShellRefusesOlderNativeLibrary(t *testing.T) {
	path := os.Getenv("MSB_OLD_SHELL_NATIVE")
	if path == "" {
		t.Skip("requires a native library predating configured-shell support")
	}
	if err := Load(path); err != nil {
		t.Fatal(err)
	}
	_, err := (&Sandbox{}).ShellPath(context.Background())
	var nativeError *Error
	if !errors.As(err, &nativeError) || nativeError.Kind != KindUnsupportedOperation {
		t.Fatalf("old-native call did not refuse before dispatch: %v", err)
	}
}
