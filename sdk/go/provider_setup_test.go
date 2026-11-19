package microsandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeProvisionIntegrityAndIsolation(t *testing.T) {
	source := filepath.Join(t.TempDir(), "native.dylib")
	bytes := []byte("stand-in artifact; installation must not execute cross-target code")
	if err := os.WriteFile(source, bytes, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bytes)
	options := NativeInstallOptions{Kind: ContextLocal, Source: source, SHA256: hex.EncodeToString(sum[:]), Target: "darwin-arm64", CacheDir: t.TempDir()}
	local, err := InstallNativeProvider(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	options.Kind = ContextRemote
	remote, err := InstallNativeProvider(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if local == remote {
		t.Fatal("providers overwrite each other")
	}
	if data, err := os.ReadFile(local); err != nil || string(data) != string(bytes) {
		t.Fatal("local artifact changed", err)
	}
	options.SHA256 = hex.EncodeToString(make([]byte, 32))
	if _, err := InstallNativeProvider(context.Background(), options); err == nil {
		t.Fatal("accepted corrupt artifact")
	}
	options.Target = "../../escape"
	if _, err := InstallNativeProvider(context.Background(), options); err == nil {
		t.Fatal("accepted invalid target")
	}
	options.Target = "darwin-arm64"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := InstallNativeProvider(ctx, options); err == nil {
		t.Fatal("cancelled install succeeded")
	}
}
