//go:build smoke && microsandbox_ffi_path

// Integration tests for CreateSandboxFromSpecJSON: boot a sandbox from a full
// SandboxSpec JSON and verify the spec's fields take effect in the guest, plus
// that chained options override the spec last-wins.
//
// These boot a microVM, so they are opt-in via MSB_VM_SMOKE on top of the FFI
// path — the Go twin of the Rust integration tests' #[ignore] (CI's smoke step
// runs on hosts that can't boot VMs). Run on a KVM/HVF-capable machine:
//
//	MSB_VM_SMOKE=1 MICROSANDBOX_FFI_PATH=/path/to/libmicrosandbox_go_ffi.{so,dylib} \
//	    go test -tags "smoke microsandbox_ffi_path" -run CreateFromSpec -count=1 ./...

package microsandbox

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/bundle"
)

// vmSmokeSetup shares ONE MSB_HOME across the VM-booting tests. The FFI caches a
// process-global server bound to the MSB_HOME of the first sandbox boot, so
// smokeSetup's per-test temp home (RemoveAll'd on cleanup) strands later tests
// on a deleted DB ("unable to open database file"). A single home — created once
// and left for the OS to reap — keeps that cached server valid; the tests
// isolate via unique sandbox names + WithReplace.
var (
	vmHomeOnce sync.Once
	vmHomeDir  string
	vmHomeErr  error
)

func vmSmokeSetup(t *testing.T) context.Context {
	t.Helper()
	if os.Getenv(bundle.FFIPathEnv) == "" {
		t.Skipf("%s not set; skipping FFI smoke test", bundle.FFIPathEnv)
	}
	if os.Getenv("MSB_VM_SMOKE") == "" {
		t.Skip("MSB_VM_SMOKE not set; VM-booting tests are opt-in (see file header)")
	}
	// Anchor under /tmp so sandbox socket paths fit under sun_path (108 bytes).
	vmHomeOnce.Do(func() { vmHomeDir, vmHomeErr = os.MkdirTemp("/tmp", "msb-vm") })
	if vmHomeErr != nil {
		t.Fatalf("mkdtemp: %v", vmHomeErr)
	}
	t.Setenv("MSB_HOME", vmHomeDir)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	if err := EnsureInstalled(ctx); err != nil {
		t.Fatalf("EnsureInstalled: %v", err)
	}
	return ctx
}

// fromSpecJSON is a full SandboxSpec — image, resources, a guest hostname, and
// an env var. Everything else falls back to the spec defaults.
func fromSpecJSON(name string) string {
	return fmt.Sprintf(`{
		"name": %q,
		"image": {"oci":{"reference":"mirror.gcr.io/library/alpine"}},
		"resources": {"vcpus":1,"memory_mib":256},
		"runtime": {"hostname":"spec-host"},
		"env": [{"key":"FROM_SPEC","value":"applied"}]
	}`, name)
}

func assertShellEq(t *testing.T, ctx context.Context, sb *Sandbox, command, expected string) {
	t.Helper()
	out, err := sb.Shell(ctx, command)
	if err != nil {
		t.Fatalf("shell %q: %v", command, err)
	}
	if !out.Success() {
		t.Fatalf("shell %q exited %d (stderr: %s)", command, out.ExitCode(), out.Stderr())
	}
	if got := strings.TrimSpace(out.Stdout()); got != expected {
		t.Fatalf("shell %q = %q, want %q", command, got, expected)
	}
}

// A full spec JSON boots and its fields take effect — the whole spec rides
// straight through with nothing dropped.
func TestCreateFromSpecJSONAppliesSpecFields(t *testing.T) {
	ctx := vmSmokeSetup(t)

	sb, err := CreateSandboxFromSpecJSON(ctx, fromSpecJSON("from-spec-json-fields"), WithReplace())
	if err != nil {
		t.Fatalf("CreateSandboxFromSpecJSON: %v", err)
	}
	t.Cleanup(func() { _ = sb.Close() })

	assertShellEq(t, ctx, sb, `printf %s "$FROM_SPEC"`, "applied")
	assertShellEq(t, ctx, sb, "hostname", "spec-host")
}

// Options chained onto CreateSandboxFromSpecJSON override the spec last-wins:
// the hostname is overridden while the rest of the spec survives.
func TestCreateFromSpecJSONOptionsOverride(t *testing.T) {
	ctx := vmSmokeSetup(t)

	sb, err := CreateSandboxFromSpecJSON(ctx, fromSpecJSON("from-spec-json-override"),
		WithHostname("override-host"), WithReplace())
	if err != nil {
		t.Fatalf("CreateSandboxFromSpecJSON: %v", err)
	}
	t.Cleanup(func() { _ = sb.Close() })

	assertShellEq(t, ctx, sb, "hostname", "override-host")
	assertShellEq(t, ctx, sb, `printf %s "$FROM_SPEC"`, "applied")
}
