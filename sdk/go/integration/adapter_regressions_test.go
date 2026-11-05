//go:build integration && microsandbox_ffi_path

package integration

import (
	"bytes"
	"testing"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

func TestConfiguredShellAdapters(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-configured-shell"
	// /bin/false exists in Alpine and cannot be mistaken for sh executing exit 0.
	sb, err := createSandbox(t, ctx, name, microsandbox.WithImage(goIntegrationImage), microsandbox.WithShell("/bin/false"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sb.Stop(ctx); _ = sb.Close(); _ = microsandbox.RemoveSandbox(ctx, name) }()
	out, err := sb.Shell(ctx, "exit 0")
	if err != nil {
		t.Fatal(err)
	}
	if out.ExitCode() != 1 {
		t.Fatalf("configured shell ignored: exit %d", out.ExitCode())
	}
	stream, err := sb.ShellStream(ctx, "exit 0")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	out, err = stream.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out.ExitCode() != 1 {
		t.Fatalf("configured streaming shell ignored: exit %d", out.ExitCode())
	}
}

func TestBinaryCollectedExecAdapters(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-binary-exec"
	script := `printf 'a\377\000b'; printf 'c\376\000d' >&2; exit 7`
	sb, err := createSandbox(t, ctx, name, microsandbox.WithImage(goIntegrationImage), microsandbox.WithEntrypoint("sh"), microsandbox.WithCmd("-c", script))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sb.Stop(ctx); _ = sb.Close(); _ = microsandbox.RemoveSandbox(ctx, name) }()
	for _, run := range []func() (*microsandbox.ExecOutput, error){
		func() (*microsandbox.ExecOutput, error) { return sb.Exec(ctx, "sh", []string{"-c", script}) },
		func() (*microsandbox.ExecOutput, error) { return sb.ExecDefault(ctx) },
	} {
		out, err := run()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out.StdoutBytes(), []byte{'a', 255, 0, 'b'}) || !bytes.Equal(out.StderrBytes(), []byte{'c', 254, 0, 'd'}) || out.ExitCode() != 7 {
			t.Fatalf("binary output lost: stdout=%v stderr=%v exit=%d", out.StdoutBytes(), out.StderrBytes(), out.ExitCode())
		}
	}
}

// Run with either the current or an older native library to exercise both decoders.
func TestCollectedExecTextCompatibility(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-text-compat"
	script := `printf 'hello'; printf 'error' >&2; exit 7`
	sb, err := createSandbox(t, ctx, name, microsandbox.WithImage(goIntegrationImage), microsandbox.WithEntrypoint("sh"), microsandbox.WithCmd("-c", script))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sb.Stop(ctx); _ = sb.Close(); _ = microsandbox.RemoveSandbox(ctx, name) }()
	for _, run := range []func() (*microsandbox.ExecOutput, error){
		func() (*microsandbox.ExecOutput, error) { return sb.Exec(ctx, "sh", []string{"-c", script}) },
		func() (*microsandbox.ExecOutput, error) { return sb.ExecDefault(ctx) },
	} {
		out, err := run()
		if err != nil {
			t.Fatal(err)
		}
		if out.Stdout() != "hello" || out.Stderr() != "error" || out.ExitCode() != 7 {
			t.Fatalf("text output changed: stdout=%q stderr=%q exit=%d", out.Stdout(), out.Stderr(), out.ExitCode())
		}
	}
}

// The two streams together fit the legacy 1 MiB FFI buffer, but duplicating
// them as base64 would exceed it. Exercise both collected execution entrypoints.
func TestLargeCollectedExecTextCompatibility(t *testing.T) {
	ctx := integrationCtx(t)
	name := "go-sdk-large-text-compat"
	script := `head -c 307200 /dev/zero | tr '\000' a; head -c 307200 /dev/zero | tr '\000' b >&2; exit 7`
	sb, err := createSandbox(t, ctx, name, microsandbox.WithImage(goIntegrationImage), microsandbox.WithEntrypoint("sh"), microsandbox.WithCmd("-c", script))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sb.Stop(ctx); _ = sb.Close(); _ = microsandbox.RemoveSandbox(ctx, name) }()
	for _, run := range []func() (*microsandbox.ExecOutput, error){
		func() (*microsandbox.ExecOutput, error) { return sb.Exec(ctx, "sh", []string{"-c", script}) },
		func() (*microsandbox.ExecOutput, error) { return sb.ExecDefault(ctx) },
	} {
		out, err := run()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out.StdoutBytes(), bytes.Repeat([]byte{'a'}, 307200)) || !bytes.Equal(out.StderrBytes(), bytes.Repeat([]byte{'b'}, 307200)) || out.ExitCode() != 7 {
			t.Fatalf("large text output changed: stdout=%d bytes stderr=%d bytes exit=%d", len(out.StdoutBytes()), len(out.StderrBytes()), out.ExitCode())
		}
	}
}
