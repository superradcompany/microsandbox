// Run from an isolated module with the selected SDK and -tags microsandbox_ffi_path.
// Never install a runtime here: the driver selects it independently of the SDK.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	msb "github.com/superradcompany/microsandbox/sdk/go"
)

type report struct {
	Language        string            `json:"language"`
	Case            string            `json:"case"`
	SDKVersion      string            `json:"sdk_version"`
	ExpectedVersion string            `json:"expected_sdk_version"`
	Native          map[string]string `json:"native"`
	Module          *debug.Module     `json:"module,omitempty"`
	RuntimeEvidence []json.RawMessage `json:"runtime_evidence"`
	Passed          []string          `json:"passed"`
	Status          string            `json:"status"`
	Error           string            `json:"error,omitempty"`
}

func main() {
	r := &report{
		Language: "go", Case: os.Getenv("MSB_COMPAT_CASE"), SDKVersion: msb.SDKVersion(),
		ExpectedVersion: os.Getenv("MSB_COMPAT_SDK_VERSION"), Native: map[string]string{},
		Passed: []string{}, Status: "failed",
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, module := range info.Deps {
			if module.Path == "github.com/superradcompany/microsandbox/sdk/go" {
				r.Module = module
			}
		}
	}
	err := run(r)
	if err != nil {
		r.Error = err.Error()
	} else {
		r.Status = "passed"
	}
	data, marshalErr := json.MarshalIndent(r, "", "  ")
	if marshalErr != nil {
		fmt.Fprintln(os.Stderr, marshalErr)
		os.Exit(1)
	}
	fmt.Println(string(data))
	path := os.Getenv("MSB_COMPAT_REPORT")
	if path == "" {
		err = errors.Join(err, errors.New("MSB_COMPAT_REPORT is required"))
	} else if writeErr := os.WriteFile(path, append(data, '\n'), 0o644); writeErr != nil {
		err = errors.Join(err, writeErr)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(r *report) error {
	for _, key := range []string{"MSB_COMPAT_IMAGE", "MSB_COMPAT_REPORT", "MSB_COMPAT_CASE", "MSB_COMPAT_SDK_VERSION", "MSB_COMPAT_SDK_ROOT", "MSB_COMPAT_SDK_GENERATION", "MSB_HOME", "MICROSANDBOX_FFI_PATH", "MSB_COMPAT_CLI", "MSB_COMPAT_VERIFY_RUNTIME"} {
		if os.Getenv(key) == "" {
			return fmt.Errorf("%s is required", key)
		}
	}
	if r.SDKVersion != strings.TrimPrefix(r.ExpectedVersion, "v") {
		return fmt.Errorf("SDK version %q does not match expected %q", r.SDKVersion, r.ExpectedVersion)
	}
	if r.Module == nil {
		return errors.New("Go build metadata does not identify the SDK dependency")
	}
	if os.Getenv("MSB_COMPAT_SDK_GENERATION") == "released" &&
		(r.Module.Replace != nil || r.Module.Version != "v"+strings.TrimPrefix(r.ExpectedVersion, "v")) {
		return errors.New("released Go SDK must use its exact module version without replacement")
	}
	if err := nativeIdentity(r); err != nil {
		return err
	}
	r.Passed = append(r.Passed, "sdk-native-identity")
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	for _, count := range []int{0, 1, 3} {
		if err := lifecycle(ctx, r, count); err != nil {
			return fmt.Errorf("tmpfs-%d: %w", count, err)
		}
	}
	return denyNetwork(ctx, r)
}

func nativeIdentity(r *report) error {
	input, err := filepath.EvalSymlinks(os.Getenv("MICROSANDBOX_FFI_PATH"))
	if err != nil {
		return err
	}
	root, err := filepath.EvalSymlinks(os.Getenv("MSB_COMPAT_SDK_ROOT"))
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(root, input)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("selected FFI library escaped SDK root: %q", input)
	}
	r.Native["selected_path"] = input
	selectedHash, err := fileHash(input)
	if err != nil {
		return err
	}
	r.Native["selected_sha256"] = selectedHash
	if expected := os.Getenv("MSB_COMPAT_NATIVE_SHA256"); expected != "" && selectedHash != expected {
		return errors.New("selected FFI library does not match MSB_COMPAT_NATIVE_SHA256")
	}
	// RuntimeVersion names the Rust SDK in the FFI library, not the msb binary.
	version, err := msb.RuntimeVersion()
	if err != nil {
		return err
	}
	r.Native["sdk_version"] = version
	if strings.TrimPrefix(version, "v") != strings.TrimPrefix(r.ExpectedVersion, "v") {
		return fmt.Errorf("native SDK version %q does not match expected %q", version, r.ExpectedVersion)
	}
	if runtime.GOOS != "linux" {
		r.Native["loaded_path_evidence"] = "/proc/self/maps unavailable on " + runtime.GOOS
		return nil
	}
	maps, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return err
	}
	loaded := map[string]bool{}
	for _, line := range strings.Split(string(maps), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 6 && strings.Contains(fields[5], "libmicrosandbox_go_ffi") {
			loaded[strings.Join(fields[5:], " ")] = true
		}
	}
	if len(loaded) != 1 {
		return fmt.Errorf("expected exactly one loaded Go FFI library, found %v", loaded)
	}
	for path := range loaded {
		r.Native["loaded_path"] = path
		hash, err := fileHash(path)
		if err != nil {
			return err
		}
		r.Native["loaded_sha256"] = hash
		if hash != selectedHash {
			return errors.New("loaded FFI library differs from MICROSANDBOX_FFI_PATH")
		}
	}
	return nil
}

func fileHash(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(data)), nil
}

func lifecycle(ctx context.Context, r *report, count int) (err error) {
	label := fmt.Sprintf("tmpfs-%d", count)
	name := fmt.Sprintf("compat-go-%d-%d", os.Getpid(), count)
	marker := "compat-go-" + r.Case + "-" + label
	options := []msb.SandboxOption{
		msb.WithImage(os.Getenv("MSB_COMPAT_IMAGE")), msb.WithMemory(256), msb.WithCPUs(1),
		msb.WithEnv(map[string]string{"MSB_COMPAT_MARKER": marker}),
	}
	mounts := map[string]msb.MountConfig{}
	for i := 0; i < count; i++ {
		mounts[fmt.Sprintf("/compat-tmpfs-%d", i)] = msb.Mount.Tmpfs(msb.TmpfsOptions{SizeMiB: 8})
	}
	if count > 0 {
		options = append(options, msb.WithMounts(mounts))
	}
	sandbox, err := msb.CreateSandbox(ctx, name, options...)
	if err != nil {
		return err
	}
	removed := false
	defer func() {
		if !removed {
			err = errors.Join(err, cleanup(name, sandbox))
		}
	}()
	r.Passed = append(r.Passed, label+"/create")
	if err = verifyRuntime(ctx, r, name); err != nil {
		return err
	}
	output, err := sandbox.Exec(ctx, "/bin/sh", []string{"-c", `printf '%s' "$MSB_COMPAT_MARKER"`})
	if err != nil {
		return err
	}
	if !output.Success() || output.Stdout() != marker {
		return fmt.Errorf("environment marker: exit=%d stdout=%q stderr=%q", output.ExitCode(), output.Stdout(), output.Stderr())
	}
	r.Passed = append(r.Passed, label+"/exec-env")
	const diskPath = "/compat-persistent.txt"
	if err = sandbox.FS().WriteString(ctx, diskPath, marker); err != nil {
		return err
	}
	if err = verifyFile(ctx, sandbox, diskPath, marker); err != nil {
		return err
	}
	r.Passed = append(r.Passed, label+"/filesystem")
	paths := make([]string, 0, len(mounts))
	for path := range mounts {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		// Inspect the guest mount table so an ordinary root directory cannot pass.
		command := fmt.Sprintf(`awk '$2 == "%s" && $3 == "tmpfs" { found=1 } END { exit !found }' /proc/mounts`, path)
		out, execErr := sandbox.Shell(ctx, command)
		if execErr != nil {
			return execErr
		}
		if !out.Success() {
			return fmt.Errorf("%s is not mounted as tmpfs: %s", path, out.Stderr())
		}
		if err = sandbox.FS().WriteString(ctx, path+"/marker", marker); err != nil {
			return err
		}
		if err = verifyFile(ctx, sandbox, path+"/marker", marker); err != nil {
			return err
		}
	}
	r.Passed = append(r.Passed, label+"/mounts")
	if err = sandbox.Stop(ctx); err != nil {
		return err
	}
	if err = sandbox.Close(); err != nil {
		return err
	}
	sandbox, err = msb.StartSandbox(ctx, name)
	if err != nil {
		return err
	}
	if err = verifyRuntime(ctx, r, name); err != nil {
		return err
	}
	if err = verifyFile(ctx, sandbox, diskPath, marker); err != nil {
		return err
	}
	for _, path := range paths {
		out, execErr := sandbox.Shell(ctx, "test ! -e "+path+"/marker")
		if execErr != nil {
			return execErr
		}
		if !out.Success() {
			return fmt.Errorf("tmpfs marker unexpectedly survived restart: %s", path)
		}
	}
	r.Passed = append(r.Passed, label+"/stop-start-persistence")
	if err = sandbox.Stop(ctx); err != nil {
		return err
	}
	if err = sandbox.Close(); err != nil {
		return err
	}
	sandbox = nil
	if count == 0 {
		if err = snapshot(ctx, r, name, diskPath, marker); err != nil {
			return err
		}
	}
	if err = msb.RemoveSandbox(ctx, name); err != nil {
		return err
	}
	removed = true
	r.Passed = append(r.Passed, label+"/remove")
	return nil
}

func snapshot(ctx context.Context, r *report, name, path, marker string) (err error) {
	handle, err := msb.GetSandbox(ctx, name)
	if err != nil {
		return err
	}
	artifact, err := handle.Snapshot(ctx, "compat-disk")
	if err != nil {
		return err
	}
	selector := name + ":compat-disk"
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		err = errors.Join(err, msb.Snapshot.Remove(cleanupCtx, selector, true))
	}()
	if _, err = artifact.Verify(ctx); err != nil {
		return err
	}
	r.Passed = append(r.Passed, "disk-snapshot/capture-verify")
	forkName := name + "-restored"
	fork, err := msb.RestoreSandbox(ctx, selector, forkName)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, cleanup(forkName, fork)) }()
	if err = verifyRuntime(ctx, r, forkName); err != nil {
		return err
	}
	if err = verifyFile(ctx, fork, path, marker); err != nil {
		return err
	}
	r.Passed = append(r.Passed, "disk-snapshot/restore-persistence")
	return nil
}

func denyNetwork(ctx context.Context, r *report) (err error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		fmt.Fprint(w, "compat-network")
	})}
	defer server.Close()
	go func() { _ = server.Serve(listener) }()
	port := listener.Addr().(*net.TCPAddr).Port
	allowedName := fmt.Sprintf("compat-go-%d-allow", os.Getpid())
	allowed, err := msb.CreateSandbox(ctx, allowedName,
		msb.WithImage(os.Getenv("MSB_COMPAT_IMAGE")), msb.WithMemory(256), msb.WithCPUs(1),
		msb.WithNetwork(msb.NetworkPolicy.AllowAll()),
	)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, cleanup(allowedName, allowed)) }()
	if err = verifyRuntime(ctx, r, allowedName); err != nil {
		return err
	}
	probe := fmt.Sprintf(`gateway=$(awk '/^nameserver / { print $2; exit }' /etc/resolv.conf); test -n "$gateway" && wget -q -T 3 -O - "http://$gateway:%d/"`, port)
	positive := func() error {
		out, err := allowed.Shell(ctx, probe, msb.WithExecTimeout(10*time.Second))
		if err != nil {
			return err
		}
		if !out.Success() || out.Stdout() != "compat-network" {
			return fmt.Errorf("network positive control failed: exit=%d stdout=%q stderr=%q", out.ExitCode(), out.Stdout(), out.Stderr())
		}
		return nil
	}
	if err = positive(); err != nil {
		return err
	}
	name := fmt.Sprintf("compat-go-%d-deny", os.Getpid())
	sandbox, err := msb.CreateSandbox(ctx, name,
		msb.WithImage(os.Getenv("MSB_COMPAT_IMAGE")), msb.WithMemory(256), msb.WithCPUs(1),
		msb.WithNetwork(msb.NetworkPolicy.None()),
	)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, cleanup(name, sandbox)) }()
	if err = verifyRuntime(ctx, r, name); err != nil {
		return err
	}
	check, err := sandbox.Shell(ctx, "command -v wget")
	if err != nil {
		return err
	}
	if !check.Success() {
		return errors.New("network scenario requires wget in MSB_COMPAT_IMAGE")
	}
	// The same host-local service must be reachable immediately before and after
	// this denial. An external outage cannot accidentally satisfy the assertion.
	out, err := sandbox.Shell(ctx, probe, msb.WithExecTimeout(10*time.Second))
	if err != nil {
		return err
	}
	if out.Success() {
		return errors.New("deny-all network policy allowed host HTTP egress")
	}
	if err = positive(); err != nil {
		return err
	}
	r.Passed = append(r.Passed, "network/positive-control")
	r.Passed = append(r.Passed, "network/deny-all")
	return nil
}

func verifyRuntime(ctx context.Context, r *report, name string) error {
	python := os.Getenv("MSB_COMPAT_PYTHON")
	if python == "" {
		python = "python3"
	}
	for _, command := range [][]string{
		{python, os.Getenv("MSB_COMPAT_VERIFY_RUNTIME"), name},
		{os.Getenv("MSB_COMPAT_CLI"), "inspect", name, "--format", "json"},
	} {
		checkCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		var stderr bytes.Buffer
		process := exec.CommandContext(checkCtx, command[0], command[1:]...)
		process.Stderr = &stderr
		output, err := process.Output()
		cancel()
		if err != nil {
			return fmt.Errorf("%v: %w: %s", command, err, stderr.String())
		}
		if !json.Valid(output) {
			return fmt.Errorf("%v did not return JSON: %s", command, output)
		}
		r.RuntimeEvidence = append(r.RuntimeEvidence, append(json.RawMessage(nil), output...))
	}
	r.Passed = append(r.Passed, name+"/runtime-identity-cli-inspect")
	return nil
}

func verifyFile(ctx context.Context, sandbox *msb.Sandbox, path, want string) error {
	got, err := sandbox.FS().ReadString(ctx, path)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("%s: got %q, want %q", path, got, want)
	}
	return nil
}

func cleanup(name string, sandbox *msb.Sandbox) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var errs []error
	if sandbox != nil {
		errs = append(errs, sandbox.Stop(ctx), sandbox.Close())
	} else if handle, err := msb.GetSandbox(ctx, name); err == nil {
		errs = append(errs, handle.Stop(ctx))
	}
	errs = append(errs, msb.RemoveSandbox(ctx, name))
	return errors.Join(errs...)
}
