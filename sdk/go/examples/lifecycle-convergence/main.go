// Lifecycle convergence and identity-safety example.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

// Metrics is the common JSON result emitted by every SDK lifecycle example.
type Metrics struct {
	SDK       string             `json:"sdk"`
	Platform  string             `json:"platform"`
	Sandbox   string             `json:"sandbox"`
	Identity  string             `json:"identity"`
	Checks    int                `json:"checks"`
	TimingsMS map[string]float64 `json:"timings_ms"`
	Result    string             `json:"result"`
}

func elapsedMS(start time.Time) float64 {
	return float64(time.Since(start).Microseconds()) / 1_000
}

func readMarker(ctx context.Context, sandbox *microsandbox.Sandbox) (string, error) {
	output, err := sandbox.Shell(ctx, `printf '%s' "$LIFECYCLE_MARKER"`)
	if err != nil {
		return "", err
	}
	if !output.Success() {
		return "", fmt.Errorf("marker exec failed with code %d", output.ExitCode())
	}
	return output.Stdout(), nil
}

func cleanup(ctx context.Context, name string) {
	handle, err := microsandbox.GetSandbox(ctx, name)
	if err != nil {
		return
	}
	_ = handle.Destroy(ctx, microsandbox.WithDestroyForce(), microsandbox.WithDestroyTimeout(5*time.Second))
}

func run(ctx context.Context, name, image, platform string) (_ *Metrics, err error) {
	total := time.Now()
	timings := make(map[string]float64)
	var live []*microsandbox.Sandbox
	defer func() {
		for _, sandbox := range live {
			_ = sandbox.Close()
		}
		if err != nil {
			cleanup(context.Background(), name)
		}
	}()

	started := time.Now()
	created, err := microsandbox.FindOrCreateSandbox(ctx, name,
		microsandbox.WithImage(image),
		microsandbox.WithCPUs(1),
		microsandbox.WithMemory(256),
		microsandbox.WithEnv(map[string]string{"LIFECYCLE_MARKER": "original"}),
	)
	if err != nil {
		return nil, err
	}
	live = append(live, created)
	timings["find_or_create_new"] = elapsedMS(started)
	originalID := created.ID()

	started = time.Now()
	reused, err := microsandbox.FindOrCreateSandbox(ctx, name,
		microsandbox.WithImage(image),
		microsandbox.WithMemory(768),
		microsandbox.WithEnv(map[string]string{"LIFECYCLE_MARKER": "ignored"}),
	)
	if err != nil {
		return nil, err
	}
	live = append(live, reused)
	timings["find_or_create_existing"] = elapsedMS(started)
	if reused.ID() != originalID {
		return nil, fmt.Errorf("find_or_create changed the persisted identity")
	}
	marker, err := readMarker(ctx, reused)
	if err != nil || strings.TrimSpace(marker) != "original" {
		return nil, fmt.Errorf("existing configuration did not win: marker=%q err=%w", marker, err)
	}

	handle, err := microsandbox.GetSandbox(ctx, name)
	if err != nil {
		return nil, err
	}
	started = time.Now()
	connected, err := handle.ConnectOrStart(ctx)
	if err != nil {
		return nil, err
	}
	live = append(live, connected)
	timings["connect_or_start"] = elapsedMS(started)
	if connected.ID() != originalID {
		return nil, fmt.Errorf("connect_or_start changed the persisted identity")
	}

	started = time.Now()
	if _, err = connected.WaitForStatus(ctx, microsandbox.SandboxStatusRunning); err != nil {
		return nil, err
	}
	timings["wait_for_running"] = elapsedMS(started)
	started = time.Now()
	marker, err = readMarker(ctx, connected)
	if err != nil || strings.TrimSpace(marker) != "original" {
		return nil, fmt.Errorf("exec observed the wrong configuration: marker=%q err=%w", marker, err)
	}
	timings["exec"] = elapsedMS(started)

	started = time.Now()
	restarted, err := connected.Restart(ctx)
	if err != nil {
		return nil, err
	}
	live = append(live, restarted)
	timings["restart"] = elapsedMS(started)
	if restarted.ID() != originalID {
		return nil, fmt.Errorf("restart changed the persisted identity")
	}
	marker, err = readMarker(ctx, restarted)
	if err != nil || strings.TrimSpace(marker) != "original" {
		return nil, fmt.Errorf("restart lost persisted configuration: marker=%q err=%w", marker, err)
	}

	stale, err := microsandbox.GetSandbox(ctx, name)
	if err != nil {
		return nil, err
	}
	started = time.Now()
	if err = restarted.Destroy(ctx); err != nil {
		return nil, err
	}
	timings["destroy_original"] = elapsedMS(started)

	replacement, err := microsandbox.FindOrCreateSandbox(ctx, name,
		microsandbox.WithImage(image),
		microsandbox.WithCPUs(1),
		microsandbox.WithMemory(256),
		microsandbox.WithEnv(map[string]string{"LIFECYCLE_MARKER": "replacement"}),
	)
	if err != nil {
		return nil, err
	}
	live = append(live, replacement)
	if replacement.ID() == originalID {
		return nil, fmt.Errorf("replacement reused the destroyed identity")
	}

	started = time.Now()
	err = stale.Destroy(ctx)
	if !microsandbox.IsKind(err, microsandbox.ErrSandboxReplaced) {
		return nil, fmt.Errorf("expected stale identity rejection, got %w", err)
	}
	err = nil
	timings["stale_identity_rejection"] = elapsedMS(started)
	marker, err = readMarker(ctx, replacement)
	if err != nil || strings.TrimSpace(marker) != "replacement" {
		return nil, fmt.Errorf("stale receiver harmed replacement: marker=%q err=%w", marker, err)
	}

	started = time.Now()
	if err = replacement.Destroy(ctx); err != nil {
		return nil, err
	}
	timings["destroy_replacement"] = elapsedMS(started)
	timings["total"] = elapsedMS(total)

	return &Metrics{
		SDK:       "go",
		Platform:  platform,
		Sandbox:   name,
		Identity:  originalID,
		Checks:    10,
		TimingsMS: timings,
		Result:    "pass",
	}, nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	name := os.Getenv("MSB_E2E_NAME")
	if name == "" {
		name = fmt.Sprintf("lifecycle-go-%d", os.Getpid())
	}
	image := os.Getenv("MSB_E2E_IMAGE")
	if image == "" {
		image = "alpine:3.19"
	}
	platform := os.Getenv("MSB_E2E_PLATFORM")
	if platform == "" {
		platform = runtime.GOOS + "-" + runtime.GOARCH
	}

	cleanup(ctx, name)
	metrics, err := run(ctx, name, image, platform)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	payload, err := json.Marshal(metrics)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("MSB_LIFECYCLE_METRICS %s\n", payload)
}
