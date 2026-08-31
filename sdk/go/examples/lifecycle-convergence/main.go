// Lifecycle convergence and identity-safety example.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
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

func runConcurrencyChecks(
	ctx context.Context,
	name, image string,
	timings map[string]float64,
	live *[]*microsandbox.Sandbox,
) error {
	raceName := name + "-race"
	cleanup(ctx, raceName)
	candidates := []string{"candidate-0", "candidate-1", "candidate-2", "candidate-3"}
	raced := make([]*microsandbox.Sandbox, len(candidates))
	errs := make([]error, len(candidates))
	start := make(chan struct{})
	var group sync.WaitGroup
	started := time.Now()
	for index, marker := range candidates {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			raced[index], errs[index] = microsandbox.ConnectOrCreateSandbox(ctx, raceName,
				microsandbox.WithImage(image),
				microsandbox.WithCPUs(1),
				microsandbox.WithMemory(256),
				microsandbox.WithEnv(map[string]string{"LIFECYCLE_MARKER": marker}),
			)
		}()
	}
	close(start)
	group.Wait()
	timings["concurrent_connect_or_create"] = elapsedMS(started)
	for index, err := range errs {
		if err != nil {
			return fmt.Errorf("concurrent connect_or_create caller %d: %w", index, err)
		}
	}
	*live = append(*live, raced...)
	raceID := raced[0].ID()
	for _, sandbox := range raced {
		if sandbox.ID() != raceID {
			return fmt.Errorf("concurrent connect_or_create callers selected different identities")
		}
	}
	marker, err := readMarker(ctx, raced[0])
	if err != nil {
		return err
	}
	marker = strings.TrimSpace(marker)
	if marker != candidates[0] && marker != candidates[1] && marker != candidates[2] && marker != candidates[3] {
		return fmt.Errorf("concurrent creation persisted unexpected marker %q", marker)
	}

	if err = raced[0].Stop(ctx); err != nil {
		return err
	}
	handles := make([]*microsandbox.SandboxHandle, len(candidates))
	for index := range handles {
		handles[index], err = microsandbox.GetSandbox(ctx, raceName)
		if err != nil {
			return err
		}
	}
	connected := make([]*microsandbox.Sandbox, len(candidates))
	errs = make([]error, len(candidates))
	start = make(chan struct{})
	started = time.Now()
	for index := range handles {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			connected[index], errs[index] = handles[index].ConnectOrStart(ctx)
		}()
	}
	close(start)
	group.Wait()
	timings["concurrent_connect_or_start"] = elapsedMS(started)
	for index, err := range errs {
		if err != nil {
			return fmt.Errorf("concurrent connect_or_start caller %d: %w", index, err)
		}
	}
	*live = append(*live, connected...)
	for _, sandbox := range connected {
		if sandbox.ID() != raceID {
			return fmt.Errorf("concurrent connect_or_start callers selected different identities")
		}
	}
	if current, err := readMarker(ctx, connected[0]); err != nil || strings.TrimSpace(current) != marker {
		return fmt.Errorf("start race lost persisted configuration: marker=%q err=%w", current, err)
	}

	if err = connected[0].Stop(ctx); err != nil {
		return err
	}
	started = time.Now()
	detached, err := handles[0].ConnectOrStart(ctx, microsandbox.WithConnectOrStartDetached())
	if err != nil {
		return err
	}
	*live = append(*live, detached)
	timings["connect_or_start_detached"] = elapsedMS(started)
	owns, err := detached.OwnsLifecycle()
	if err != nil || detached.ID() != raceID || owns {
		return fmt.Errorf("detached connect_or_start changed identity or took lifecycle ownership: owns=%v err=%w", owns, err)
	}

	started = time.Now()
	forced, err := detached.Restart(ctx,
		microsandbox.WithRestartForce(),
		microsandbox.WithRestartTimeout(5*time.Second),
	)
	if err != nil {
		return err
	}
	*live = append(*live, forced)
	timings["restart_force"] = elapsedMS(started)
	owns, err = forced.OwnsLifecycle()
	if err != nil || forced.ID() != raceID || !owns {
		return fmt.Errorf("forced restart changed identity or failed to return an attached handle: owns=%v err=%w", owns, err)
	}
	if current, err := readMarker(ctx, forced); err != nil || strings.TrimSpace(current) != marker {
		return fmt.Errorf("forced restart lost persisted configuration: marker=%q err=%w", current, err)
	}

	started = time.Now()
	detachedRestart, err := forced.Restart(ctx,
		microsandbox.WithRestartTimeout(3*time.Second),
		microsandbox.WithRestartDetached(),
	)
	if err != nil {
		return err
	}
	*live = append(*live, detachedRestart)
	timings["restart_detached_timeout"] = elapsedMS(started)
	owns, err = detachedRestart.OwnsLifecycle()
	if err != nil || detachedRestart.ID() != raceID || owns {
		return fmt.Errorf("detached restart changed identity or took lifecycle ownership: owns=%v err=%w", owns, err)
	}
	if current, err := readMarker(ctx, detachedRestart); err != nil || strings.TrimSpace(current) != marker {
		return fmt.Errorf("detached restart lost persisted configuration: marker=%q err=%w", current, err)
	}

	started = time.Now()
	if err = detachedRestart.Destroy(ctx,
		microsandbox.WithDestroyForce(),
		microsandbox.WithDestroyTimeout(5*time.Second),
	); err != nil {
		return err
	}
	timings["destroy_force_timeout"] = elapsedMS(started)
	return nil
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
			cleanup(context.Background(), name+"-race")
		}
	}()

	if err = runConcurrencyChecks(ctx, name, image, timings, &live); err != nil {
		return nil, err
	}

	started := time.Now()
	created, err := microsandbox.ConnectOrCreateSandbox(ctx, name,
		microsandbox.WithImage(image),
		microsandbox.WithCPUs(1),
		microsandbox.WithMemory(256),
		microsandbox.WithEnv(map[string]string{"LIFECYCLE_MARKER": "original"}),
	)
	if err != nil {
		return nil, err
	}
	live = append(live, created)
	timings["connect_or_create_new"] = elapsedMS(started)
	originalID := created.ID()

	started = time.Now()
	reused, err := microsandbox.ConnectOrCreateSandbox(ctx, name,
		microsandbox.WithImage(image),
		microsandbox.WithMemory(768),
		microsandbox.WithEnv(map[string]string{"LIFECYCLE_MARKER": "ignored"}),
	)
	if err != nil {
		return nil, err
	}
	live = append(live, reused)
	timings["connect_or_create_existing"] = elapsedMS(started)
	if reused.ID() != originalID {
		return nil, fmt.Errorf("connect_or_create changed the persisted identity")
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

	replacement, err := microsandbox.ConnectOrCreateSandbox(ctx, name,
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
		Checks:    16,
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
	cleanup(ctx, name+"-race")
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
