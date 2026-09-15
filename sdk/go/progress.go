package microsandbox

import (
	"context"
	"encoding/json"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// CreationProgress reports image work (Kind "pull") or runtime startup (Kind "startup").
// Progress fields are cumulative; events may be omitted for slow consumers.
type CreationProgress struct {
	Kind     string                 `json:"kind"`
	Progress CreationProgressDetail `json:"progress"`
}

// CreationProgressDetail contains stage-specific fields. Unknown totals are nil.
type CreationProgressDetail struct {
	Kind               string  `json:"kind,omitempty"`
	Phase              string  `json:"phase,omitempty"`
	CompletedBytes     uint64  `json:"completed_bytes"`
	TotalBytes         *uint64 `json:"total_bytes,omitempty"`
	Reference          string  `json:"reference,omitempty"`
	LayerIndex         *uint64 `json:"layer_index,omitempty"`
	LayerCount         *uint64 `json:"layer_count,omitempty"`
	Digest             string  `json:"digest,omitempty"`
	DiffID             string  `json:"diff_id,omitempty"`
	ManifestDigest     string  `json:"manifest_digest,omitempty"`
	DownloadedBytes    uint64  `json:"downloaded_bytes,omitempty"`
	TotalDownloadBytes *uint64 `json:"total_download_bytes,omitempty"`
	BytesRead          uint64  `json:"bytes_read,omitempty"`
}

// CreationResult is the authoritative creation outcome. The caller owns Sandbox on success.
type CreationResult struct {
	Sandbox *Sandbox
	Err     error
}

// CreateSandboxWithProgress starts creation and returns events and a single result.
// Always receive the result and close its Sandbox when finished. Ignoring progress never
// delays or cancels creation. Cancel ctx to cancel creation, not just observation.
func CreateSandboxWithProgress(ctx context.Context, name string, opts ...SandboxOption) (<-chan CreationProgress, <-chan CreationResult) {
	return sandboxWithProgress(ctx, func(id uint64) (*ffi.Sandbox, error) {
		config := SandboxConfig{}
		for _, opt := range opts {
			opt(&config)
		}
		if err := resolveRegistryCACertPaths(&config); err != nil {
			return nil, err
		}
		options := buildFFICreateOptions(config)
		if err := validateOwnedMounts(config.Volumes); err != nil {
			return nil, err
		}
		options.CreationProgress = id
		return ffi.CreateSandbox(ctx, name, options)
	})
}

// RestoreSandboxWithProgress restores a detached sandbox with bounded progress events.
func RestoreSandboxWithProgress(ctx context.Context, snapshot, name string, opts ...RestoreOption) (<-chan CreationProgress, <-chan CreationResult) {
	return sandboxWithProgress(ctx, func(id uint64) (*ffi.Sandbox, error) {
		config := RestoreConfig{}
		for _, opt := range opts {
			opt(&config)
		}
		options := buildFFIRestoreOptions(snapshot, config)
		if err := validateOwnedMounts(config.Volumes); err != nil {
			return nil, err
		}
		options.CreationProgress = id
		return ffi.RestoreSandbox(ctx, name, options)
	})
}

func sandboxWithProgress(ctx context.Context, start func(uint64) (*ffi.Sandbox, error)) (<-chan CreationProgress, <-chan CreationResult) {

	events := make(chan CreationProgress, 64)
	results := make(chan CreationResult, 1)
	go func() {
		defer close(events)
		defer close(results)
		id, err := ffi.OpenCreationProgress(ctx)
		if err != nil {
			results <- CreationResult{Err: wrapFFI(err)}
			return
		}
		defer ffi.CloseCreationProgress(id)
		observation, stop := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				raw, err := ffi.ReceiveCreationProgress(observation, id)
				if err != nil {
					return
				}
				var event CreationProgress
				if json.Unmarshal(raw, &event) != nil {
					continue
				}
				select {
				case events <- event:
				default:
				} // Telemetry never holds up creation.
			}
		}()
		inner, err := start(id)
		stop()
		<-done // No sender may remain when events is closed.
		if err != nil {
			results <- CreationResult{Err: wrapFFI(err)}
			return
		}
		results <- CreationResult{Sandbox: &Sandbox{inner: inner}}
	}()
	return events, results
}
