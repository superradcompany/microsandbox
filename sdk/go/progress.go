package microsandbox

import (
	"context"
	"encoding/json"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// StartupPhase identifies the runtime preparation phase.
type StartupPhase string

const (
	StartupPhasePreparingSnapshot       StartupPhase = "preparing_snapshot"
	StartupPhaseWaitingForMemoryBacking StartupPhase = "waiting_for_memory_backing"
	StartupPhasePreparingMemoryBacking  StartupPhase = "preparing_memory_backing"
	StartupPhaseReusingMemoryBacking    StartupPhase = "reusing_memory_backing"
	StartupPhaseSyncingMemoryBacking    StartupPhase = "syncing_memory_backing"
	StartupPhaseActivating              StartupPhase = "activating"
)

// PullEventKind identifies the image preparation event reported during a pull.
type PullEventKind string

const (
	PullEventResolving                PullEventKind = "resolving"
	PullEventResolved                 PullEventKind = "resolved"
	PullEventLayerDownloadProgress    PullEventKind = "layer_download_progress"
	PullEventLayerDownloadComplete    PullEventKind = "layer_download_complete"
	PullEventLayerDownloadVerifying   PullEventKind = "layer_download_verifying"
	PullEventLayerMaterializeStarted  PullEventKind = "layer_materialize_started"
	PullEventLayerMaterializeProgress PullEventKind = "layer_materialize_progress"
	PullEventLayerMaterializeWriting  PullEventKind = "layer_materialize_writing"
	PullEventLayerMaterializeComplete PullEventKind = "layer_materialize_complete"
	PullEventStitchMergingTrees       PullEventKind = "stitch_merging_trees"
	PullEventStitchWritingFsmeta      PullEventKind = "stitch_writing_fsmeta"
	PullEventStitchWritingVMDK        PullEventKind = "stitch_writing_vmdk"
	PullEventStitchComplete           PullEventKind = "stitch_complete"
	PullEventComplete                 PullEventKind = "complete"
)

// CreationProgressKind identifies the stage family of a creation progress event.
type CreationProgressKind string

const (
	CreationProgressPull    CreationProgressKind = "pull"
	CreationProgressStartup CreationProgressKind = "startup"
)

// CreationProgress reports image work (Kind "pull") or runtime startup (Kind "startup").
// Progress fields are cumulative; events may be omitted for slow consumers.
type CreationProgress struct {
	Kind     CreationProgressKind   `json:"kind"`
	Progress CreationProgressDetail `json:"progress"`
}

// CreationProgressDetail contains stage-specific fields. Unknown totals are nil.
type CreationProgressDetail struct {
	Kind               PullEventKind `json:"kind,omitempty"`
	Phase              StartupPhase  `json:"phase,omitempty"`
	CompletedBytes     uint64        `json:"completed_bytes"`
	TotalBytes         *uint64       `json:"total_bytes,omitempty"`
	Reference          string        `json:"reference,omitempty"`
	LayerIndex         *uint64       `json:"layer_index,omitempty"`
	LayerCount         *uint64       `json:"layer_count,omitempty"`
	Digest             string        `json:"digest,omitempty"`
	DiffID             string        `json:"diff_id,omitempty"`
	ManifestDigest     string        `json:"manifest_digest,omitempty"`
	DownloadedBytes    uint64        `json:"downloaded_bytes,omitempty"`
	TotalDownloadBytes *uint64       `json:"total_download_bytes,omitempty"`
	BytesRead          uint64        `json:"bytes_read,omitempty"`
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
	if err := ctx.Err(); err != nil {
		return failedCreationProgress(err)
	}
	config := SandboxConfig{}
	for _, option := range opts {
		option(&config)
	}
	if err := prepareSandboxCreateConfig(&config); err != nil {
		return failedCreationProgress(err)
	}
	selected, err := configuredContext()
	if err != nil {
		return failedCreationProgress(err)
	}
	return selected.Sandboxes().createWithProgress(ctx, name, config)
}

// RestoreSandboxWithProgress restores a detached sandbox with bounded progress events.
func RestoreSandboxWithProgress[T SnapshotSeed](ctx context.Context, snapshot T, name string, opts ...RestoreOption) (<-chan CreationProgress, <-chan CreationResult) {
	if err := ctx.Err(); err != nil {
		return failedCreationProgress(err)
	}
	config := RestoreConfig{}
	for _, opt := range opts {
		opt(&config)
	}
	if err := validateRestoreConfig(config); err != nil {
		return failedCreationProgress(err)
	}
	selected, err := restoreContext(snapshot)
	if err != nil {
		return failedCreationProgress(err)
	}
	destination := selected.nativeContext()
	return sandboxWithProgress(ctx, destination.Library(), func(id uint64) (*ffi.Sandbox, error) {
		options := buildFFIRestoreOptions(snapshot, config)
		options.CreationProgress = id
		return destination.RestoreSandbox(ctx, name, options)
	})
}

func sandboxWithProgress(ctx context.Context, library *ffi.Library, start func(uint64) (*ffi.Sandbox, error)) (<-chan CreationProgress, <-chan CreationResult) {

	events := make(chan CreationProgress, 64)
	results := make(chan CreationResult, 1)
	go func() {
		defer close(events)
		defer close(results)
		id, err := library.OpenCreationProgress(ctx)
		if err != nil {
			results <- CreationResult{Err: wrapFFI(err)}
			return
		}
		defer library.CloseCreationProgress(id)
		observation, stop := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				raw, err := library.ReceiveCreationProgress(observation, id)
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

// CreateWithProgress retains this collection's provider for creation and telemetry.
func (s *Sandboxes) CreateWithProgress(ctx context.Context, name string, opts ...SandboxOption) (<-chan CreationProgress, <-chan CreationResult) {
	config := SandboxConfig{}
	for _, opt := range opts {
		opt(&config)
	}
	if err := prepareSandboxCreateConfig(&config); err != nil {
		return failedCreationProgress(err)
	}
	return s.createWithProgress(ctx, name, config)
}

// The options have already been applied and validated; callbacks run only once.
func (s *Sandboxes) createWithProgress(ctx context.Context, name string, config SandboxConfig) (<-chan CreationProgress, <-chan CreationResult) {
	destination, err := nativeDestination(s.selected)
	if err != nil {
		return failedCreationProgress(err)
	}
	return sandboxWithProgress(ctx, destination.Library(), func(id uint64) (*ffi.Sandbox, error) {
		options := buildFFICreateOptions(config)
		options.CreationProgress = id
		return destination.CreateSandbox(ctx, name, options, false)
	})
}

func failedCreationProgress(err error) (<-chan CreationProgress, <-chan CreationResult) {
	events := make(chan CreationProgress)
	results := make(chan CreationResult, 1)
	results <- CreationResult{Err: err}
	close(events)
	close(results)
	return events, results
}

// RestoreWithProgress restores a reference in this collection's destination.
func (s *Sandboxes) RestoreWithProgress(ctx context.Context, snapshot string, name string, opts ...RestoreOption) (<-chan CreationProgress, <-chan CreationResult) {
	destination, err := nativeDestination(s.selected)
	if err != nil {
		return failedCreationProgress(err)
	}
	config := RestoreConfig{}
	for _, opt := range opts {
		opt(&config)
	}
	if err := validateRestoreConfig(config); err != nil {
		return failedCreationProgress(err)
	}
	return sandboxWithProgress(ctx, destination.Library(), func(id uint64) (*ffi.Sandbox, error) {
		options := buildFFIRestoreOptions(snapshot, config)
		options.CreationProgress = id
		return destination.RestoreSandbox(ctx, name, options)
	})
}
