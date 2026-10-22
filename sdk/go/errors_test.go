package microsandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

func TestErrorKindString(t *testing.T) {
	cases := []struct {
		kind ErrorKind
		want string
	}{
		{ErrUnknown, "Unknown"},
		{ErrSandboxNotFound, "SandboxNotFound"},
		{ErrSandboxReplaced, "SandboxReplaced"},
		{ErrSandboxStopTimedOut, "SandboxStopTimedOut"},
		{ErrSandboxStillRunning, "SandboxStillRunning"},
		{ErrVolumeNotFound, "VolumeNotFound"},
		{ErrVolumeAlreadyExists, "VolumeAlreadyExists"},
		{ErrExecTimeout, "ExecTimeout"},
		{ErrStopTimeout, "StopTimeout"},
		{ErrInvalidConfig, "InvalidConfig"},
		{ErrInvalidArgument, "InvalidArgument"},
		{ErrInvalidHandle, "InvalidHandle"},
		{ErrBufferTooSmall, "BufferTooSmall"},
		{ErrCancelled, "Cancelled"},
		{ErrMetricsDisabled, "MetricsDisabled"},
		{ErrMetricsUnavailable, "MetricsUnavailable"},
		{ErrUnsupportedOperation, "UnsupportedOperation"},
		{ErrInternal, "Internal"},
		{ErrNoDefaultCommand, "NoDefaultCommand"},
		{ErrorKind(9999), "Unknown"},
	}
	for _, c := range cases {
		if got := c.kind.String(); got != c.want {
			t.Errorf("ErrorKind(%d).String() = %q, want %q", int(c.kind), got, c.want)
		}
	}
}

func TestErrorError(t *testing.T) {
	e := &Error{Kind: ErrSandboxNotFound, Message: "no such sandbox"}
	got := e.Error()
	want := "no such sandbox"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestErrorErrorWithCause(t *testing.T) {
	cause := errors.New("root cause")
	e := &Error{Kind: ErrInternal, Message: "transport failed", Cause: cause}
	got := e.Error()
	if got != "transport failed: root cause" {
		t.Errorf("unexpected: %q", got)
	}
	if !errors.Is(e, cause) {
		t.Error("errors.Is should unwrap to cause")
	}
}

func TestErrorErrorEmptyMessageFallsBackToKind(t *testing.T) {
	e := &Error{Kind: ErrInvalidHandle}
	if got := e.Error(); got != "InvalidHandle" {
		t.Errorf("want kind fallback, got %q", got)
	}
}

func TestErrorErrorEmptyMessageWithCauseUsesCause(t *testing.T) {
	cause := errors.New("dlopen: no such file")
	e := &Error{Kind: ErrLibraryNotLoaded, Cause: cause}
	if got := e.Error(); got != "dlopen: no such file" {
		t.Errorf("want cause passthrough, got %q", got)
	}
}

func TestIsKind(t *testing.T) {
	e := &Error{Kind: ErrSandboxNotFound, Message: "gone"}
	if !IsKind(e, ErrSandboxNotFound) {
		t.Error("IsKind should match direct error")
	}
	wrapped := fmt.Errorf("wrap: %w", e)
	if !IsKind(wrapped, ErrSandboxNotFound) {
		t.Error("IsKind should match wrapped error")
	}
	if IsKind(e, ErrInvalidHandle) {
		t.Error("IsKind should not match a different kind")
	}
	if IsKind(nil, ErrSandboxNotFound) {
		t.Error("IsKind(nil, ...) should return false")
	}
}

func TestWrapFFINil(t *testing.T) {
	if wrapFFI(nil) != nil {
		t.Error("wrapFFI(nil) should return nil")
	}
}

func TestSnapshotSourceRecoveryError(t *testing.T) {
	for _, kind := range []string{"installed", "archive", ""} {
		t.Run(kind, func(t *testing.T) {
			artifact := "null"
			publicationError := `"disk full"`
			if kind != "" {
				artifact = fmt.Sprintf(`{"kind":%q,"path":"/saved","snapshot_id":"snap_1","digest":"sha256:digest"}`, kind)
				publicationError = "null"
			}
			payload := fmt.Sprintf(`{"kind":"snapshot_source_recovery","message":"capture completed, source recovery failed","recovery":{"source_sandbox":"team/source","checkpoint_id":"checkpoint-1","checkpoint_root":"sha256:root","checkpoint_path":"/runtime/checkpoint","artifact":%s,"detail":"thaw acknowledgement lost","publication_error":%s}}`, artifact, publicationError)
			var native ffi.Error
			if err := json.Unmarshal([]byte(payload), &native); err != nil {
				t.Fatal(err)
			}
			err := fmt.Errorf("snapshot: %w", wrapFFI(&native))
			var recovery *SnapshotSourceRecoveryError
			if !errors.As(err, &recovery) {
				t.Fatalf("missing typed recovery: %v", err)
			}
			if !IsKind(err, ErrSnapshotSourceRecovery) {
				t.Fatal("kind lost through wrapping")
			}
			if recovery.Error() != native.Message {
				t.Fatalf("message changed: %s", recovery)
			}
			r := recovery.Recovery
			if r.SourceSandbox != "team/source" || r.CheckpointID != "checkpoint-1" || r.CheckpointRoot != "sha256:root" || r.CheckpointPath != "/runtime/checkpoint" || r.Detail != "thaw acknowledgement lost" {
				t.Fatalf("metadata lost: %+v", r)
			}
			if kind == "" {
				if r.Artifact != nil || r.PublicationError == nil || *r.PublicationError != "disk full" {
					t.Fatalf("unpublished recovery lost: %+v", r)
				}
			} else if r.Artifact == nil || r.Artifact.Kind != kind || r.Artifact.Path != "/saved" || r.Artifact.SnapshotID != "snap_1" || r.Artifact.Digest != "sha256:digest" || r.PublicationError != nil {
				t.Fatalf("published artifact lost: %+v", r)
			}
		})
	}
}

// Missing fields from older native producers remain unknown, not a guessed head.
func TestSnapshotRecoveryPublicationHead(t *testing.T) {
	for _, head := range []string{`null`, `{"group":"history","previous":null,"head":"snap_1","reason":"initialized","changed":true}`} {
		payload := `{"kind":"snapshot_source_recovery","message":"source recovery failed","recovery":{"artifact":{"kind":"installed","path":"/saved","snapshot_id":"snap_1","digest":"digest","head_update":` + head + `}}}`
		var native ffi.Error
		if err := json.Unmarshal([]byte(payload), &native); err != nil {
			t.Fatal(err)
		}
		var recovery *SnapshotSourceRecoveryError
		if !errors.As(wrapFFI(&native), &recovery) {
			t.Fatal("lost typed error")
		}
		update := recovery.Recovery.Artifact.HeadUpdate
		if head == "null" {
			if update != nil {
				t.Fatal("invented head outcome")
			}
		} else if update == nil || update.Group != "history" || update.Head == nil || *update.Head != "snap_1" || update.Reason != "initialized" || !update.Changed {
			t.Fatalf("lost publication outcome: %+v", update)
		}
	}
}

func TestWrapFFIFfiError(t *testing.T) {
	fe := &ffi.Error{Kind: ffi.KindSandboxNotFound, Message: "missing"}
	err := wrapFFI(fe)
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("wrapFFI should return *Error, got %T", err)
	}
	if e.Kind != ErrSandboxNotFound {
		t.Errorf("got Kind %v, want ErrSandboxNotFound", e.Kind)
	}
	if e.Message != "missing" {
		t.Errorf("got Message %q, want %q", e.Message, "missing")
	}
}

func TestWrapFFINonFfiError(t *testing.T) {
	raw := errors.New("plain error")
	err := wrapFFI(raw)
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("wrapFFI should return *Error, got %T", err)
	}
	if e.Kind != ErrInternal {
		t.Errorf("non-ffi error should map to ErrInternal, got %v", e.Kind)
	}
	if !errors.Is(err, raw) {
		t.Error("cause should be unwrappable via errors.Is")
	}
}

func TestKindFromFFIAllTags(t *testing.T) {
	cases := []struct {
		tag  string
		want ErrorKind
	}{
		{ffi.KindSandboxNotFound, ErrSandboxNotFound},
		{ffi.KindSandboxAlreadyExists, ErrSandboxAlreadyExists},
		{ffi.KindSandboxReplaced, ErrSandboxReplaced},
		{ffi.KindSandboxStopTimedOut, ErrSandboxStopTimedOut},
		{ffi.KindSandboxStillRunning, ErrSandboxStillRunning},
		{ffi.KindVolumeNotFound, ErrVolumeNotFound},
		{ffi.KindVolumeAlreadyExists, ErrVolumeAlreadyExists},
		{ffi.KindExecTimeout, ErrExecTimeout},
		{ffi.KindStopTimeout, ErrStopTimeout},
		{ffi.KindNoDefaultCommand, ErrNoDefaultCommand},
		{ffi.KindInvalidConfig, ErrInvalidConfig},
		{ffi.KindInvalidArgument, ErrInvalidArgument},
		{ffi.KindInvalidHandle, ErrInvalidHandle},
		{ffi.KindBufferTooSmall, ErrBufferTooSmall},
		{ffi.KindCancelled, ErrCancelled},
		{ffi.KindMetricsDisabled, ErrMetricsDisabled},
		{ffi.KindMetricsUnavailable, ErrMetricsUnavailable},
		{ffi.KindUnsupportedOperation, ErrUnsupportedOperation},
		{"unrecognized_tag", ErrInternal},
	}
	for _, c := range cases {
		got := kindFromFFI(c.tag)
		if got != c.want {
			t.Errorf("kindFromFFI(%q) = %v, want %v", c.tag, got, c.want)
		}
	}
}

func TestSnapshotImportPublicationOutcome(t *testing.T) {
	for _, outcome := range []string{"not_committed", "committed", "unknown"} {
		t.Run(outcome, func(t *testing.T) {
			payload := fmt.Sprintf(`{"kind":"snapshot_import","message":"batch failure","import":{"operation_id":"attempt-1","archives":["/base.msb","/child.msb"],"group_path":null,"outcome":%q,"detail":"index failure"}}`, outcome)
			var native ffi.Error
			if err := json.Unmarshal([]byte(payload), &native); err != nil {
				t.Fatal(err)
			}
			err := wrapFFI(&native)
			var imported *SnapshotImportError
			if !errors.As(err, &imported) || !IsKind(err, ErrSnapshotImport) {
				t.Fatalf("lost import details: %v", err)
			}
			if string(imported.Details.Outcome) != outcome || imported.Details.OperationID != "attempt-1" || imported.Details.GroupPath != nil || len(imported.Details.Archives) != 2 {
				t.Fatalf("wrong details: %+v", imported.Details)
			}
			native.Import.Archives[0] = "changed"
			if imported.Details.Archives[0] != "/base.msb" {
				t.Fatal("native payload remained aliased")
			}
			if imported.Error() != native.Message || imported.Details.Detail != "index failure" {
				t.Fatal("original diagnostic lost")
			}
		})
	}
}

func TestCommittedCheckpointRemovalPreservesOutcome(t *testing.T) {
	native := &ffi.Error{
		Kind:    ffi.KindSnapshotRemovalRecovery,
		Message: "removal committed; cleanup failed",
		Detail:  "catalog unavailable",
		Removal: json.RawMessage(`{"id":"removed","head_update":{"group":"history","previous":"removed","head":"parent","reason":"parent_fallback","changed":true},"warnings":[]}`),
	}
	err := wrapFFI(native)
	var recovery *SnapshotRemovalRecoveryError
	if !errors.As(err, &recovery) {
		t.Fatalf("lost typed recovery: %T %v", err, err)
	}
	if recovery.Result.ID != "removed" || recovery.Result.HeadUpdate == nil || recovery.Result.HeadUpdate.Head == nil || *recovery.Result.HeadUpdate.Head != "parent" {
		t.Fatalf("lost committed outcome: %+v", recovery.Result)
	}
	if recovery.Detail != "catalog unavailable" || !IsKind(err, ErrSnapshotRemovalRecovery) || !errors.Is(err, native) {
		t.Fatalf("lost error identity: %+v", recovery)
	}
}

func TestCommittedGroupRemovalPreservesOutcome(t *testing.T) {
	native := &ffi.Error{Kind: ffi.KindSnapshotGroupRemovalRecovery, Message: "group removed; cleanup failed", Detail: "catalog unavailable", Removal: json.RawMessage(`{"group":"history","removed":["parent","child"],"head_update":{"group":"history","previous":"child","head":null,"reason":"cleared","changed":true},"warnings":[]}`)}
	err := wrapFFI(native)
	var recovery *SnapshotGroupRemovalRecoveryError
	if !errors.As(err, &recovery) {
		t.Fatalf("lost typed recovery: %T %v", err, err)
	}
	if recovery.Result.Group != "history" || len(recovery.Result.Removed) != 2 || recovery.Result.HeadUpdate == nil || recovery.Result.HeadUpdate.Head != nil {
		t.Fatalf("lost committed outcome: %+v", recovery.Result)
	}
	if recovery.Detail != "catalog unavailable" || !IsKind(err, ErrSnapshotGroupRemovalRecovery) || !errors.Is(err, native) {
		t.Fatalf("lost error identity: %+v", recovery)
	}
}
