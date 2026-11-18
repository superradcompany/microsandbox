package microsandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"testing"
	"time"

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
		{ErrCloudOnly, "CloudOnly"},
		{ErrModificationNotConfirmed, "ModificationNotConfirmed"},
		{ErrInternal, "Internal"},
		{ErrNoDefaultCommand, "NoDefaultCommand"},
		{ErrServiceNotFound, "ServiceNotFound"},
		{ErrServiceAlreadyExists, "ServiceAlreadyExists"},
		{ErrService, "Service"},
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

func TestModificationNotConfirmedErrorPreservesMessage(t *testing.T) {
	message := "the change did not complete as asked: the running sandbox does not hold the secret"
	err := wrapFFI(&ffi.Error{
		Kind:    ffi.KindModificationNotConfirmed,
		Message: message,
	})

	if !IsKind(err, ErrModificationNotConfirmed) {
		t.Fatalf("got %v, want ErrModificationNotConfirmed", err)
	}
	if err.Error() != message {
		t.Fatalf("got %q, want %q", err.Error(), message)
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

func TestServiceError(t *testing.T) {
	cases := []struct {
		payload    string
		reason     ServiceErrorReason
		retryAfter time.Duration
		changed    ChangeState
		code       string
		status     int
		message    string
	}{
		{
			`{"kind":"service","message":"service shop: unreachable","changed":"unchanged","service":{"slug":"shop","reason":"target_unreachable","retry_after_ms":5000}}`,
			ServiceReasonTargetUnreachable, 5 * time.Second, ChangeUnchanged,
			"", 0, "",
		},
		{
			`{"kind":"service","message":"service shop: paused","changed":"unchanged","service":{"slug":"shop","reason":"service_changes_paused","retry_after_ms":5000}}`,
			ServiceReasonChangesPaused, 5 * time.Second, ChangeUnchanged,
			"", 0, "",
		},
		{
			`{"kind":"service","message":"service shop: sandbox limit","changed":"unchanged","service":{"slug":"shop","reason":"sandbox_service_limit_exceeded","retry_after_ms":null}}`,
			ServiceReasonSandboxLimitExceeded, 0, ChangeUnchanged,
			"", 0, "",
		},
		{
			`{"kind":"service","message":"service shop: may have been applied","changed":"unknown","service":{"slug":"shop","reason":"outcome_unknown","retry_after_ms":null}}`,
			ServiceReasonOutcomeUnknown, 0, ChangeUnknown,
			"", 0, "",
		},
		{
			`{"kind":"service","message":"service shop: reserved","changed":"unchanged","service":{"slug":"shop","reason":"other","retry_after_ms":null,"raw_code":"slug_reserved","raw_status":409,"raw_message":"slug is reserved"}}`,
			ServiceReasonOther, 0, ChangeUnchanged,
			"slug_reserved", 409, "slug is reserved",
		},
		{
			`{"kind":"service","message":"service shop: newer","service":{"slug":"shop","reason":"renamed","retry_after_ms":null}}`,
			ServiceReasonOther, 0, ChangeUnknown,
			"", 0, "",
		},
	}
	for _, c := range cases {
		var native ffi.Error
		if err := json.Unmarshal([]byte(c.payload), &native); err != nil {
			t.Fatal(err)
		}

		err := fmt.Errorf("update: %w", wrapFFI(&native))

		var serviceErr *ServiceError
		if !errors.As(err, &serviceErr) {
			t.Fatalf("missing typed service error: %v", err)
		}
		if !IsKind(err, ErrService) || serviceErr.Error() != native.Message {
			t.Fatalf("kind or message lost: %v", err)
		}
		if serviceErr.Slug != "shop" || serviceErr.Reason != c.reason ||
			serviceErr.RetryAfter != c.retryAfter || serviceErr.Changed != c.changed ||
			serviceErr.RawCode != c.code || serviceErr.RawStatus != c.status || serviceErr.RawMessage != c.message {
			t.Fatalf("details lost: %+v", serviceErr)
		}
		var base *Error
		if !errors.As(err, &base) || base.Changed != c.changed {
			t.Fatalf("base change state lost: %+v", base)
		}
	}
}

func TestRetryAfterFromMillis(t *testing.T) {
	maximum := uint64(math.MaxInt64) / uint64(time.Millisecond)
	for _, test := range []struct {
		name string
		ms   *uint64
		want time.Duration
	}{
		{"nil", nil, 0},
		{"zero", uint64Pointer(0), 0},
		{"normal", uint64Pointer(5_000), 5 * time.Second},
		{"maximum", &maximum, time.Duration(maximum) * time.Millisecond},
		{"one over", uint64Pointer(9_223_372_036_855), time.Duration(math.MaxInt64)},
		{"uint64 maximum", uint64Pointer(math.MaxUint64), time.Duration(math.MaxInt64)},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := retryAfterFromMillis(test.ms)
			if got != test.want || got < 0 {
				t.Fatalf("retry after = %v, want %v and non-negative", got, test.want)
			}
		})
	}
}

func TestWrapFFIRetryAfterSaturates(t *testing.T) {
	var native ffi.Error
	payload := `{"kind":"service","message":"try later","changed":"unchanged","service":{"slug":"shop","reason":"target_unreachable","retry_after_ms":18446744073709551615}}`
	if err := json.Unmarshal([]byte(payload), &native); err != nil {
		t.Fatal(err)
	}

	var serviceErr *ServiceError
	if err := wrapFFI(&native); !errors.As(err, &serviceErr) {
		t.Fatalf("got %v, want ServiceError", err)
	}
	if serviceErr.RetryAfter != time.Duration(math.MaxInt64) {
		t.Fatalf("retry after = %v, want MaxInt64", serviceErr.RetryAfter)
	}
}

func uint64Pointer(value uint64) *uint64 { return &value }

func TestWrapFFIMapsTopLevelChangeState(t *testing.T) {
	err := wrapFFI(&ffi.Error{Kind: ffi.KindInternal, Message: "failed", Changed: "unchanged"})
	var base *Error
	if !errors.As(err, &base) || base.Changed != ChangeUnchanged {
		t.Fatalf("change state lost: %+v", base)
	}
}

func TestServiceChangeCancelledBeforeDispatchIsUnchanged(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := CreateService(ctx, "shop", ServiceTarget{Sandbox: "web", Port: 8080})
	var base *Error
	if !errors.As(err, &base) || base.Changed != ChangeUnchanged || !errors.Is(err, context.Canceled) {
		t.Fatalf("CreateService() error = %+v, want cancelled and unchanged", err)
	}
}

func TestServiceChangeCancellationWithoutPredispatchProofIsUnknown(t *testing.T) {
	var base *Error
	if err := wrapServiceChange(context.Canceled); !errors.As(err, &base) || base.Changed != ChangeUnknown {
		t.Fatalf("wrapServiceChange() error = %+v, want unknown", err)
	}

	if err := wrapFFI(context.Canceled); !errors.As(err, &base) || base.Changed != "" {
		t.Fatalf("non-change state set: %+v", base)
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
		{ffi.KindCloudOnly, ErrCloudOnly},
		{ffi.KindModificationNotConfirmed, ErrModificationNotConfirmed},
		{ffi.KindServiceNotFound, ErrServiceNotFound},
		{ffi.KindServiceAlreadyExists, ErrServiceAlreadyExists},
		{ffi.KindService, ErrService},
		{"unrecognized_tag", ErrInternal},
	}
	for _, c := range cases {
		got := kindFromFFI(c.tag)
		if got != c.want {
			t.Errorf("kindFromFFI(%q) = %v, want %v", c.tag, got, c.want)
		}
	}
}
