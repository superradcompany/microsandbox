package microsandbox

import (
	"context"
	"math"
	"testing"
	"time"
)

func TestStopDeadlineIsExplicit(t *testing.T) {
	if got := stopTimeoutMillis(nil); got != nil {
		t.Fatalf("ordinary Stop has a hidden deadline: %d", *got)
	}
	for _, test := range []struct {
		name string
		wait time.Duration
		want uint64
	}{
		{"zero", 0, 0},
		{"negative", -time.Second, 0},
		{"submillisecond", time.Nanosecond, 1},
		{"explicit", 30 * time.Second, 30_000},
		{"maximum", time.Duration(math.MaxInt64), 9_223_372_036_855},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := stopTimeoutMillis([]StopOption{WithStopTimeout(test.wait)})
			if got == nil || *got != test.want {
				t.Fatalf("explicit deadline = %v, want %d", got, test.want)
			}
		})
	}
	got := stopTimeoutMillis([]StopOption{WithStopTimeout(time.Second), WithStopTimeout(0)})
	if got == nil || *got != 0 {
		t.Fatal("last explicit zero deadline was lost")
	}
}

func TestStopDeadlineDoesNotChangeKillDefault(t *testing.T) {
	if got := killTimeoutMillis(nil); got != 5_000 {
		t.Fatalf("Kill default = %d, want 5000", got)
	}
}

// Both public receiver types expose the same explicit bounded method while
// preserving the existing variadic Stop API.
var _ interface {
	Stop(context.Context, ...StopOption) error
	StopWithTimeout(context.Context, time.Duration) error
	RequestStop(context.Context) error
} = (*Sandbox)(nil)

var _ interface {
	Stop(context.Context, ...StopOption) error
	StopWithTimeout(context.Context, time.Duration) error
	RequestStop(context.Context) error
} = (*SandboxHandle)(nil)
