package microsandbox

import (
	"reflect"
	"testing"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

func TestLogOptionsToFFI(t *testing.T) {
	since := time.Unix(10, int64(123*time.Millisecond))
	until := time.Unix(20, int64(456*time.Millisecond))

	got := logOptionsToFFI(LogOptions{
		Tail:    50,
		Since:   since,
		Until:   until,
		Sources: []LogSource{LogSourceStdout, LogSourceSystem},
	})

	if got.Tail != 50 {
		t.Errorf("Tail = %d, want 50", got.Tail)
	}
	if got.SinceMs == nil || *got.SinceMs != since.UnixMilli() {
		t.Errorf("SinceMs = %v, want %d", got.SinceMs, since.UnixMilli())
	}
	if got.UntilMs == nil || *got.UntilMs != until.UnixMilli() {
		t.Errorf("UntilMs = %v, want %d", got.UntilMs, until.UnixMilli())
	}
	if want := []string{"stdout", "system"}; !reflect.DeepEqual(got.Sources, want) {
		t.Errorf("Sources = %v, want %v", got.Sources, want)
	}
}

func TestLogEntriesFromFFI(t *testing.T) {
	sessionID := uint64(7)
	entries, err := logEntriesFromFFI([]ffi.LogEntry{{
		Source:      "stdout",
		SessionID:   &sessionID,
		TimestampMs: 1234,
		DataB64:     "aGVsbG8K",
		Cursor:      "AQECAwQ=",
	}})
	if err != nil {
		t.Fatalf("logEntriesFromFFI: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}
	if entries[0].Source != LogSourceStdout {
		t.Errorf("Source = %q, want %q", entries[0].Source, LogSourceStdout)
	}
	if entries[0].SessionID == nil || *entries[0].SessionID != sessionID {
		t.Errorf("SessionID = %v, want %d", entries[0].SessionID, sessionID)
	}
	if entries[0].Timestamp.UnixMilli() != 1234 {
		t.Errorf("Timestamp = %d, want 1234", entries[0].Timestamp.UnixMilli())
	}
	if entries[0].Text() != "hello\n" {
		t.Errorf("Text = %q, want %q", entries[0].Text(), "hello\n")
	}
	if entries[0].Cursor != "AQECAwQ=" {
		t.Errorf("Cursor = %q, want %q", entries[0].Cursor, "AQECAwQ=")
	}
}

func TestLogStreamOptionsToFFI(t *testing.T) {
	since := time.Unix(30, int64(789*time.Millisecond))
	until := time.Unix(40, int64(0))

	got := logStreamOptionsToFFI(LogStreamOptions{
		Sources: []LogSource{LogSourceStdout, LogSourceSystem},
		Since:   since,
		Until:   until,
		Follow:  true,
	})

	if got.SinceMs == nil || *got.SinceMs != since.UnixMilli() {
		t.Errorf("SinceMs = %v, want %d", got.SinceMs, since.UnixMilli())
	}
	if got.UntilMs == nil || *got.UntilMs != until.UnixMilli() {
		t.Errorf("UntilMs = %v, want %d", got.UntilMs, until.UnixMilli())
	}
	if got.FromCursor != nil {
		t.Errorf("FromCursor = %v, want nil", got.FromCursor)
	}
	if !got.Follow {
		t.Errorf("Follow = false, want true")
	}
	if want := []string{"stdout", "system"}; !reflect.DeepEqual(got.Sources, want) {
		t.Errorf("Sources = %v, want %v", got.Sources, want)
	}
}

func TestLogStreamOptionsToFFI_FromCursor(t *testing.T) {
	got := logStreamOptionsToFFI(LogStreamOptions{
		FromCursor: "AQECAwQ=",
	})
	if got.FromCursor == nil || *got.FromCursor != "AQECAwQ=" {
		t.Errorf("FromCursor = %v, want %q", got.FromCursor, "AQECAwQ=")
	}
	if got.SinceMs != nil {
		t.Errorf("SinceMs = %v, want nil", got.SinceMs)
	}
}
