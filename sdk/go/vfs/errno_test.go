package vfs

import (
	"fmt"
	"os"
	"testing"
)

func TestErrnoOfUnwrapsWrappedErrno(t *testing.T) {
	// A provider that wraps its errno with fmt.Errorf("...: %w", ...) — the
	// idiomatic Go pattern — must still map to the underlying Linux errno, not
	// collapse to EIO.
	wrapped := fmt.Errorf("open /x: %w", Err(ENOENT))
	if got := errnoOf(wrapped); got != ENOENT {
		t.Fatalf("errnoOf(wrapped) = %d, want ENOENT(%d)", got, ENOENT)
	}
	if got := errnoOf(Err(EACCES)); got != EACCES {
		t.Fatalf("errnoOf(direct) = %d, want EACCES(%d)", got, EACCES)
	}
	if got := errnoOf(fmt.Errorf("opaque failure")); got != EIO {
		t.Fatalf("errnoOf(plain) = %d, want EIO(%d)", got, EIO)
	}
	if got := errnoOf(os.ErrNotExist); got != ENOENT {
		t.Fatalf("errnoOf(os.ErrNotExist) = %d, want ENOENT(%d)", got, ENOENT)
	}
	if got := errnoOf(nil); got != 0 {
		t.Fatalf("errnoOf(nil) = %d, want 0", got)
	}
}

func TestNodeKindByteRejectsOutOfRange(t *testing.T) {
	// The Go decoder must reject the same out-of-range node kinds the Rust
	// scaffold rejects, so the two sides agree on which messages are valid.
	if _, err := nodeKindByte(uint64(Socket)); err != nil {
		t.Fatalf("kind=Socket(%d) should be valid: %v", Socket, err)
	}
	if _, err := nodeKindByte(uint64(Socket) + 1); err == nil {
		t.Fatalf("kind=%d (beyond Socket) should be rejected", uint64(Socket)+1)
	}
}
