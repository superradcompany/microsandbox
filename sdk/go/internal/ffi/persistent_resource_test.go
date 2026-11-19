package ffi

import (
	"context"
	"fmt"
	"testing"
)

func TestResourceResultOnlyRetriesReads(t *testing.T) {
	for _, operation := range []string{"fs_read", "fs_write", "destroy", "info"} {
		t.Run(operation, func(t *testing.T) {
			calls := 0
			out, err := readResourceResult(context.Background(), operation, func(size int) (string, error) {
				calls++
				if calls == 1 {
					return "", &Error{Kind: KindBufferTooSmall, Message: fmt.Sprintf("output buffer too small: need %d, have %d", defaultBufSize*3, size)}
				}
				if size != defaultBufSize*3 {
					t.Fatalf("buffer size: %d", size)
				}
				return "result", nil
			})
			if operation == "fs_read" {
				if calls != 2 || err != nil || out != "result" {
					t.Fatalf("read: %d, %q, %v", calls, out, err)
				}
			} else if calls != 1 || err == nil {
				t.Fatalf("operation replayed: %d, %v", calls, err)
			}
		})
	}
}

func TestResourceReadCancellationPreventsRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	_, err := readResourceResult(ctx, "fs_read", func(size int) (string, error) {
		calls++
		cancel()
		return "", &Error{Kind: KindBufferTooSmall, Message: fmt.Sprintf("output buffer too small: need %d, have %d", size+1, size)}
	})
	if calls != 1 || err != context.Canceled {
		t.Fatalf("cancellation: %d, %v", calls, err)
	}
}
