package ffi

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCallSyncReturnsOutputAndErrors(t *testing.T) {
	out, err := callSync(func(buf []byte) error {
		copy(buf, "{\"handle\":42}\x00ignored")
		return nil
	})
	if err != nil || out != `{"handle":42}` {
		t.Fatalf("callSync = %q, %v", out, err)
	}
	want := errors.New("native open failed")
	out, err = callSync(func(buf []byte) error {
		copy(buf, "partial output")
		return want
	})
	if !errors.Is(err, want) || out != "" {
		t.Fatalf("failed callSync = %q, %v", out, err)
	}
}

func TestOpenCreationProgressPreCancelledDoesNotAllocate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	id, err := openCreationProgress(ctx, func() (uint64, error) {
		t.Fatal("cancelled open must not allocate a stream")
		return 42, nil
	}, func(uint64) error {
		t.Fatal("nothing was allocated to close")
		return nil
	})
	if id != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("open = %d, %v", id, err)
	}
}

func TestOpenCreationProgressCancellationClosesOnlyAllocatedStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	release := make(chan struct{})
	type result struct {
		id  uint64
		err error
	}
	done := make(chan result, 1)
	streams := map[uint64]bool{7: true}
	var closed []uint64
	go func() {
		id, err := openCreationProgress(ctx, func() (uint64, error) {
			streams[42] = true
			close(started)
			// Reproduce cancellation after native allocation but before its result returns.
			<-release
			return 42, nil
		}, func(id uint64) error {
			closed = append(closed, id)
			delete(streams, id)
			return nil
		})
		done <- result{id, err}
	}()
	<-started
	cancel()
	close(release)
	select {
	case got := <-done:
		if got.id != 0 || !errors.Is(got.err, context.Canceled) {
			t.Fatalf("cancelled open = %d, %v", got.id, got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("synchronous open did not finish after release")
	}
	if len(closed) != 1 || closed[0] != 42 || len(streams) != 1 || !streams[7] {
		t.Fatalf("cleanup changed the wrong ownership: closed=%v streams=%v", closed, streams)
	}
}

func TestOpenCreationProgressSuccessTransfersOwnership(t *testing.T) {
	streams := map[uint64]bool{}
	closeStream := func(id uint64) error {
		delete(streams, id)
		return nil
	}
	for next := uint64(1); next <= 20; next++ {
		id, err := openCreationProgress(context.Background(), func() (uint64, error) {
			streams[next] = true
			return next, nil
		}, closeStream)
		if err != nil || id != next || !streams[id] {
			t.Fatalf("successful open lost ownership: id=%d err=%v streams=%v", id, err, streams)
		}
		if err := closeStream(id); err != nil {
			t.Fatal(err)
		}
	}
	if len(streams) != 0 {
		t.Fatalf("open/close leaked streams: %v", streams)
	}
}

func TestOpenCreationProgressPreservesCancellationAndCleanupFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cleanup := errors.New("stream cleanup failed")
	id, err := openCreationProgress(ctx, func() (uint64, error) {
		cancel()
		return 42, nil
	}, func(id uint64) error {
		if id != 42 {
			t.Fatalf("closed stream %d instead of 42", id)
		}
		return cleanup
	})
	if id != 0 || !errors.Is(err, context.Canceled) || !errors.Is(err, cleanup) {
		t.Fatalf("cancelled open lost its failure details: id=%d err=%v", id, err)
	}
}

func TestOpenCreationProgressDecodeFailureCleansKnownHandle(t *testing.T) {
	want := errors.New("malformed native reply")
	var closed uint64
	id, err := openCreationProgress(context.Background(), func() (uint64, error) {
		return 42, want
	}, func(id uint64) error {
		closed = id
		return nil
	})
	if id != 0 || !errors.Is(err, want) || closed != 42 {
		t.Fatalf("failed open = %d, %v; closed=%d", id, err, closed)
	}
}
