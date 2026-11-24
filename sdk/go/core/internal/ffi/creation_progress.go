package ffi

import (
	"bytes"
	"context"
	"errors"
)

// callSync is only for synchronous FFI functions without a cancellation-ID argument.
// They cannot unregister a token, and their successful result must not be discarded by
// racing context cancellation. The caller owns any resource identified by that result.
func callSync(fn func([]byte) error) (string, error) {
	buf := make([]byte, defaultBufSize)
	if err := fn(buf); err != nil {
		return "", err
	}
	end := bytes.IndexByte(buf, 0)
	if end < 0 {
		end = len(buf)
	}
	return string(buf[:end]), nil
}

// openCreationProgress keeps an allocated stream owned through the synchronous open
// boundary. If cancellation wins before ownership reaches the caller, close that exact
// stream ourselves; the public creator cannot defer cleanup for a handle it never received.
func openCreationProgress(
	ctx context.Context,
	open func() (uint64, error),
	close func(uint64) error,
) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	id, err := open()
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		if id != 0 {
			err = errors.Join(err, close(id))
		}
		return 0, err
	}
	return id, nil
}
