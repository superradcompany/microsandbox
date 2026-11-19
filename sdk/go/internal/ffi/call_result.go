package ffi

import "context"

type nativeCallResult struct {
	out string
	err error
}

// Wait for native completion even after cancellation: the caller may release
// argument memory on return. A resource published just before cancellation must
// be released here when it cannot be delivered to the caller.
func awaitNativeResult(ctx context.Context, done <-chan nativeCallResult, cancel func(), abandoned func(string)) (string, error) {
	select {
	case result := <-done:
		return result.out, result.err
	case <-ctx.Done():
		cancel()
		result := <-done
		if result.err == nil && abandoned != nil {
			abandoned(result.out)
		}
		return "", ctx.Err()
	}
}
