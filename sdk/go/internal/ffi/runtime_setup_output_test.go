package ffi

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestRuntimeSetupRetriesOnlyReadOnlyDiagnosis(t *testing.T) {
	for _, operation := range []string{"diagnose_storage", "resolve", "install", "ensure", "recover_storage"} {
		t.Run(operation, func(t *testing.T) {
			var sizes []int
			output, err := runtimeSetupOutput(context.Background(), operation, func(size int) (string, error) {
				sizes = append(sizes, size)
				if len(sizes) == 1 {
					return "", &Error{Kind: KindBufferTooSmall, Message: fmt.Sprintf("output buffer too small: need %d, have %d", defaultBufSize+1, size)}
				}
				return "report", nil
			})
			if operation == "diagnose_storage" {
				if err != nil || output != "report" || !slices.Equal(sizes, []int{defaultBufSize, 2 * defaultBufSize}) {
					t.Fatalf("diagnosis output = %q, %v; sizes = %v", output, err, sizes)
				}
			} else {
				var native *Error
				if !errors.As(err, &native) || native.Kind != KindBufferTooSmall || output != "" || !slices.Equal(sizes, []int{defaultBufSize}) {
					t.Fatalf("%s must not retry: output = %q, %v; sizes = %v", operation, output, err, sizes)
				}
			}
		})
	}
}

func TestStorageDiagnosisRejectsOversizedOutputBeforeAllocation(t *testing.T) {
	for _, needed := range []int{storageDiagnosisMaxBufSize + 1, int(^uint(0) >> 1)} {
		calls := 0
		output, err := runtimeSetupOutput(context.Background(), "diagnose_storage", func(size int) (string, error) {
			calls++
			if size != defaultBufSize {
				t.Fatalf("allocated an oversized response: %d", size)
			}
			return "", &Error{Kind: KindBufferTooSmall, Message: fmt.Sprintf("output buffer too small: need %d, have %d", needed, size)}
		})
		var native *Error
		if !errors.As(err, &native) || native.Kind != KindBufferTooSmall || !strings.Contains(native.Message, "smaller named subsets") || output != "" || calls != 1 {
			t.Fatalf("oversized report: output = %q, err = %v, calls = %d", output, err, calls)
		}
	}
}

func TestStorageDiagnosisBoundsChangingReportRetries(t *testing.T) {
	var sizes []int
	_, err := runtimeSetupOutput(context.Background(), "diagnose_storage", func(size int) (string, error) {
		sizes = append(sizes, size)
		return "", &Error{Kind: KindBufferTooSmall, Message: fmt.Sprintf("output buffer too small: need %d, have %d", size+1, size)}
	})
	var native *Error
	if !errors.As(err, &native) || native.Kind != KindBufferTooSmall || !strings.Contains(native.Message, "smaller named subsets") {
		t.Fatalf("changing report did not stop at the cap: %v", err)
	}
	want := []int{1 << 20, 2 << 20, 4 << 20, 8 << 20, 16 << 20, 32 << 20}
	if !slices.Equal(sizes, want) {
		t.Fatalf("retry sizes = %v; want %v", sizes, want)
	}
}

func TestStorageDiagnosisAllowsOutputAtLimit(t *testing.T) {
	var sizes []int
	output, err := runtimeSetupOutput(context.Background(), "diagnose_storage", func(size int) (string, error) {
		sizes = append(sizes, size)
		if size < storageDiagnosisMaxBufSize {
			return "", &Error{Kind: KindBufferTooSmall, Message: fmt.Sprintf("output buffer too small: need %d, have %d", storageDiagnosisMaxBufSize, size)}
		}
		return "report", nil
	})
	if err != nil || output != "report" || !slices.Equal(sizes, []int{defaultBufSize, storageDiagnosisMaxBufSize}) {
		t.Fatalf("report at limit: output = %q, err = %v, sizes = %v", output, err, sizes)
	}
}

func TestStorageDiagnosisDoesNotRetryUnusableBufferErrors(t *testing.T) {
	for _, native := range []*Error{
		{Kind: KindInternal, Message: "output buffer too small: need 2097152, have 1048576"},
		{Kind: KindBufferTooSmall, Message: "different error format"},
		{Kind: KindBufferTooSmall, Message: "output buffer too small: need 1048576, have 1048576"},
		{Kind: KindBufferTooSmall, Message: "output buffer too small: need -1, have 1048576"},
		{Kind: KindBufferTooSmall, Message: "output buffer too small: need 2097152, have 1"},
		{Kind: KindBufferTooSmall, Message: "output buffer too small: need 18446744073709551616, have 1048576"},
	} {
		calls := 0
		_, err := runtimeSetupOutput(context.Background(), "diagnose_storage", func(int) (string, error) {
			calls++
			return "", native
		})
		if err != native || calls != 1 {
			t.Fatalf("unusable error was retried or replaced: %v, calls = %d", err, calls)
		}
	}
}

func TestStorageDiagnosisCancellationPreventsInitialCallAndRetry(t *testing.T) {
	for _, cancelBefore := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if cancelBefore {
			cancel()
		}
		calls := 0
		_, err := runtimeSetupOutput(ctx, "diagnose_storage", func(size int) (string, error) {
			calls++
			cancel()
			return "", &Error{Kind: KindBufferTooSmall, Message: fmt.Sprintf("output buffer too small: need %d, have %d", size+1, size)}
		})
		cancel()
		want := 1
		if cancelBefore {
			want = 0
		}
		if !errors.Is(err, context.Canceled) || calls != want {
			t.Fatalf("cancel before = %v: err = %v, calls = %d", cancelBefore, err, calls)
		}
	}
}
