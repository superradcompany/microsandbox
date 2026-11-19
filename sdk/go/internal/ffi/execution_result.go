package ffi

/*
#include <stdlib.h>
#include "provider.h"
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"unsafe"
)

// executionResult transfers an already-completed result through an owned native
// buffer. Cancellation still waits for native return so no output slot is freed
// while Rust may write it; all allocations are freed through their own provider.
func (library *Library) executionResult(ctx context.Context, handle uint64, operation, command string, options ExecOptions) (*ExecResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}
	op, cmd, opts := C.CString(operation), C.CString(command), C.CString(string(raw))
	defer C.free(unsafe.Pointer(op))
	defer C.free(unsafe.Pointer(cmd))
	defer C.free(unsafe.Pointer(opts))
	output, length, cleanup := library.allocRustBytesOut()
	defer cleanup()
	defer library.freeRustBytes(output, length)
	err = library.callRaw(ctx, func(cancel C.uint64_t) *C.char {
		return C.provider_call_execution_result(library.table, cancel, C.uint64_t(handle), op, cmd, opts, output, length)
	})
	if err != nil {
		return nil, err
	}
	if uint64(*length) > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("execution result exceeds Go address space")
	}
	if *output == nil && *length != 0 {
		return nil, fmt.Errorf("native execution result has no data")
	}
	// Decode before releasing the allocation; Go's string copy owns the JSON bytes.
	data := unsafe.Slice((*byte)(unsafe.Pointer(*output)), int(*length))
	return decodeCollectedOutput(string(data))
}
