package ffi

/*
#include "provider.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
int has_persistent_resources(void);
char *call_msb_context_operation(uint64_t, uint64_t, const char *, uint8_t *, size_t);
char *call_msb_resource_operation(uint64_t, uint64_t, const char *, uint8_t *, size_t);
void call_msb_resource_release(uint64_t);
char *call_msb_sandbox_resource_operation(uint64_t, uint64_t, const char *, uint8_t *, size_t);
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

// PersistentResource owns only its native registration; finalization cannot delete storage.
// No request context is retained, and each operation borrows the native Arc before awaiting.
type PersistentResource struct {
	library *Library

	handle      uint64
	destination *Context
	Observation json.RawMessage
}

func (r *PersistentResource) Context() *Context { return r.destination }
func releasePersistentPage(raw string)          { defaultLibrary().releasePersistentPage(raw) }
func (c *Context) Resources(ctx context.Context, operation, name string, args any) ([]*PersistentResource, error) {
	if C.provider_has_persistent_resources(c.lib().table) == 0 {
		return nil, &Error{Kind: KindUnsupportedOperation, Message: "native SDK does not support retained persistent resources; update the native SDK"}
	}
	raw, err := json.Marshal(struct {
		Operation string `json:"operation"`
		Name      string `json:"name"`
		Args      any    `json:"args,omitempty"`
	}{operation, name, args})
	if err != nil {
		return nil, err
	}
	if err := c.lib().requireImportBudget(raw); err != nil {
		return nil, err
	}
	request := C.CString(string(raw))
	defer C.free(unsafe.Pointer(request))
	out, err := c.lib().callBufWithAbandonedResult(ctx, defaultBufSize, func(id C.uint64_t, buf *C.uint8_t, size C.size_t) *C.char {
		return C.provider_call_msb_context_operation(c.lib().table, id, C.uint64_t(c.handle), request, buf, size)
	}, c.lib().releasePersistentPage)
	runtime.KeepAlive(c)
	if err != nil {
		return nil, err
	}
	return c.lib().persistentResourcesFromJSON(c, out)
}

func persistentResourcesFromJSON(c *Context, out string) ([]*PersistentResource, error) {
	return defaultLibrary().persistentResourcesFromJSON(c, out)
}
func (r *PersistentResource) Operation(ctx context.Context, operation string, args, result any) error {
	raw, err := json.Marshal(struct {
		Operation string `json:"operation"`
		Args      any    `json:"args,omitempty"`
	}{operation, args})
	if err != nil {
		return err
	}
	request := C.CString(string(raw))
	defer C.free(unsafe.Pointer(request))
	invoke := func(id C.uint64_t, buf *C.uint8_t, size C.size_t) *C.char {
		return C.provider_call_msb_resource_operation(r.lib().table, id, C.uint64_t(r.handle), request, buf, size)
	}
	out, err := readResourceResult(ctx, operation, func(size int) (string, error) {
		return r.lib().callBuf(ctx, size, invoke)
	})
	runtime.KeepAlive(r)
	if err != nil {
		return err
	}
	if result == nil {
		return nil
	}
	return json.Unmarshal([]byte(out), result)
}

func (s *Sandbox) Snapshot(ctx context.Context, name string) (*PersistentResource, error) {
	if err := s.lib().requireSandboxResources(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(map[string]any{"operation": "snapshot", "options": map[string]any{}, "name": name})
	if err != nil {
		return nil, err
	}
	request := C.CString(string(raw))
	defer C.free(unsafe.Pointer(request))
	out, err := s.lib().callBufWithAbandonedResult(ctx, defaultBufSize, func(id C.uint64_t, buf *C.uint8_t, size C.size_t) *C.char {
		return C.provider_call_msb_sandbox_resource_operation(s.lib().table, id, s.h(), request, buf, size)
	}, s.lib().releasePersistentPage)
	if err != nil {
		return nil, err
	}
	resources, err := s.lib().persistentResourcesFromJSON(s.destination, out)
	if err != nil {
		return nil, err
	}
	if len(resources) != 1 {
		return nil, fmt.Errorf("snapshot capture did not return one resource")
	}
	return resources[0], nil
}

func (receiver *PersistentResource) lib() *Library {
	if receiver.library != nil {
		return receiver.library
	}
	if receiver.destination != nil {
		return receiver.destination.lib()
	}
	return defaultLibrary()
}

func (library *Library) releasePersistentPage(raw string) {
	var page struct {
		Resources []struct {
			Handle uint64 `json:"handle"`
		} `json:"resources"`
	}
	_ = json.Unmarshal([]byte(raw), &page)
	for _, resource := range page.Resources {
		if resource.Handle != 0 {
			C.provider_call_msb_resource_release(library.table, C.uint64_t(resource.Handle))
		}
	}
}

func (library *Library) newPersistentResource(c *Context, handle uint64, observation json.RawMessage) *PersistentResource {
	resource := &PersistentResource{library: library, handle: handle, destination: c, Observation: observation}
	runtime.SetFinalizer(resource, func(r *PersistentResource) { C.provider_call_msb_resource_release(library.table, C.uint64_t(r.handle)) })
	return resource
}

func (library *Library) persistentResourcesFromJSON(c *Context, out string) ([]*PersistentResource, error) {
	var page struct {
		Resources []json.RawMessage `json:"resources"`
	}
	if err := json.Unmarshal([]byte(out), &page); err != nil {
		library.releasePersistentPage(out)
		return nil, err
	}
	handles := make([]uint64, len(page.Resources))
	for i, entry := range page.Resources {
		var registration struct {
			Handle uint64 `json:"handle"`
		}
		if err := json.Unmarshal(entry, &registration); err != nil || registration.Handle == 0 {
			library.releasePersistentPage(out)
			return nil, fmt.Errorf("invalid persistent resource registration")
		}
		handles[i] = registration.Handle
	}
	resources := make([]*PersistentResource, len(handles))
	for i, handle := range handles {
		resources[i] = library.newPersistentResource(c, handle, page.Resources[i])
	}
	return resources, nil
}

// Only filesystem reads can be retried with a larger buffer. Never replay writes,
// destruction, or creation after a native operation has already taken effect.
func readResourceResult(ctx context.Context, operation string, invoke func(int) (string, error)) (string, error) {
	size := defaultBufSize
	for {
		out, err := invoke(size)
		var native *Error
		if operation != "fs_read" || !errors.As(err, &native) || native.Kind != KindBufferTooSmall {
			return out, err
		}
		var needed, available int
		if _, parseErr := fmt.Sscanf(native.Message, "output buffer too small: need %d, have %d", &needed, &available); parseErr != nil || needed <= size || available != size {
			return out, err
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		size = needed
	}
}
