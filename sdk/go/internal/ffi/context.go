package ffi

/*
#include "provider.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
int has_contexts(void);
char *call_msb_context_create(uint64_t, const char *, uint8_t *, size_t);
char *call_msb_context_operation(uint64_t, uint64_t, const char *, uint8_t *, size_t);
void call_msb_context_release(uint64_t);
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"unsafe"
)

// Context retains one native provider registration. Resources and collections
// keep this object alive; its finalizer releases only the registry's reference.
type Context struct {
	library *Library

	handle uint64
	kind   string
	info   *BackendInfo
}

func NewContext(options any) (*Context, error) { return defaultLibrary().NewContext(options) }

// DeriveRemote registers with the original provider, never the currently selected library.
func (c *Context) DeriveRemote(overrides any) (*Context, error) {
	derived, err := c.lib().NewContext(struct {
		BaseHandle uint64 `json:"baseHandle"`
		Overrides  any    `json:"overrides"`
	}{c.handle, overrides})
	runtime.KeepAlive(c)
	return derived, err
}

func (c *Context) Kind() string { return c.kind }

// Info belongs to this registration, not the currently configured default.
func (c *Context) Info() (*BackendInfo, error) {
	if c.info == nil {
		return nil, &Error{Kind: KindUnsupportedOperation, Message: "native SDK does not support retained context metadata; update the native SDK"}
	}
	return c.info, nil
}
func (c *Context) CreateSandbox(ctx context.Context, name string, options CreateOptions, connectOrCreate bool) (*Sandbox, error) {
	options.ContextHandle = c.handle
	sandbox, err := c.lib().createSandbox(ctx, name, options, connectOrCreate)
	runtime.KeepAlive(c)
	if sandbox != nil {
		sandbox.destination = c
	}
	return sandbox, err
}

func (c *Context) sandboxOperation(ctx context.Context, operation, name string, filter *SandboxListOptions) (*SandboxPage, error) {
	raw, err := json.Marshal(struct {
		Operation string              `json:"operation"`
		Name      string              `json:"name"`
		Filter    *SandboxListOptions `json:"filter,omitempty"`
	}{operation, name, filter})
	if err != nil {
		return nil, err
	}
	request := C.CString(string(raw))
	defer C.free(unsafe.Pointer(request))
	out, err := c.lib().callBufWithAbandonedResult(ctx, defaultBufSize, func(id C.uint64_t, buf *C.uint8_t, size C.size_t) *C.char {
		return C.provider_call_msb_context_operation(c.lib().table, id, C.uint64_t(c.handle), request, buf, size)
	}, c.lib().releaseResourcePage)
	runtime.KeepAlive(c)
	if err != nil {
		return nil, err
	}
	page, err := c.lib().decodeResourcePage(out)
	if err != nil {
		return nil, err
	}
	for _, sandbox := range page.Sandboxes {
		sandbox.destination = c
	}
	return page, nil
}
func (c *Context) Sandbox(ctx context.Context, operation, name string) (*Sandbox, error) {
	page, err := c.sandboxOperation(ctx, operation, name, nil)
	if err != nil {
		return nil, err
	}
	if len(page.Sandboxes) != 1 {
		for _, sandbox := range page.Sandboxes {
			sandbox.Close()
		}
		return nil, fmt.Errorf("native lookup did not return one sandbox")
	}
	return page.Sandboxes[0], nil
}
func (c *Context) ListSandboxes(ctx context.Context, options SandboxListOptions) (*SandboxPage, error) {
	return c.sandboxOperation(ctx, "sandbox_list", "", &options)
}
func (c *Context) RemoveSandbox(ctx context.Context, name string) error {
	_, err := c.sandboxOperation(ctx, "sandbox_remove", name, nil)
	return err
}
func (s *Sandbox) Context() *Context { return s.destination }

// Request handles collection operations that return values rather than registrations.
func (c *Context) Request(ctx context.Context, operation, name string, args, result any) error {
	raw, err := json.Marshal(struct {
		Operation string `json:"operation"`
		Name      string `json:"name"`
		Args      any    `json:"args,omitempty"`
	}{operation, name, args})
	if err != nil {
		return err
	}
	if err := c.lib().requireImportBudget(raw); err != nil {
		return err
	}
	request := C.CString(string(raw))
	defer C.free(unsafe.Pointer(request))
	out, err := c.lib().call(ctx, func(id C.uint64_t, buf *C.uint8_t, size C.size_t) *C.char {
		return C.provider_call_msb_context_operation(c.lib().table, id, C.uint64_t(c.handle), request, buf, size)
	})
	runtime.KeepAlive(c)
	if err != nil {
		return err
	}
	if result == nil {
		return nil
	}
	return json.Unmarshal([]byte(out), result)
}

func (receiver *Context) lib() *Library {
	if receiver.library != nil {
		return receiver.library
	}
	return defaultLibrary()
}

func (library *Library) requestContext(options any) (string, error) {
	if err := library.ensureLoaded(); err != nil {
		return "", err
	}
	if C.provider_has_contexts(library.table) == 0 {
		return "", &Error{Kind: KindUnsupportedOperation, Message: "native SDK does not support explicit contexts; update the native SDK"}
	}
	raw, err := json.Marshal(options)
	if err != nil {
		return "", err
	}
	cOptions := C.CString(string(raw))
	defer C.free(unsafe.Pointer(cOptions))
	return library.call(context.Background(), func(id C.uint64_t, buf *C.uint8_t, size C.size_t) *C.char {
		return C.provider_call_msb_context_create(library.table, id, cOptions, buf, size)
	})
}

// Ask an installed provider to read the common configuration before choosing
// a library. The probe needs no credentials and allocates no native handle.
func ConfiguredContext() (*Context, error) {
	selection.Lock()
	probe := selectedProviders["local"]
	if probe == nil {
		probe = selectedProviders["remote"]
	}
	selection.Unlock()
	library := defaultNative
	if probe != nil {
		kind, err := probe.requestContext(map[string]string{"selection": "kind"})
		if err != nil {
			return nil, err
		}
		switch kind {
		case "local":
			library = DefaultLibrary()
		case "remote":
			library = SelectedProvider(kind)
		default:
			return nil, fmt.Errorf("unknown configured provider %q", kind)
		}
	}
	return library.NewContext(map[string]string{"selection": "configured"})
}

func (library *Library) NewContext(options any) (*Context, error) {
	out, err := library.requestContext(options)
	if err != nil {
		return nil, err
	}
	var response struct {
		Handle uint64       `json:"handle"`
		Kind   string       `json:"kind"`
		Info   *BackendInfo `json:"info"`
	}
	if err := json.Unmarshal([]byte(out), &response); err != nil || response.Handle == 0 || response.Kind == "" {
		if h := salvageHandle(out); h != 0 {
			C.provider_call_msb_context_release(library.table, C.uint64_t(h))
		}
		return nil, fmt.Errorf("invalid native context registration")
	}
	destination := &Context{library: library, handle: response.Handle, kind: response.Kind, info: response.Info}
	runtime.SetFinalizer(destination, func(c *Context) { C.provider_call_msb_context_release(library.table, C.uint64_t(c.handle)) })
	return destination, nil
}

func (c *Context) RestoreSandbox(ctx context.Context, name string, options RestoreOptions) (*Sandbox, error) {
	options.ContextHandle = c.handle
	sandbox, err := c.lib().RestoreSandbox(ctx, name, options)
	runtime.KeepAlive(c)
	if sandbox != nil {
		sandbox.destination = c
	}
	return sandbox, err
}
