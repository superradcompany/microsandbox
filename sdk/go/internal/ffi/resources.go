package ffi

/*
#include "provider.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
int has_sandbox_resources(void);
int has_sandbox_resource_wait(void);
char *call_msb_sandbox_resource_wait_for_status(uint64_t, uint64_t, const char *, uint8_t *, size_t);
char *call_msb_sandbox_resource_list(uint64_t, const char *, uint8_t *, size_t);
char *call_msb_sandbox_resource_operation(uint64_t, uint64_t, const char *, uint8_t *, size_t);
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
	"unsafe"
)

// ResourceInfo is one live observation, not mutable state cached on a resource.
type ResourceInfo struct {
	ID                 string     `json:"id"`
	Name               string     `json:"name"`
	Status             string     `json:"status"`
	LastFailureMessage *string    `json:"last_failure_message"`
	CreatedAt          *time.Time `json:"created_at"`
	UpdatedAt          *time.Time `json:"updated_at"`
}

type resourceRegistration struct {
	Handle      uint64 `json:"handle"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	BackendKind string `json:"backend_kind"`
}

type resourcePage struct {
	Sandboxes  []resourceRegistration `json:"sandboxes"`
	NextCursor *string                `json:"next_cursor"`
}

func requireSandboxResources() error { return defaultLibrary().requireSandboxResources() }

// resourceOperation dispatches against the registered receiver, preserving its destination.
func (s *Sandbox) resourceOperation(ctx context.Context, operation string) (string, error) {
	if err := s.lib().requireSandboxResources(); err != nil {
		return "", err
	}
	cOperation := C.CString(operation)
	defer C.free(unsafe.Pointer(cOperation))
	return s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_resource_operation(s.lib().table, cancelID, s.h(), cOperation, buf, bufLen)
	})
}

// WaitForStatus retains the native receiver throughout the cancellable wait.
func (s *Sandbox) WaitForStatus(ctx context.Context, status string) error {
	if err := s.lib().ensureLoaded(); err != nil {
		return err
	}
	if C.provider_has_sandbox_resource_wait(s.lib().table) == 0 {
		return &Error{Kind: KindUnsupportedOperation, Message: "native SDK does not support receiver-bound status waiting; update the native SDK"}
	}
	cStatus := C.CString(status)
	defer C.free(unsafe.Pointer(cStatus))
	_, err := s.lib().call(ctx, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_resource_wait_for_status(s.lib().table, cancelID, s.h(), cStatus, buf, bufLen)
	})
	return err
}

func (s *Sandbox) EnsureRunning(ctx context.Context) error {
	_, err := s.resourceOperation(ctx, "ensure_running")
	return err
}

func (s *Sandbox) Info(ctx context.Context) (*ResourceInfo, error) {
	out, err := s.resourceOperation(ctx, "info")
	if err != nil {
		return nil, err
	}
	var info ResourceInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		return nil, fmt.Errorf("parse sandbox observation: %w", err)
	}
	return &info, nil
}

func (s *Sandbox) ConfigJSON(ctx context.Context) (string, error) {
	return s.resourceOperation(ctx, "config")
}

// A late successful page still owns every native registration. Release all of it
// when cancellation or a decode error prevents transferring it to the caller.
func releaseResourcePage(out string) { defaultLibrary().releaseResourcePage(out) }

func ListSandboxes(ctx context.Context, options SandboxListOptions) (*SandboxPage, error) {
	return defaultLibrary().ListSandboxes(ctx, options)
}

func decodeResourcePage(out string) (*SandboxPage, error) {
	return defaultLibrary().decodeResourcePage(out)
}

// Lifecycle uses the retained receiver, including for stopped resources.
func (s *Sandbox) Lifecycle(ctx context.Context, operation string, options SandboxHandleLifecycleOptions) (*Sandbox, error) {
	request, err := json.Marshal(struct {
		Operation string                        `json:"operation"`
		Options   SandboxHandleLifecycleOptions `json:"options"`
	}{operation, options})
	if err != nil {
		return nil, err
	}
	if err := s.lib().requireSandboxResources(); err != nil {
		return nil, err
	}
	cRequest := C.CString(string(request))
	defer C.free(unsafe.Pointer(cRequest))
	out, err := s.lib().callBufWithAbandonedResult(ctx, defaultBufSize, func(id C.uint64_t, buf *C.uint8_t, size C.size_t) *C.char {
		return C.provider_call_msb_sandbox_resource_operation(s.lib().table, id, s.h(), cRequest, buf, size)
	}, func(raw string) {
		if h := salvageHandle(raw); h != 0 {
			s.lib().releaseHandle(h)
		}
	})
	if err != nil {
		return nil, err
	}
	if operation != "restart" {
		return nil, nil
	}
	var result resourceRegistration
	if err := json.Unmarshal([]byte(out), &result); err != nil || result.Handle == 0 {
		if h := salvageHandle(out); h != 0 {
			s.lib().releaseHandle(h)
		}
		return nil, fmt.Errorf("invalid restart registration")
	}
	restarted := &Sandbox{library: s.lib(), name: result.Name, id: result.ID, backendKind: result.BackendKind, destination: s.destination}
	restarted.handle.Store(result.Handle)
	return restarted, nil
}

func (library *Library) requireSandboxResources() error {
	if err := library.ensureLoaded(); err != nil {
		return err
	}
	if C.provider_has_sandbox_resources(library.table) == 0 {
		return &Error{Kind: KindUnsupportedOperation, Message: "native SDK does not support unified sandbox resources; update the native SDK"}
	}
	return nil
}

func (library *Library) releaseResourcePage(out string) {
	var page resourcePage
	_ = json.Unmarshal([]byte(out), &page)
	for _, resource := range page.Sandboxes {
		if resource.Handle != 0 {
			library.releaseHandle(resource.Handle)
		}
	}
}

func (library *Library) decodeResourcePage(out string) (*SandboxPage, error) {
	var page resourcePage
	if err := json.Unmarshal([]byte(out), &page); err != nil {
		library.releaseResourcePage(out)
		return nil, fmt.Errorf("parse sandbox resource page: %w", err)
	}
	for _, resource := range page.Sandboxes {
		if resource.Handle == 0 || resource.ID == "" || resource.Name == "" {
			library.releaseResourcePage(out)
			return nil, fmt.Errorf("invalid sandbox resource registration")
		}
	}
	resources := make([]*Sandbox, len(page.Sandboxes))
	for i, resource := range page.Sandboxes {
		sandbox := &Sandbox{library: library, name: resource.Name, id: resource.ID, backendKind: resource.BackendKind}
		sandbox.handle.Store(resource.Handle)
		resources[i] = sandbox
	}
	return &SandboxPage{Sandboxes: resources, NextCursor: page.NextCursor}, nil
}

func (library *Library) ListSandboxes(ctx context.Context, options SandboxListOptions) (*SandboxPage, error) {
	if err := library.requireSandboxResources(); err != nil {
		return nil, err
	}
	filter, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}
	cFilter := C.CString(string(filter))
	defer C.free(unsafe.Pointer(cFilter))
	out, err := library.callBufWithAbandonedResult(ctx, defaultBufSize, func(cancelID C.uint64_t, buf *C.uint8_t, bufLen C.size_t) *C.char {
		return C.provider_call_msb_sandbox_resource_list(library.table, cancelID, cFilter, buf, bufLen)
	}, library.releaseResourcePage)
	if err != nil {
		return nil, err
	}
	return library.decodeResourcePage(out)
}
