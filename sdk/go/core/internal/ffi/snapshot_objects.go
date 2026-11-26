package ffi

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
)

// SnapshotObject retains a Rust group or checkpoint and its selected backend.
// Sharing this Go pointer shares ownership; garbage collection only releases the
// receiver, never the durable group/member. KeepAlive covers blocking native calls.
type SnapshotObject struct {
	scoped      bool
	destination *Context
	checkpoint  *PersistentResource
	handle      uint64
	library     *Library
}

func NewSnapshotObject(handle uint64) *SnapshotObject {
	return defaultLibrary().NewSnapshotObject(handle)
}

func (library *Library) NewSnapshotObject(handle uint64) *SnapshotObject {
	if handle == 0 {
		return nil
	}
	object := &SnapshotObject{handle: handle, library: library}
	runtime.SetFinalizer(object, func(object *SnapshotObject) { object.library.releaseSnapshotObject(object.handle) })
	return object
}

// The root carries the provider even before it owns a native history registration.
func (c *Context) SnapshotRoot() *SnapshotObject {
	return &SnapshotObject{library: c.lib(), destination: c, scoped: true}
}

func (s *Sandbox) SnapshotRoot() *SnapshotObject {
	return &SnapshotObject{library: s.lib(), destination: s.destination, scoped: true}
}

func (r *PersistentResource) SnapshotReceiver() *SnapshotObject {
	if r == nil {
		return nil
	}
	return &SnapshotObject{library: r.lib(), destination: r.destination, scoped: true, checkpoint: r}
}

func (o *SnapshotObject) Library() *Library {
	if o == nil {
		return defaultLibrary()
	}
	return o.library
}

func (o *SnapshotObject) Child(handle uint64) *SnapshotObject {
	child := o.library.NewSnapshotObject(handle)
	if child != nil {
		child.scoped, child.destination = o.scoped, o.destination
	}
	return child
}

func (o *SnapshotObject) Resource(observation json.RawMessage) (*PersistentResource, error) {
	var row struct {
		Handle uint64 `json:"handle"`
	}
	if err := json.Unmarshal(observation, &row); err != nil {
		return nil, err
	}
	if row.Handle == 0 {
		return nil, fmt.Errorf("checkpoint registration has no handle")
	}
	return o.library.newPersistentResource(o.destination, row.Handle, observation), nil
}

func (object *SnapshotObject) Call(ctx context.Context, request any) ([]byte, error) {
	if object.scoped {
		if err := object.library.requireContextSnapshotObjects(); err != nil {
			return nil, err
		}
		envelope := map[string]any{"op": "with_context", "request": request}
		if object.destination != nil {
			envelope["context"] = object.destination.handle
		}
		if object.checkpoint != nil {
			envelope["checkpoint"] = object.checkpoint.handle
		}
		request = envelope
	}
	result, err := object.library.SnapshotObjectCall(ctx, object.handle, request)
	runtime.KeepAlive(object)
	return result, err
}

// Spawn uses the retained source; native code pins a group's head before launch.
func (object *SnapshotObject) Spawn(ctx context.Context, name string, options RestoreOptions) (*Sandbox, error) {
	if err := object.library.CheckRestoreBootOptions(ctx, options); err != nil {
		return nil, err
	}
	if err := object.library.CheckRestoreGuestClock(ctx, options.GuestClock); err != nil {
		return nil, err
	}
	raw, err := object.Call(ctx, map[string]any{"op": "spawn", "name": name, "options": options})
	if err != nil {
		return nil, err
	}
	var result struct {
		Handle      uint64 `json:"handle"`
		Name        string `json:"name"`
		ID          string `json:"id"`
		BackendKind string `json:"backend_kind"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		if handle := salvageHandle(string(raw)); handle != 0 {
			object.library.releaseHandle(handle)
		}
		return nil, fmt.Errorf("parse checkpoint spawn: %w", err)
	}
	sandbox := &Sandbox{library: object.library, destination: object.destination, name: result.Name, id: result.ID, backendKind: result.BackendKind}
	sandbox.handle.Store(result.Handle)
	return sandbox, nil
}
