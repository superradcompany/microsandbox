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
type SnapshotObject struct{ handle uint64 }

func NewSnapshotObject(handle uint64) *SnapshotObject {
	if handle == 0 {
		return nil
	}
	object := &SnapshotObject{handle: handle}
	runtime.SetFinalizer(object, func(object *SnapshotObject) { releaseSnapshotObject(object.handle) })
	return object
}

func (object *SnapshotObject) Call(ctx context.Context, request any) ([]byte, error) {
	result, err := SnapshotObjectCall(ctx, object.handle, request)
	runtime.KeepAlive(object)
	return result, err
}

// Spawn uses the retained source; native code pins a group's head before launch.
func (object *SnapshotObject) Spawn(ctx context.Context, name string, options RestoreOptions) (*Sandbox, error) {
	if err := CheckRestoreGuestClock(ctx, options.GuestClock); err != nil {
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
			releaseHandle(handle)
		}
		return nil, fmt.Errorf("parse checkpoint spawn: %w", err)
	}
	sandbox := &Sandbox{name: result.Name, id: result.ID, backendKind: result.BackendKind}
	sandbox.handle.Store(result.Handle)
	return sandbox, nil
}
