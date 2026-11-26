package ffi

/*
#include <stdlib.h>
#include "provider.h"
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"sync"
	"unsafe"
)

// Library owns an immutable dispatch table. Numeric handles, cancellation IDs,
// Rust allocations and destructors must always use the same Library instance.
// A successfully admitted library stays resident for the process lifetime.
type Library struct {
	table           *C.msb_library
	info            ProviderInfo
	defaultProvider bool
}

type ProviderInfo struct {
	ABI     int    `json:"abi"`
	Version string `json:"version"`
	Local   bool   `json:"local"`
	Remote  bool   `json:"remote"`
}

// Serialize only library admission, including the Windows loader's error buffer.
// Native operations never acquire this mutex and can run across providers in parallel.
var providerLoadLock sync.Mutex

var defaultNative = &Library{table: C.default_msb_library(), defaultProvider: true}

func (l *Library) ensureLoaded() error {
	if l == nil || l.table == nil {
		return &Error{Kind: KindLibraryNotLoaded, Message: "native provider is not initialized"}
	}
	if l.defaultProvider {
		if err := ensureLoaded(); err != nil {
			return err
		}
		selection.Lock()
		if pinnedDefault == nil {
			pinnedDefault = l
		}
		selection.Unlock()
		return nil
	}
	return nil
}

// LoadProvider admits a selected artifact without changing the full SDK's loader.
// The package layer supplies the expected version and verifies artifact integrity
// before calling this function. Loading a native library executes trusted code.
func LoadProvider(path, kind, version string) (*Library, error) {
	if kind != "local" && kind != "remote" && kind != "full" {
		return nil, fmt.Errorf("unknown microsandbox provider %q", kind)
	}
	providerLoadLock.Lock()
	defer providerLoadLock.Unlock()
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	var failure *C.char
	table := C.open_msb_provider(cPath, &failure)
	if table == nil {
		if failure == nil {
			return nil, fmt.Errorf("native provider load failed without an error")
		}
		defer C.free(unsafe.Pointer(failure))
		return nil, fmt.Errorf("load microsandbox %s provider: %s", kind, C.GoString(failure))
	}
	accepted := false
	defer func() {
		if !accepted {
			C.discard_msb_provider(table)
		}
	}()
	metadata := C.msb_provider_information(table)
	if metadata == nil {
		return nil, fmt.Errorf("native provider has no ABI handshake; install a matching SDK provider")
	}
	raw := C.GoString(metadata)
	C.provider_call_msb_free_string(table, metadata)
	var info ProviderInfo
	if err := json.Unmarshal([]byte(raw), &info); err != nil {
		return nil, fmt.Errorf("invalid native provider handshake: %w", err)
	}
	supported := (kind == "local" && info.Local) || (kind == "remote" && info.Remote) || (kind == "full" && info.Local && info.Remote)
	if info.ABI != 1 || info.Version != version || !supported {
		return nil, fmt.Errorf("incompatible %s provider: ABI %d, version %s; reinstall matching core and provider versions", kind, info.ABI, info.Version)
	}
	accepted = true
	return &Library{table: table, info: info}, nil
}

func (l *Library) Info() ProviderInfo { return l.info }

// Library retains the dispatch table that owns this sandbox and its derived jobs.
func (s *Sandbox) Library() *Library { return s.lib() }

// Selection only affects future constructors. Every live object keeps its Library.
var selection sync.Mutex
var selectedProviders = map[string]*Library{}
var pinnedDefault *Library

func RegisterProvider(kind string, library *Library) {
	selection.Lock()
	defer selection.Unlock()
	selectedProviders[kind] = library
}

func SelectedProvider(kind string) *Library {
	selection.Lock()
	defer selection.Unlock()
	if library := selectedProviders[kind]; library != nil {
		return library
	}
	return defaultNative
}

func defaultLibrary() *Library {
	selection.Lock()
	defer selection.Unlock()
	if pinnedDefault != nil {
		return pinnedDefault
	}
	if library := selectedProviders["local"]; library != nil {
		pinnedDefault = library
		return library
	}
	return defaultNative
}

// DefaultLibrary pins a successfully resolved local provider for package factories.
func DefaultLibrary() *Library       { return defaultLibrary() }
func (c *Context) Library() *Library { return c.lib() }
