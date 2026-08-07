package microsandbox

import (
	"fmt"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// BackendKind identifies where sandbox operations execute.
type BackendKind string

const (
	// BackendLocal runs microVMs on the calling host.
	BackendLocal BackendKind = "local"
	// BackendCloud routes operations to the microsandbox cloud API.
	BackendCloud BackendKind = "cloud"
	// BackendUnknown means the loaded compatibility bundle predates backend introspection.
	BackendUnknown BackendKind = "unknown"
)

// BackendInfo is a secret-safe description of the active SDK backend.
// It intentionally never contains the API key.
type BackendInfo struct {
	Kind    BackendKind `json:"kind"`
	APIURL  string      `json:"api_url,omitempty"`
	Source  string      `json:"source"`
	Profile string      `json:"profile,omitempty"`
}

// DefaultBackendInfo returns the backend selected and cached by the native SDK.
func DefaultBackendInfo() (BackendInfo, error) {
	info, err := ffi.DefaultBackendInfo()
	if err != nil {
		return BackendInfo{}, wrapFFI(err)
	}
	if info == nil {
		return BackendInfo{}, fmt.Errorf(
			"microsandbox: backend info unavailable in the loaded native bundle; update the SDK runtime",
		)
	}
	return BackendInfo{
		Kind:    BackendKind(info.Kind),
		APIURL:  stringValue(info.APIURL),
		Source:  info.Source,
		Profile: stringValue(info.Profile),
	}, nil
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
