package microsandbox

import (
	"os"
	"strings"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// ComputeType selects the machine type for newly created remote sandboxes.
type ComputeType string

const (
	ComputeStandard ComputeType = "standard"
	ComputeShared   ComputeType = "shared"
)

// RemoteContextOption selects one setting for a new or derived remote context.
type RemoteContextOption func(*remoteContextOverrides)

type remoteContextOverrides struct {
	ComputeType      *ComputeType `json:"computeType,omitempty"`
	URL              *string      `json:"url,omitempty"`
	APIKey           *string      `json:"apiKey,omitempty"`
	RequestTimeoutMS *uint64      `json:"requestTimeoutMs,omitempty"`
	UserAgent        *string      `json:"userAgent,omitempty"`
	err              error
}

// WithRemoteComputeType selects the machine type for new sandboxes.
// Existing sandboxes keep their original type.
func WithRemoteComputeType(computeType ComputeType) RemoteContextOption {
	return func(o *remoteContextOverrides) { o.ComputeType = &computeType }
}

// WithRemoteURL selects the derived context's endpoint. An empty URL is invalid.
func WithRemoteURL(url string) RemoteContextOption {
	return func(o *remoteContextOverrides) { o.URL = &url }
}

// WithRemoteAPIKey selects the derived context's credentials. An empty key is invalid.
func WithRemoteAPIKey(apiKey string) RemoteContextOption {
	return func(o *remoteContextOverrides) { o.APIKey = &apiKey }
}

// WithRemoteRequestTimeout sets a non-negative timeout, rounded down to milliseconds.
func WithRemoteRequestTimeout(timeout time.Duration) RemoteContextOption {
	return func(o *remoteContextOverrides) {
		if timeout < 0 {
			o.err = &Error{Kind: ErrInvalidConfig, Message: "remote request timeout must be non-negative"}
			return
		}
		ms := uint64(timeout.Milliseconds())
		o.RequestTimeoutMS = &ms
	}
}

// WithRemoteUserAgent sets the derived context's HTTP User-Agent.
func WithRemoteUserAgent(agent string) RemoteContextOption {
	return func(o *remoteContextOverrides) { o.UserAgent = &agent }
}

// WithOptions derives an independent context through the retained native provider.
// This context and its existing resources keep their original destination and credentials.
// The method captures configuration only; it performs no remote lookup.
func (c *RemoteContext) WithOptions(options ...RemoteContextOption) (*RemoteContext, error) {
	inner, err := nativeDestination(c)
	if err != nil {
		return nil, err
	}
	overrides, err := remoteOptions(options)
	if err != nil {
		return nil, err
	}
	derived, err := inner.DeriveRemote(overrides)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &RemoteContext{inner: derived}, nil
}

func remoteOptions(options []RemoteContextOption) (remoteContextOverrides, error) {
	overrides := remoteContextOverrides{}
	for _, option := range options {
		if option == nil {
			return overrides, &Error{Kind: ErrInvalidConfig, Message: "remote context option must not be nil"}
		}
		option(&overrides)
	}
	if overrides.err != nil {
		return overrides, overrides.err
	}
	return overrides, nil
}

// NewRemoteContextWithOptions captures explicit settings and environment defaults.
func NewRemoteContextWithOptions(options ...RemoteContextOption) (*RemoteContext, error) {
	return buildRemoteContext(ffi.SelectedProvider("remote"), options)
}

func buildRemoteContext(library *ffi.Library, options []RemoteContextOption) (*RemoteContext, error) {
	overrides, err := remoteOptions(options)
	if err != nil {
		return nil, err
	}
	if overrides.APIKey == nil {
		key := os.Getenv("MSB_API_KEY")
		overrides.APIKey = &key
	}
	if overrides.URL == nil {
		if url := strings.TrimSpace(os.Getenv("MSB_API_URL")); url != "" {
			overrides.URL = &url
		}
	}
	inner, err := library.NewContext(struct {
		Kind string `json:"kind"`
		remoteContextOverrides
	}{"remote", overrides})
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &RemoteContext{inner: inner}, nil
}
