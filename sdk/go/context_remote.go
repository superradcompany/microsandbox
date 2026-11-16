package microsandbox

import "time"

// RemoteContextOption overrides one captured setting when deriving a remote context.
// Omitted options preserve their values; no profile or environment is resolved again.
type RemoteContextOption func(*remoteContextOverrides)

type remoteContextOverrides struct {
	URL              *string `json:"url,omitempty"`
	APIKey           *string `json:"apiKey,omitempty"`
	RequestTimeoutMS *uint64 `json:"requestTimeoutMs,omitempty"`
	UserAgent        *string `json:"userAgent,omitempty"`
	err              error
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
	overrides := remoteContextOverrides{}
	for _, option := range options {
		if option == nil {
			return nil, &Error{Kind: ErrInvalidConfig, Message: "remote context option must not be nil"}
		}
		option(&overrides)
	}
	if overrides.err != nil {
		return nil, overrides.err
	}
	derived, err := inner.DeriveRemote(overrides)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return &RemoteContext{inner: derived}, nil
}
