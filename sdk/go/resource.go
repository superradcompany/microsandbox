package microsandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// SandboxInfo is a single live backend observation. It may change after lookup.
type SandboxInfo struct {
	ID                 string
	Name               string
	Status             SandboxStatus
	LastFailureMessage *string
	CreatedAt          *time.Time
	UpdatedAt          *time.Time
}

// EnsureRunning prepares this receiver, retaining any newly started local run.
// It never creates a missing resource or switches to a same-name replacement.
func (s *Sandbox) EnsureRunning(ctx context.Context) error {
	return wrapFFI(s.inner.EnsureRunning(ctx))
}

// Info fetches related mutable fields in one lookup without starting the sandbox.
func (s *Sandbox) Info(ctx context.Context) (*SandboxInfo, error) {
	observed, err := s.inner.Info(ctx)
	if err != nil {
		return nil, wrapFFI(err)
	}
	info := &SandboxInfo{ID: observed.ID, Name: observed.Name, Status: SandboxStatus(observed.Status), LastFailureMessage: observed.LastFailureMessage}
	info.CreatedAt = observed.CreatedAt
	info.UpdatedAt = observed.UpdatedAt
	return info, nil
}

// Status fetches current lifecycle status; it does not prepare the runtime.
func (s *Sandbox) Status(ctx context.Context) (SandboxStatus, error) {
	info, err := s.Info(ctx)
	if err != nil {
		return "", err
	}
	return info.Status, nil
}

// LastFailureMessage fetches the latest provider-reported failure, when available.
func (s *Sandbox) LastFailureMessage(ctx context.Context) (*string, error) {
	info, err := s.Info(ctx)
	if err != nil {
		return nil, err
	}
	return info.LastFailureMessage, nil
}

// Config fetches latest persisted settings, which may still require restart to apply.
func (s *Sandbox) Config(ctx context.Context) (*SandboxConfigInspection, error) {
	raw, err := s.inner.ConfigJSON(ctx)
	if err != nil {
		return nil, wrapFFI(err)
	}
	var config SandboxConfigInspection
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		return nil, err
	}
	if config.Kind != "local" && config.Kind != "remote" {
		return nil, fmt.Errorf("native library returned an unsupported configuration inspection shape; rebuild or upgrade the native provider")
	}
	return &config, nil
}

// ConfigJSON fetches the latest persisted configuration without starting a runtime.
func (s *Sandbox) ConfigJSON(ctx context.Context) (string, error) {
	value, err := s.inner.ConfigJSON(ctx)
	return value, wrapFFI(err)
}
