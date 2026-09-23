package microsandbox

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// RuntimeConfig overrides persisted configuration for a single setup operation.
// Empty fields retain the configured paths or resolved runtime home.
type RuntimeConfig struct {
	Home          string `json:"home,omitempty"`
	MSBPath       string `json:"msb_path,omitempty"`
	LibkrunfwPath string `json:"libkrunfw_path,omitempty"`
}

// RuntimeOrigin identifies the source of a resolved pair.
type RuntimeOrigin string

const (
	RuntimeOriginEnvironment   RuntimeOrigin = "environment"
	RuntimeOriginSDKPackage    RuntimeOrigin = "sdk_package"
	RuntimeOriginConfiguration RuntimeOrigin = "configuration"
	RuntimeOriginHome          RuntimeOrigin = "home"
	RuntimeOriginInstalled     RuntimeOrigin = "installed"
)

// ResolvedRuntime contains the selected executable and matching firmware library.
type ResolvedRuntime struct {
	MSBPath       string        `json:"msb_path"`
	LibkrunfwPath string        `json:"libkrunfw_path"`
	Origin        RuntimeOrigin `json:"origin"`
}

// InstallSource selects an explicit acquisition source.
type InstallSource string

const (
	InstallSourceReleaseDownload InstallSource = "release_download"
	InstallSourceArchive         InstallSource = "archive"
	InstallSourceDirectory       InstallSource = "directory"
	InstallSourceEmbeddedArchive InstallSource = "embedded_archive"
)

// InstallOptions configures installation. The zero value downloads the SDK's
// pinned runtime and verifies it. Verify may be set to a pointer to false for
// provisioning environments that cannot run host verification.
type InstallOptions struct {
	Source                InstallSource `json:"source,omitempty"`
	SourcePath            string        `json:"source_path,omitempty"`
	Version               string        `json:"version,omitempty"`
	Force                 bool          `json:"force,omitempty"`
	Verify                *bool         `json:"verify,omitempty"`
	ExpectedArchiveSHA256 string        `json:"expected_archive_sha256,omitempty"`
}

// ResolveRuntime finds an existing pair without installing host runtime binaries.
// As with other Go SDK operations, first use may materialize the embedded SDK FFI library.
func ResolveRuntime(config RuntimeConfig) (ResolvedRuntime, error) {
	return runtimeSetup(context.Background(), "resolve", config, InstallOptions{})
}

// IsRuntimeInstalled reports whether a complete pair resolves for config.
func IsRuntimeInstalled(config RuntimeConfig) bool {
	_, err := ResolveRuntime(config)
	return err == nil
}

// InstallRuntime installs the selected source and returns the installed pair.
func InstallRuntime(ctx context.Context, config RuntimeConfig, options InstallOptions) (ResolvedRuntime, error) {
	return runtimeSetup(ctx, "install", config, options)
}

// EnsureRuntime resolves first and installs only when the runtime is wholly
// absent. It propagates partial-installation and explicit-path errors.
func EnsureRuntime(ctx context.Context, config RuntimeConfig, options InstallOptions) (ResolvedRuntime, error) {
	return runtimeSetup(ctx, "ensure", config, options)
}

func runtimeSetup(ctx context.Context, operation string, config RuntimeConfig, options InstallOptions) (ResolvedRuntime, error) {
	var result ResolvedRuntime
	configJSON, err := json.Marshal(config)
	if err != nil {
		return result, fmt.Errorf("runtime config: %w", err)
	}
	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return result, fmt.Errorf("install options: %w", err)
	}
	output, err := ffi.RuntimeSetup(ctx, operation, string(configJSON), string(optionsJSON))
	if err != nil {
		return result, wrapFFI(err)
	}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return result, fmt.Errorf("decode resolved runtime: %w", err)
	}
	return result, nil
}
