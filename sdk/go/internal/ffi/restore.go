package ffi

import (
	"context"
	"encoding/json"
	"errors"
)

// RestoreOptions is deliberately separate from CreateOptions: no image or
// startup command can cross the restore entry point. Optional pointers retain
// explicit zero values so the native restore path can validate the user's intent.
type RestoreOptions struct {
	PullPolicy                  string                `json:"pull_policy,omitempty"`
	Proxy                       *OutboundProxyOptions `json:"proxy,omitempty"`
	Workdir                     *string               `json:"workdir,omitempty"`
	Shell                       *string               `json:"shell,omitempty"`
	Entrypoint                  *[]string             `json:"entrypoint,omitempty"`
	Cmd                         *[]string             `json:"cmd,omitempty"`
	Env                         map[string]string     `json:"env,omitempty"`
	Init                        *InitOptions          `json:"init,omitempty"`
	Hostname                    *string               `json:"hostname,omitempty"`
	MaxCPUs                     *uint8                `json:"max_cpus,omitempty"`
	MaxMemoryMiB                *uint32               `json:"max_memory_mib,omitempty"`
	Labels                      map[string]string     `json:"labels,omitempty"`
	Snapshot                    string                `json:"snapshot"`
	SnapshotReferenceKind       string                `json:"snapshot_reference_kind,omitempty"`
	CPUs                        *uint8                `json:"cpus,omitempty"`
	MemoryMiB                   *uint32               `json:"memory_mib,omitempty"`
	NetworkPolicy               *CustomNetworkPolicy  `json:"network_policy,omitempty"`
	MaxConnections              *uint                 `json:"max_connections,omitempty"`
	MaxTCPConnections           *uint                 `json:"max_tcp_connections,omitempty"`
	MaxUDPConnections           *uint                 `json:"max_udp_connections,omitempty"`
	DisableNetwork              bool                  `json:"disable_network,omitempty"`
	GuestClock                  string                `json:"guest_clock,omitempty"`
	SecurityProfile             string                `json:"security_profile,omitempty"`
	MaxDurationSecs             *uint64               `json:"max_duration_secs,omitempty"`
	IdleTimeoutSecs             *uint64               `json:"idle_timeout_secs,omitempty"`
	CreationProgress            uint64                `json:"creation_progress,omitempty"`
	Forked                      bool                  `json:"forked,omitempty"`
	DiskOnly                    bool                  `json:"disk_only,omitempty"`
	SnapshotBase                string                `json:"snapshot_base,omitempty"`
	User                        string                `json:"user,omitempty"`
	LogLevel                    string                `json:"log_level,omitempty"`
	ExternalMountPolicy         string                `json:"external_mount_policy,omitempty"`
	DangerouslyInheritResources bool                  `json:"dangerously_inherit_resources,omitempty"`
	AllowMissingResources       bool                  `json:"allow_missing_resources,omitempty"`
	Volumes                     map[string]MountSpec  `json:"volumes,omitempty"`
	CapturedVolumes             []string              `json:"captured_volumes,omitempty"`
	Ports                       []PortBindingOptions  `json:"ports,omitempty"`
	TCPAcceptQueueSize          *uint32               `json:"tcp_accept_queue_size,omitempty"`
	MaxInboundTCPConnections    *uint                 `json:"max_inbound_tcp_connections,omitempty"`
	Vsock                       []VsockRouteOptions   `json:"vsock,omitempty"`
}

// CheckRestoreGuestClock requires acknowledgement only for explicit selection. Older native
// libraries must not silently ignore an option, including an explicit sync over a saved off.
func CheckRestoreGuestClock(ctx context.Context, policy string) error {
	if policy == "" {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := SnapshotObjectCall(ctx, 0, map[string]any{"op": "restore_guest_clock"})
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var native *Error
		if !errors.As(err, &native) || (native.Kind != KindUnsupportedOperation && native.Kind != KindInvalidArgument) {
			return err
		}
		return &Error{Kind: KindUnsupportedOperation, Message: "guest clock selection requires an updated native SDK: " + err.Error()}
	}
	var policies []string
	if err := json.Unmarshal(raw, &policies); err == nil {
		for _, supported := range policies {
			if supported == policy {
				return nil
			}
		}
	}
	return &Error{Kind: KindUnsupportedOperation, Message: "native SDK does not support requested guest clock policy " + policy}
}

// CheckRestoreBootOptions refuses explicit options an older native library cannot apply.
// Ordinary restoration makes no capability call and retains its existing wire shape.
func CheckRestoreBootOptions(ctx context.Context, options RestoreOptions) error {
	var requested []string
	if options.PullPolicy != "" {
		requested = append(requested, "pull_policy")
	}
	if options.Proxy != nil {
		requested = append(requested, "proxy")
	}
	if options.Workdir != nil {
		requested = append(requested, "workdir")
	}
	if options.Shell != nil {
		requested = append(requested, "shell")
	}
	if options.Entrypoint != nil {
		requested = append(requested, "entrypoint")
	}
	if options.Cmd != nil {
		requested = append(requested, "cmd")
	}
	if len(options.Env) > 0 {
		requested = append(requested, "env")
	}
	if options.Init != nil {
		requested = append(requested, "init")
	}
	if options.Hostname != nil {
		requested = append(requested, "hostname")
	}
	if options.MaxCPUs != nil {
		requested = append(requested, "max_cpus")
	}
	if options.MaxMemoryMiB != nil {
		requested = append(requested, "max_memory_mib")
	}
	if len(options.Labels) > 0 {
		requested = append(requested, "labels")
	}
	if len(requested) == 0 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := SnapshotObjectCall(ctx, 0, map[string]any{"op": "restore_boot_options"})
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var native *Error
		if !errors.As(err, &native) || (native.Kind != KindUnsupportedOperation && native.Kind != KindInvalidArgument) {
			return err
		}
		return &Error{Kind: KindUnsupportedOperation, Message: "requested restore options require an updated native SDK: " + err.Error()}
	}
	var supported []string
	if err := json.Unmarshal(raw, &supported); err != nil {
		return &Error{Kind: KindUnsupportedOperation, Message: "native SDK did not acknowledge restore boot options"}
	}
	for _, option := range requested {
		found := false
		for _, name := range supported {
			if name == option {
				found = true
				break
			}
		}
		if !found {
			return &Error{Kind: KindUnsupportedOperation, Message: "native SDK does not support restore option " + option}
		}
	}
	return nil
}
