package ffi

// RestoreOptions is deliberately separate from CreateOptions: no image or
// startup command can cross the restore entry point. Optional pointers retain
// explicit zero values so the native restore path can validate the user's intent.
type RestoreOptions struct {
	Snapshot                    string               `json:"snapshot"`
	SnapshotReferenceKind       string               `json:"snapshot_reference_kind,omitempty"`
	CPUs                        *uint8               `json:"cpus,omitempty"`
	MemoryMiB                   *uint32              `json:"memory_mib,omitempty"`
	NetworkPolicy               *CustomNetworkPolicy `json:"network_policy,omitempty"`
	MaxConnections              *uint                `json:"max_connections,omitempty"`
	MaxTCPConnections           *uint                `json:"max_tcp_connections,omitempty"`
	MaxUDPConnections           *uint                `json:"max_udp_connections,omitempty"`
	DisableNetwork              bool                 `json:"disable_network,omitempty"`
	SecurityProfile             string               `json:"security_profile,omitempty"`
	MaxDurationSecs             *uint64              `json:"max_duration_secs,omitempty"`
	IdleTimeoutSecs             *uint64              `json:"idle_timeout_secs,omitempty"`
	CreationProgress            uint64               `json:"creation_progress,omitempty"`
	Forked                      bool                 `json:"forked,omitempty"`
	DiskOnly                    bool                 `json:"disk_only,omitempty"`
	SnapshotBase                string               `json:"snapshot_base,omitempty"`
	User                        string               `json:"user,omitempty"`
	LogLevel                    string               `json:"log_level,omitempty"`
	ExternalMountPolicy         string               `json:"external_mount_policy,omitempty"`
	DangerouslyInheritResources bool                 `json:"dangerously_inherit_resources,omitempty"`
	AllowMissingResources       bool                 `json:"allow_missing_resources,omitempty"`
	Volumes                     map[string]MountSpec `json:"volumes,omitempty"`
	CapturedVolumes             []string             `json:"captured_volumes,omitempty"`
	Ports                       []PortBindingOptions `json:"ports,omitempty"`
	Vsock                       []VsockRouteOptions  `json:"vsock,omitempty"`
}
