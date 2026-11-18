package microsandbox

import "encoding/json"

// SandboxConfigInspection is a fresh persisted observation, not creation input
// or a guarantee that the running VM has applied these settings. Paths in
// Unavailable and Redacted use the wire's snake_case field names.
type SandboxConfigInspection struct {
	Kind        string                `json:"kind"`
	Name        string                `json:"name"`
	Spec        SandboxInspectionSpec `json:"spec"`
	Unavailable []string              `json:"unavailable"`
	Redacted    []string              `json:"redacted"`
}

// SandboxInspectionSpec preserves backend-specific source and network views.
// Image is a local tagged source, a remote OCI string, or JSON null for an
// unavailable remote non-OCI source. It must not be reused as creation input.
type SandboxInspectionSpec struct {
	Name              string                    `json:"name,omitempty"`
	Image             json.RawMessage           `json:"image"`
	Resources         SandboxResourceInspection `json:"resources"`
	Runtime           SandboxRuntimeInspection  `json:"runtime"`
	Env               []SandboxInspectionEnv    `json:"env"`
	Labels            map[string]string         `json:"labels"`
	Rlimits           []map[string]any          `json:"rlimits"`
	Lifecycle         map[string]any            `json:"lifecycle"`
	Mounts            []map[string]any          `json:"mounts"`
	Network           map[string]any            `json:"network"`
	Init              json.RawMessage           `json:"init,omitempty"`
	Patches           []map[string]any          `json:"patches,omitempty"`
	SecurityProfile   *string                   `json:"security_profile,omitempty"`
	Vsock             map[string]any            `json:"vsock,omitempty"`
	DeploymentProfile *string                   `json:"deployment_profile,omitempty"`
	PullPolicy        *PullPolicy               `json:"pull_policy,omitempty"`
}

// SandboxResourceInspection distinguishes local cpus from remote vcpus and
// uses pointers so unavailable capacity is not presented as a zero allocation.
type SandboxResourceInspection struct {
	CPUPlacement     *string `json:"cpu_placement,omitempty"`
	PlacementProfile *string `json:"placement_profile,omitempty"`
	THP              *string `json:"thp,omitempty"`
	NestedVirt       *bool   `json:"nested_virt,omitempty"`
	CPUs             *uint8  `json:"cpus,omitempty"`
	VCPUs            *uint8  `json:"vcpus,omitempty"`
	MemoryMiB        uint32  `json:"memory_mib"`
	DiskSizeMiB      *uint32 `json:"disk_size_mib,omitempty"`
	MaxCPUs          *uint8  `json:"max_cpus,omitempty"`
	MaxMemoryMiB     *uint32 `json:"max_memory_mib,omitempty"`
}

// SandboxRuntimeInspection contains execution settings observed at the backend.
// Nil pointers/slices represent unset values, not invented SDK defaults.
type SandboxRuntimeInspection struct {
	Workdir                 *string           `json:"workdir"`
	Shell                   *string           `json:"shell"`
	Scripts                 map[string]string `json:"scripts"`
	Entrypoint              []string          `json:"entrypoint"`
	Cmd                     []string          `json:"cmd"`
	Hostname                *string           `json:"hostname"`
	User                    *string           `json:"user"`
	LogLevel                *LogLevel         `json:"log_level"`
	MetricsSampleIntervalMs *uint64           `json:"metrics_sample_interval_ms"`
	DisableMetricsSample    bool              `json:"disable_metrics_sample"`
	GuestClock              *string           `json:"guest_clock,omitempty"`
}

// SandboxInspectionEnv is a persisted guest environment entry.
type SandboxInspectionEnv struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
