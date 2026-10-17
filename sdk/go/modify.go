package microsandbox

// Sandbox modification.
//
// Modify funnels through the Rust core's canonical patch/plan contract: the
// options below serialize into a SandboxModificationPatch, the core plans or
// applies it, and the returned plan JSON decodes into SandboxModificationPlan.

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// ModificationPolicy selects how a modification is planned or applied.
type ModificationPolicy string

const (
	// ModificationPolicyNoRestart applies only changes that can complete
	// without restarting the running sandbox. This is the default.
	ModificationPolicyNoRestart ModificationPolicy = "no_restart"

	// ModificationPolicyNextStart persists the desired config for the next
	// start and leaves any running VM unchanged.
	ModificationPolicyNextStart ModificationPolicy = "next_start"

	// ModificationPolicyRestart persists the patch and restarts the sandbox
	// if restart-required changes are present.
	ModificationPolicyRestart ModificationPolicy = "restart"
)

// ModifyOptions describes a requested sandbox modification. Zero-valued
// fields are left unchanged (0 is not a valid CPU, memory, or disk size).
type ModifyOptions struct {
	// CPUs sets the desired effective vCPU count.
	CPUs uint8

	// MaxCPUs sets the desired boot-time maximum possible vCPU count.
	MaxCPUs uint8

	// MemoryMiB sets the desired effective guest memory in MiB.
	MemoryMiB uint32

	// MaxMemoryMiB sets the desired boot-time maximum hotpluggable memory in MiB.
	MaxMemoryMiB uint32

	// RootDiskSizeMiB sets the desired root disk size in MiB. Managed and flat
	// disks are grow-only.
	RootDiskSizeMiB uint32

	// Env sets environment variables for future execs.
	Env map[string]string

	// EnvRemove removes environment variable keys.
	EnvRemove []string

	// Labels sets sandbox labels.
	Labels map[string]string

	// LabelsRemove removes label keys.
	LabelsRemove []string

	// Workdir sets the working directory for future execs.
	Workdir string

	// Secrets sets desired secret specs, keyed by secret name. The core
	// planner diffs each spec against the existing config to infer what
	// changes; omitting a name never means removal (see SecretsRemove).
	Secrets map[string]SecretModifySpec

	// SecretsRemove removes secrets by name.
	SecretsRemove []string

	// Mounts adds mounts, keyed by guest path. A mount at a guest path that
	// already has one replaces it. Named volumes must already exist, and
	// owned mounts cannot be added. Mount changes take effect on the next
	// start.
	Mounts map[string]MountConfig

	// MountsRemove removes mounts by guest path. Takes effect on the next
	// start.
	MountsRemove []string

	// Ports adds or updates mappings without changing other host endpoints.
	Ports []PortBinding

	// PortsRemove removes published host endpoints.
	PortsRemove []PortEndpoint

	// Policy selects the apply policy. Defaults to ModificationPolicyNoRestart.
	Policy ModificationPolicy

	// DryRun computes the plan without applying anything.
	DryRun bool
}

// PortEndpoint identifies a published host listener. Bind defaults to loopback;
// Protocol defaults to TCP.
type PortEndpoint struct {
	Bind     string
	HostPort uint16
	Protocol PortProtocol
}

// SecretModifySpec describes the desired state for one secret in a
// modification. Env, Value, and Store are mutually exclusive ways to provide
// the secret material; setting more than one is rejected before the request
// crosses into the core.
type SecretModifySpec struct {
	// Env resolves the value from a host environment variable at apply time.
	Env string

	// Value supplies the raw secret material directly, for callers that hold
	// only a value (e.g. from their own vault).
	Value string

	// Store resolves the value from a host-side secret store reference.
	Store string

	// Placeholder sets the guest-visible placeholder/reference explicitly.
	Placeholder string

	// AllowedHosts sets the desired allowed host patterns. Empty leaves an
	// existing secret's hosts unchanged; a new secret needs at least one.
	AllowedHosts []string
}

// SandboxModificationPlan is the dry-run or apply plan returned by Modify.
type SandboxModificationPlan struct {
	// Sandbox being modified.
	Sandbox string `json:"sandbox"`

	// Status used for classification ("running", "stopped", ...).
	Status string `json:"status"`

	// Applied reports whether the changes were applied.
	Applied bool `json:"applied"`

	// Policy used to produce the plan.
	Policy ModificationPolicy `json:"policy"`

	// Changes planned by the core.
	Changes []PlannedChange `json:"changes"`

	// Conflicts that must be resolved before the patch can apply.
	Conflicts []ModificationConflict `json:"conflicts"`

	// Warnings about the patch or current runtime capabilities.
	Warnings []ModificationWarning `json:"warnings"`

	// ResizeStatus reports live resource resize outcomes after apply.
	ResizeStatus []ResourceResizeStatus `json:"resize_status,omitempty"`
}

// PlannedChange is one planned modification entry. Kind is "config" or
// "secret"; secret entries carry Name/BeforeRef/AfterRef/AllowHosts while
// config entries carry Before/After.
type PlannedChange struct {
	Kind        string   `json:"kind"`
	Field       string   `json:"field"`
	Name        string   `json:"name,omitempty"`
	Change      string   `json:"change"`
	Before      *string  `json:"before,omitempty"`
	After       *string  `json:"after,omitempty"`
	BeforeRef   *string  `json:"before_ref,omitempty"`
	AfterRef    *string  `json:"after_ref,omitempty"`
	Disposition string   `json:"disposition"`
	AllowHosts  []string `json:"allow_hosts,omitempty"`
	Reason      *string  `json:"reason,omitempty"`
}

// ModificationConflict blocks applying a modification.
type ModificationConflict struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ModificationWarning is a non-fatal warning emitted while planning.
type ModificationWarning struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ResourceResizeStatus reports runtime convergence for a live resize.
type ResourceResizeStatus struct {
	Resource  string `json:"resource"`
	Requested string `json:"requested"`
	Actual    string `json:"actual"`
	Enforced  string `json:"enforced"`
	State     string `json:"state"`
}

// Modify plans or applies a sandbox modification on this live sandbox.
// With DryRun the plan is computed without applying anything.
func (s *Sandbox) Modify(ctx context.Context, opts ModifyOptions) (*SandboxModificationPlan, error) {
	if err := checkModifyMounts(opts); err != nil {
		return nil, err
	}
	if len(opts.Ports) > 0 || len(opts.PortsRemove) > 0 {
		if err := ffi.RequirePortModification(); err != nil {
			return nil, err
		}
	}
	payload, err := buildModifyRequestJSON(opts)
	if err != nil {
		return nil, err
	}
	out, err := s.inner.Modify(ctx, payload)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return parseModificationPlan(out)
}

// Modify plans or applies a sandbox modification by name. It does not start
// stopped sandboxes; next-start changes persist for the next boot.
func (h *SandboxHandle) Modify(ctx context.Context, opts ModifyOptions) (*SandboxModificationPlan, error) {
	if err := checkModifyMounts(opts); err != nil {
		return nil, err
	}
	if len(opts.Ports) > 0 || len(opts.PortsRemove) > 0 {
		if err := ffi.RequirePortModification(); err != nil {
			return nil, err
		}
	}
	payload, err := buildModifyRequestJSON(opts)
	if err != nil {
		return nil, err
	}
	out, err := ffi.ModifySandboxByName(ctx, h.name, payload)
	if err != nil {
		return nil, wrapFFI(err)
	}
	return parseModificationPlan(out)
}

// modifyEnvVar mirrors the core EnvVar serde shape.
type modifyEnvVar struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// modifyPort carries a mapping or a host endpoint in the core wire format.
type modifyPort struct {
	HostBind  string       `json:"host_bind"`
	HostPort  uint16       `json:"host_port"`
	GuestPort uint16       `json:"guest_port,omitempty"`
	Protocol  PortProtocol `json:"protocol"`
}

// modifyPatch mirrors the core SandboxModificationPatch serde shape.
type modifyPatch struct {
	Ports           []modifyPort   `json:"ports,omitempty"`
	PortsRemove     []modifyPort   `json:"ports_remove,omitempty"`
	CPUs            *uint8         `json:"cpus,omitempty"`
	MaxCPUs         *uint8         `json:"max_cpus,omitempty"`
	MemoryMiB       *uint32        `json:"memory_mib,omitempty"`
	MaxMemoryMiB    *uint32        `json:"max_memory_mib,omitempty"`
	RootDiskSizeMiB *uint32        `json:"root_disk_size_mib,omitempty"`
	Env             []modifyEnvVar `json:"env,omitempty"`
	EnvRemove       []string       `json:"env_remove,omitempty"`
	Labels          [][2]string    `json:"labels,omitempty"`
	LabelsRemove    []string       `json:"labels_remove,omitempty"`
	Workdir         *string        `json:"workdir,omitempty"`
	Secrets         []modifySecret `json:"secrets,omitempty"`
	SecretsRemove   []string       `json:"secrets_remove,omitempty"`
	Mounts          []modifyMount  `json:"mounts,omitempty"`
	MountsRemove    []string       `json:"mounts_remove,omitempty"`
}

// modifyMount mirrors the core VolumeMount serde shape, tagged on "type"
// ("Bind", "Named", "Tmpfs", or "DiskImage"), not the flat create-time spec.
type modifyMount struct {
	Type               string             `json:"type"`
	Host               string             `json:"host,omitempty"`
	Name               string             `json:"name,omitempty"`
	Guest              string             `json:"guest"`
	Format             string             `json:"format,omitempty"`
	Fstype             string             `json:"fstype,omitempty"`
	SizeMiB            uint32             `json:"size_mib,omitempty"`
	QuotaMiB           uint32             `json:"quota_mib,omitempty"`
	StatVirtualization string             `json:"stat_virtualization,omitempty"`
	HostPermissions    string             `json:"host_permissions,omitempty"`
	Options            modifyMountOptions `json:"options"`
}

// modifyMountOptions mirrors the core MountOptions serde shape.
type modifyMountOptions struct {
	Readonly    bool    `json:"readonly"`
	Noexec      bool    `json:"noexec"`
	Nosuid      bool    `json:"nosuid"`
	Nodev       bool    `json:"nodev"`
	OverrideUID *uint32 `json:"override_uid,omitempty"`
	OverrideGID *uint32 `json:"override_gid,omitempty"`
}

// modifySecret mirrors the core SecretModificationPatch serde shape. Value is
// the only field that may carry raw secret material; it is omitted when empty
// and must never be echoed into errors or debug output.
type modifySecret struct {
	Name         string              `json:"name"`
	Source       *modifySecretSource `json:"source,omitempty"`
	Value        string              `json:"value,omitempty"`
	Placeholder  *string             `json:"placeholder,omitempty"`
	AllowedHosts []string            `json:"allowed_hosts,omitempty"`
}

// modifySecretSource mirrors the core SecretSource serde shape (internally
// tagged on "kind": {"kind":"env","var":...} or {"kind":"store","reference":...}).
type modifySecretSource struct {
	Kind      string `json:"kind"`
	Var       string `json:"var,omitempty"`
	Reference string `json:"reference,omitempty"`
}

type modifyRequest struct {
	Patch  modifyPatch `json:"patch"`
	Policy string      `json:"policy,omitempty"`
	DryRun bool        `json:"dry_run,omitempty"`
}

// buildModifyRequestJSON serializes ModifyOptions into the FFI wire shape.
// Map entries are emitted in sorted key order so identical options always
// produce identical requests (and plan ordering).
func buildModifyRequestJSON(opts ModifyOptions) (string, error) {
	patch := modifyPatch{
		EnvRemove:     opts.EnvRemove,
		LabelsRemove:  opts.LabelsRemove,
		SecretsRemove: opts.SecretsRemove,
	}
	for _, port := range opts.Ports {
		patch.Ports = append(patch.Ports, portForModify(port.Bind, port.HostPort, port.GuestPort, port.Protocol))
	}
	for _, port := range opts.PortsRemove {
		patch.PortsRemove = append(patch.PortsRemove, portForModify(port.Bind, port.HostPort, 0, port.Protocol))
	}
	if opts.CPUs > 0 {
		patch.CPUs = &opts.CPUs
	}
	if opts.MaxCPUs > 0 {
		patch.MaxCPUs = &opts.MaxCPUs
	}
	if opts.MemoryMiB > 0 {
		patch.MemoryMiB = &opts.MemoryMiB
	}
	if opts.MaxMemoryMiB > 0 {
		patch.MaxMemoryMiB = &opts.MaxMemoryMiB
	}
	if opts.RootDiskSizeMiB > 0 {
		patch.RootDiskSizeMiB = &opts.RootDiskSizeMiB
	}
	for _, key := range sortedKeys(opts.Env) {
		patch.Env = append(patch.Env, modifyEnvVar{Key: key, Value: opts.Env[key]})
	}
	for _, key := range sortedKeys(opts.Labels) {
		patch.Labels = append(patch.Labels, [2]string{key, opts.Labels[key]})
	}
	if opts.Workdir != "" {
		patch.Workdir = &opts.Workdir
	}
	for _, name := range sortedKeys(opts.Secrets) {
		entry, err := buildModifySecret(name, opts.Secrets[name])
		if err != nil {
			return "", err
		}
		patch.Secrets = append(patch.Secrets, entry)
	}
	patch.MountsRemove = opts.MountsRemove
	for _, guest := range sortedKeys(opts.Mounts) {
		entry, err := buildModifyMount(guest, opts.Mounts[guest])
		if err != nil {
			return "", err
		}
		patch.Mounts = append(patch.Mounts, entry)
	}

	raw, err := json.Marshal(modifyRequest{
		Patch:  patch,
		Policy: string(opts.Policy),
		DryRun: opts.DryRun,
	})
	if err != nil {
		return "", fmt.Errorf("marshal modify request: %w", err)
	}
	return string(raw), nil
}

// buildModifySecret converts one SecretModifySpec into the wire shape,
// rejecting specs that set more than one of Env/Value/Store. Error messages
// name only the offending fields, never the secret material itself.
func buildModifySecret(name string, spec SecretModifySpec) (modifySecret, error) {
	set := make([]string, 0, 3)
	if spec.Env != "" {
		set = append(set, "Env")
	}
	if spec.Value != "" {
		set = append(set, "Value")
	}
	if spec.Store != "" {
		set = append(set, "Store")
	}
	if len(set) > 1 {
		return modifySecret{}, fmt.Errorf(
			"secret %q: %s are mutually exclusive; set at most one",
			name, strings.Join(set, " and "),
		)
	}

	entry := modifySecret{Name: name, Value: spec.Value, AllowedHosts: spec.AllowedHosts}
	switch {
	case spec.Env != "":
		entry.Source = &modifySecretSource{Kind: "env", Var: spec.Env}
	case spec.Store != "":
		entry.Source = &modifySecretSource{Kind: "store", Reference: spec.Store}
	}
	if spec.Placeholder != "" {
		placeholder := spec.Placeholder
		entry.Placeholder = &placeholder
	}
	return entry, nil
}

// buildModifyMount converts one MountConfig into the core VolumeMount shape.
// Modify never provisions volumes, so a named mount that carries creation
// settings is refused rather than silently losing them.
func buildModifyMount(guest string, mount MountConfig) (modifyMount, error) {
	entry := modifyMount{
		Guest: guest,
		Options: modifyMountOptions{
			Readonly: mount.Readonly,
			Noexec:   mount.Noexec,
			Nosuid:   mount.Nosuid,
			Nodev:    mount.Nodev,
		},
	}
	if mount.Owner != nil {
		uid, gid := mount.Owner.UID, mount.Owner.GID
		entry.Options.OverrideUID, entry.Options.OverrideGID = &uid, &gid
	}
	if bad := inapplicableMountOptions(mount); len(bad) > 0 {
		return modifyMount{}, fmt.Errorf("mount %q: %s not valid for this kind of mount", guest, strings.Join(bad, ", "))
	}
	if configuresNamedVolume(mount) {
		return modifyMount{}, fmt.Errorf("mount %q: modify does not create or configure named volumes; create the volume first", guest)
	}
	switch mount.Kind() {
	case MountKindBind:
		entry.Type, entry.Host, entry.QuotaMiB = "Bind", mount.Bind, mount.QuotaMiB
		entry.StatVirtualization = string(mount.StatVirtualization)
		entry.HostPermissions = string(mount.HostPermissions)
	case MountKindNamed:
		entry.Type, entry.Name = "Named", mount.Named
		entry.StatVirtualization = string(mount.StatVirtualization)
		entry.HostPermissions = string(mount.HostPermissions)
	case MountKindTmpfs:
		entry.Type, entry.SizeMiB = "Tmpfs", mount.SizeMiB
	case MountKindDisk:
		entry.Type, entry.Host, entry.Fstype = "DiskImage", mount.Disk, mount.Fstype
		format, err := diskImageFormat(mount.Format, mount.Disk)
		if err != nil {
			return modifyMount{}, fmt.Errorf("mount %q: %w", guest, err)
		}
		entry.Format = format
	default:
		return modifyMount{}, fmt.Errorf("mount %q: modify supports bind, named, tmpfs, and disk mounts", guest)
	}
	return entry, nil
}

// configuresNamedVolume reports whether a named mount asks for more than an
// existing volume: a create mode, disk storage, a size, or a quota.
func configuresNamedVolume(mount MountConfig) bool {
	if mount.Kind() != MountKindNamed {
		return false
	}
	return mount.NamedMode == "create" || mount.NamedKind == "disk" || mount.SizeMiB != 0 || mount.QuotaMiB != 0
}

// inapplicableMountOptions lists options unsupported by the mount kind.
// Named-volume provisioning settings (NamedMode, NamedKind, SizeMiB,
// QuotaMiB) are checked by configuresNamedVolume instead.
func inapplicableMountOptions(mount MountConfig) []string {
	kind := mount.Kind()
	virtiofs := kind == MountKindBind || kind == MountKindNamed
	var bad []string
	add := func(set bool, name string) {
		if set {
			bad = append(bad, name)
		}
	}
	add(mount.QuotaMiB != 0 && !virtiofs, "QuotaMiB")
	add(mount.SizeMiB != 0 && kind != MountKindTmpfs && kind != MountKindNamed, "SizeMiB")
	add((mount.NamedMode != "" || mount.NamedKind != "") && kind != MountKindNamed, "NamedMode/NamedKind")
	add(mount.Format != "" && kind != MountKindDisk, "Format")
	add(mount.Fstype != "" && kind != MountKindDisk, "Fstype")
	add(mount.StatVirtualization != "" && !virtiofs, "StatVirtualization")
	add(mount.HostPermissions != "" && !virtiofs, "HostPermissions")
	add(mount.Owner != nil && !virtiofs, "Owner")
	return bad
}

// diskImageFormat returns the core format name. With no explicit format it is
// inferred from the file extension as the core builder does: case-sensitive,
// ".qcow2" and ".vmdk" only, anything else (including a bare dotfile such as
// ".qcow2") raw. An explicit format must be raw, qcow2, or vmdk.
func diskImageFormat(format, host string) (string, error) {
	if format == "" {
		format = "raw"
		if base := filepath.Base(host); filepath.Ext(base) != base {
			switch ext := filepath.Ext(base); ext {
			case ".qcow2", ".vmdk":
				format = strings.TrimPrefix(ext, ".")
			}
		}
	}
	switch format {
	case "raw":
		return "Raw", nil
	case "qcow2":
		return "Qcow2", nil
	case "vmdk":
		return "Vmdk", nil
	default:
		return "", fmt.Errorf("unknown disk image format: %s", format)
	}
}

// modifyMountsSupported probes the loaded native library; tests replace it to
// simulate an older library.
var modifyMountsSupported = ffi.ModifyMountsSupported

// checkModifyMounts rejects mount changes when the loaded native library
// predates them, since it would silently drop the unknown patch fields.
func checkModifyMounts(opts ModifyOptions) error {
	if len(opts.Mounts) == 0 && len(opts.MountsRemove) == 0 {
		return nil
	}
	supported, err := modifyMountsSupported()
	if err != nil {
		return wrapFFI(err)
	}
	if !supported {
		return wrapFFI(&ffi.Error{
			Kind:    ffi.KindUnsupportedOperation,
			Message: "native SDK does not support modifying mounts; update the native SDK",
		})
	}
	return nil
}

func parseModificationPlan(raw string) (*SandboxModificationPlan, error) {
	var plan SandboxModificationPlan
	if err := json.Unmarshal([]byte(raw), &plan); err != nil {
		return nil, fmt.Errorf("parse modification plan: %w", err)
	}
	return &plan, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func portForModify(bind string, host, guest uint16, protocol PortProtocol) modifyPort {
	if bind == "" {
		bind = "127.0.0.1"
	}
	if protocol == "" {
		protocol = PortProtocolTCP
	}
	return modifyPort{HostBind: bind, HostPort: host, GuestPort: guest, Protocol: protocol}
}
