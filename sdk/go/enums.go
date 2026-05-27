package microsandbox

// This file defines typed string enums that mirror the Node.js and Python
// SDKs. They are deliberately string-backed so Go callers can pass a raw
// literal ("running") or the typed constant (SandboxStatusRunning) in the
// same field. The FFI boundary carries plain strings.

// SandboxStatus reports the lifecycle state of a sandbox.
type SandboxStatus string

const (
	SandboxStatusRunning  SandboxStatus = "running"
	SandboxStatusStopped  SandboxStatus = "stopped"
	SandboxStatusCrashed  SandboxStatus = "crashed"
	SandboxStatusDraining SandboxStatus = "draining"
	SandboxStatusPaused   SandboxStatus = "paused"
)

// FsEntryKind classifies a directory listing entry.
type FsEntryKind string

const (
	FsEntryKindFile      FsEntryKind = "file"
	FsEntryKindDirectory FsEntryKind = "directory"
	FsEntryKindSymlink   FsEntryKind = "symlink"
	FsEntryKindOther     FsEntryKind = "other"
)

// PolicyAction is the action half of a PolicyRule.
type PolicyAction string

const (
	PolicyActionAllow PolicyAction = "allow"
	PolicyActionDeny  PolicyAction = "deny"
)

// PolicyDirection is the direction half of a PolicyRule. The Go SDK follows
// the Python naming ("egress"/"ingress"); Node uses "outbound"/"inbound" as
// an alias but the wire format carries the Python values.
type PolicyDirection string

const (
	PolicyDirectionEgress  PolicyDirection = "egress"
	PolicyDirectionIngress PolicyDirection = "ingress"
	PolicyDirectionAny     PolicyDirection = "any"
)

// PolicyProtocol is the protocol half of a PolicyRule.
type PolicyProtocol string

const (
	PolicyProtocolTCP    PolicyProtocol = "tcp"
	PolicyProtocolUDP    PolicyProtocol = "udp"
	PolicyProtocolICMPv4 PolicyProtocol = "icmpv4"
	PolicyProtocolICMPv6 PolicyProtocol = "icmpv6"
)

// NetworkPolicyPreset is the preset name accepted by NetworkConfig.Policy.
// Prefer the NetworkPolicy factory (NetworkPolicy.None / PublicOnly / AllowAll
// / NonLocal) which returns a preconfigured *NetworkConfig.
type NetworkPolicyPreset string

const (
	NetworkPolicyPresetNone       NetworkPolicyPreset = "none"
	NetworkPolicyPresetPublicOnly NetworkPolicyPreset = "public-only"
	NetworkPolicyPresetAllowAll   NetworkPolicyPreset = "allow-all"
	NetworkPolicyPresetNonLocal   NetworkPolicyPreset = "non-local"
)

// PatchKind is the discriminator for PatchConfig.Kind. Prefer the Patch
// factory (Patch.Text, Patch.Mkdir, ...) which returns a preconfigured
// PatchConfig.
type PatchKind string

const (
	PatchKindText     PatchKind = "text"
	PatchKindAppend   PatchKind = "append"
	PatchKindMkdir    PatchKind = "mkdir"
	PatchKindRemove   PatchKind = "remove"
	PatchKindSymlink  PatchKind = "symlink"
	PatchKindCopyFile PatchKind = "copy_file"
	PatchKindCopyDir  PatchKind = "copy_dir"
)

// PullPolicy controls image pull behaviour.
type PullPolicy string

const (
	// PullPolicyDefault is the zero value; the runtime applies its default
	// (currently equivalent to PullPolicyIfMissing).
	PullPolicyDefault   PullPolicy = ""
	PullPolicyAlways    PullPolicy = "always"
	PullPolicyIfMissing PullPolicy = "if-missing"
	PullPolicyNever     PullPolicy = "never"
)

// LogLevel selects the sandbox process log verbosity.
type LogLevel string

const (
	LogLevelDefault LogLevel = ""
	LogLevelTrace   LogLevel = "trace"
	LogLevelDebug   LogLevel = "debug"
	LogLevelInfo    LogLevel = "info"
	LogLevelWarn    LogLevel = "warn"
	LogLevelError   LogLevel = "error"
)

// StatVirtualization is the per-mount stat-virtualization policy for
// virtiofs-backed mounts (bind directories, bind files, and named
// directory/file volumes). Tmpfs and disk-image mounts ignore it.
//
// The zero value is the empty string, which the FFI treats as "use the
// runtime default" (StatVirtualizationStrict).
type StatVirtualization string

const (
	// StatVirtualizationDefault leaves the runtime default in place
	// (currently equivalent to StatVirtualizationStrict).
	StatVirtualizationDefault StatVirtualization = ""
	// StatVirtualizationStrict fails closed: probe the host backing path
	// at mount time and refuse to start if the xattr overlay is unavailable.
	StatVirtualizationStrict StatVirtualization = "strict"
	// StatVirtualizationRelaxed applies the xattr overlay opportunistically.
	// Skips the eager probe and falls back to real host stat when the
	// overlay is absent. Corrupt overlay still fails with EIO.
	StatVirtualizationRelaxed StatVirtualization = "relaxed"
	// StatVirtualizationOff exposes literal host metadata. The override
	// xattr is never read or written; guest chown / mknod-special / Linux
	// file-backed symlinks are rejected with clear errnos.
	StatVirtualizationOff StatVirtualization = "off"
)

// HostPermissions is the per-mount policy for whether guest chmod bits
// propagate to the real host inode. Mirror is rejected when combined with
// StatVirtualizationOff (there is no overlay for Mirror to keep private).
//
// The zero value is the empty string, which the FFI treats as "use the
// runtime default" (HostPermissionsPrivate).
type HostPermissions string

const (
	// HostPermissionsDefault leaves the runtime default in place
	// (currently equivalent to HostPermissionsPrivate).
	HostPermissionsDefault HostPermissions = ""
	// HostPermissionsPrivate keeps guest chmod inside the metadata overlay
	// only; host inodes retain conservative 0o600/0o700 modes.
	HostPermissionsPrivate HostPermissions = "private"
	// HostPermissionsMirror propagates ordinary rwx bits for regular files
	// and directories to the host inode. Setuid/setgid are stripped; uid,
	// gid, file type, and device ids are never mirrored. An owner-access
	// floor (0o600 files, 0o700 dirs) is always applied.
	HostPermissionsMirror HostPermissions = "mirror"
)

// ViolationAction selects what happens when a secret placeholder is detected
// going to a host the secret isn't allowed to talk to.
type ViolationAction string

const (
	// ViolationActionDefault leaves the runtime default in place
	// (currently "block-and-log").
	ViolationActionDefault     ViolationAction = ""
	ViolationActionBlock       ViolationAction = "block"
	ViolationActionBlockAndLog ViolationAction = "block-and-log"
	// ViolationActionBlockAndTerminate also kills the sandbox.
	ViolationActionBlockAndTerminate ViolationAction = "block-and-terminate"
)
