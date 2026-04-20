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
// Prefer the NetworkPolicy factory (NetworkPolicy.None / PublicOnly / AllowAll)
// which returns a preconfigured *NetworkConfig.
type NetworkPolicyPreset string

const (
	NetworkPolicyPresetNone       NetworkPolicyPreset = "none"
	NetworkPolicyPresetPublicOnly NetworkPolicyPreset = "public-only"
	NetworkPolicyPresetAllowAll   NetworkPolicyPreset = "allow-all"
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

// PullPolicy controls image pull behaviour. Reserved for a future WithPullPolicy
// option; declared now for parity with the other SDKs.
type PullPolicy string

const (
	PullPolicyAlways    PullPolicy = "always"
	PullPolicyIfMissing PullPolicy = "if-missing"
	PullPolicyNever     PullPolicy = "never"
)
