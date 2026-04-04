//! `microsandbox-protocol` defines the shared protocol types used for communication
//! between the host and the guest agent over CBOR-over-virtio-serial.

#![warn(missing_docs)]

mod error;

//--------------------------------------------------------------------------------------------------
// Constants: Host↔Guest Protocol
//--------------------------------------------------------------------------------------------------

/// Virtio-console port name for the agent channel.
pub const AGENT_PORT_NAME: &str = "agent";

/// Virtiofs tag for the runtime filesystem (scripts, heartbeat).
pub const RUNTIME_FS_TAG: &str = "msb_runtime";

/// Guest mount point for the runtime filesystem.
pub const RUNTIME_MOUNT_POINT: &str = "/.msb";

/// Guest directory for file mount virtiofs shares.
pub const FILE_MOUNTS_DIR: &str = "/.msb/file-mounts";

/// Guest path for named scripts (added to PATH by agentd).
pub const SCRIPTS_PATH: &str = "/.msb/scripts";

//--------------------------------------------------------------------------------------------------
// Constants: Guest Init Environment Variables
//--------------------------------------------------------------------------------------------------

/// Environment variable carrying tmpfs mount specs for guest init.
///
/// Format: `path[,key=value,...][;path[,key=value,...];...]`
///
/// - `path` — guest mount path (required, always the first element)
/// - `size=N` — size limit in MiB (optional)
/// - `noexec` — mount with noexec flag (optional)
/// - `mode=N` — permission mode as octal integer (optional, e.g. `mode=1777`)
///
/// Entries are separated by `;`. Within an entry, the path comes first
/// followed by comma-separated options.
///
/// Examples:
/// - `MSB_TMPFS=/tmp,size=256` — 256 MiB tmpfs at `/tmp`
/// - `MSB_TMPFS=/tmp,size=256;/var/tmp,size=128` — two tmpfs mounts
/// - `MSB_TMPFS=/tmp` — tmpfs at `/tmp` with defaults
/// - `MSB_TMPFS=/tmp,size=256,noexec` — with noexec flag
pub const ENV_TMPFS: &str = "MSB_TMPFS";

/// Environment variable specifying the block device for rootfs switch.
///
/// Format: `device[,key=value,...]`
/// - `device` — block device path (required, always first element)
/// - `fstype=TYPE` — filesystem type (optional; auto-detected if absent)
pub const ENV_BLOCK_ROOT: &str = "MSB_BLOCK_ROOT";

/// Environment variable carrying the guest network interface configuration.
///
/// Format: `key=value,...`
///
/// - `iface=NAME` — interface name (required)
/// - `mac=AA:BB:CC:DD:EE:FF` — MAC address (required)
/// - `mtu=N` — MTU (optional)
///
/// Example:
/// - `MSB_NET=iface=eth0,mac=02:5a:7b:13:01:02,mtu=1500`
pub const ENV_NET: &str = "MSB_NET";

/// Environment variable carrying the guest IPv4 network configuration.
///
/// Format: `key=value,...`
///
/// - `addr=A.B.C.D/N` — address with prefix length (required)
/// - `gw=A.B.C.D` — default gateway (required)
/// - `dns=A.B.C.D` — DNS server (optional)
///
/// Example:
/// - `MSB_NET_IPV4=addr=100.96.1.2/30,gw=100.96.1.1,dns=100.96.1.1`
pub const ENV_NET_IPV4: &str = "MSB_NET_IPV4";

/// Environment variable carrying the guest IPv6 network configuration.
///
/// Format: `key=value,...`
///
/// - `addr=ADDR/N` — address with prefix length (required)
/// - `gw=ADDR` — default gateway (required)
/// - `dns=ADDR` — DNS server (optional)
///
/// Example:
/// - `MSB_NET_IPV6=addr=fd42:6d73:62:2a::2/64,gw=fd42:6d73:62:2a::1,dns=fd42:6d73:62:2a::1`
pub const ENV_NET_IPV6: &str = "MSB_NET_IPV6";

/// Environment variable carrying virtiofs directory volume mount specs for guest init.
///
/// Format: `tag:guest_path[:ro][;tag:guest_path[:ro];...]`
///
/// - `tag` — virtiofs tag name (required, matches the tag used in `--mount`)
/// - `guest_path` — mount point inside the guest (required)
/// - `ro` — mount read-only (optional suffix)
///
/// Entries are separated by `;`.
///
/// Examples:
/// - `MSB_DIR_MOUNTS=data:/data` — mount virtiofs tag `data` at `/data`
/// - `MSB_DIR_MOUNTS=data:/data:ro` — mount read-only
/// - `MSB_DIR_MOUNTS=data:/data;cache:/cache:ro` — two mounts
pub const ENV_DIR_MOUNTS: &str = "MSB_DIR_MOUNTS";

/// Environment variable carrying virtiofs **file** volume mount specs for guest init.
///
/// Used when the host path is a single file rather than a directory. The SDK
/// wraps each file in an isolated staging directory (hard-linked to preserve
/// the same inode) and shares that directory via virtiofs. Agentd mounts the
/// share at [`FILE_MOUNTS_DIR`]`/<tag>/` and bind-mounts the file to the
/// guest path.
///
/// Format: `tag:filename:guest_path[:ro][;tag:filename:guest_path[:ro];...]`
///
/// - `tag` — virtiofs tag name (required, matches the tag used in `--mount`)
/// - `filename` — name of the file inside the virtiofs share (required)
/// - `guest_path` — final file path inside the guest (required)
/// - `ro` — mount read-only (optional suffix)
///
/// Entries are separated by `;`.
///
/// Examples:
/// - `MSB_FILE_MOUNTS=fm_config:app.conf:/etc/app.conf`
/// - `MSB_FILE_MOUNTS=fm_config:app.conf:/etc/app.conf:ro`
/// - `MSB_FILE_MOUNTS=fm_a:a.sh:/usr/bin/a.sh;fm_b:b.sh:/usr/bin/b.sh`
pub const ENV_FILE_MOUNTS: &str = "MSB_FILE_MOUNTS";

/// Environment variable carrying the default guest user for agentd execs.
///
/// Format: `USER[:GROUP]` or `UID[:GID]`
///
/// - `USER`
/// - `UID`
/// - `USER:GROUP`
/// - `UID:GID`
///
/// Example:
/// - `MSB_USER=alice` — default to user `alice`
/// - `MSB_USER=1000` — default to UID 1000
/// - `MSB_USER=alice:developers` — default to user `alice` and group `developers`
/// - `MSB_USER=1000:100` — default to UID 1000 and GID 100
pub const ENV_USER: &str = "MSB_USER";

/// Environment variable carrying the guest hostname for agentd.
///
/// Format: bare string
///
/// Example:
/// - `MSB_HOSTNAME=worker-01`
///
/// agentd calls `sethostname()` and adds the name to `/etc/hosts`.
/// Defaults to the sandbox name when not explicitly set.
pub const ENV_HOSTNAME: &str = "MSB_HOSTNAME";

/// Guest-side path to the CA certificate for TLS interception.
///
/// Placed by the sandbox process via the runtime virtiofs mount.
/// agentd checks for this file during init and installs it into the guest
/// trust store.
pub const GUEST_TLS_CA_PATH: &str = "/.msb/tls/ca.pem";

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod codec;
pub mod core;
pub mod exec;
pub mod fs;
pub mod heartbeat;
pub mod message;

pub use error::*;
