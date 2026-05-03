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
/// - `ro` — mount read-only (optional)
/// - `mode=N` — permission mode as octal integer (optional, e.g. `mode=1777`)
///
/// Entries are separated by `;`. Within an entry, the path comes first
/// followed by comma-separated options. Options compose order-independently
/// (e.g. `,ro,noexec` and `,noexec,ro` are equivalent).
///
/// Examples:
/// - `MSB_TMPFS=/tmp,size=256` — 256 MiB tmpfs at `/tmp`
/// - `MSB_TMPFS=/tmp,size=256;/var/tmp,size=128` — two tmpfs mounts
/// - `MSB_TMPFS=/tmp` — tmpfs at `/tmp` with defaults
/// - `MSB_TMPFS=/tmp,size=256,noexec` — with noexec flag
/// - `MSB_TMPFS=/seed,size=64,ro` — read-only tmpfs
pub const ENV_TMPFS: &str = "MSB_TMPFS";

/// Environment variable specifying how agentd assembles the root filesystem.
///
/// Format: comma-separated `key=value` pairs, semicolons for multi-value fields.
///
/// Variants:
/// - `kind=disk-image,device=/dev/vda[,fstype=ext4]`
/// - `kind=oci-layered,lowers=/dev/vdb;/dev/vdc;/dev/vdd,lower_fstype=erofs,upper=/dev/vde,upper_fstype=ext4`
/// - `kind=oci-flat,lower=/dev/vdb,lower_fstype=erofs,upper=/dev/vdc,upper_fstype=ext4`
///
/// Legacy format (`/dev/vda[,fstype=ext4]`) is accepted and treated as `kind=disk-image`.
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

/// Environment variable carrying disk-image volume mount specs for guest init.
///
/// Each spec describes one virtio-blk device attached for the sole purpose
/// of being mounted at a guest path by agentd (distinct from the rootfs
/// block device, which is described by [`ENV_BLOCK_ROOT`]).
///
/// Format: `id:guest_path[:fstype][:ro][;id:guest_path[:fstype][:ro];...]`
///
/// - `id` — the `virtio_blk_config.serial` value set by the VMM. Agentd
///   resolves it to a device node via `/dev/disk/by-id/virtio-<id>`, or
///   by scanning `/sys/block/*/serial` as a fallback.
/// - `guest_path` — absolute mount path in the guest (required).
/// - `fstype` — inner filesystem type (optional). When empty or absent,
///   agentd probes `/proc/filesystems` to find a type that mounts cleanly.
/// - `ro` — optional flag: mount read-only.
///
/// Entries are separated by `;`. The `fstype` slot is positional, not
/// keyed. To express "no fstype + ro" the slot must be empty:
/// `id:/path::ro`. The form `id:/path:ro` would parse as `fstype=ro`,
/// not the readonly flag.
///
/// Examples:
/// - `MSB_DISK_MOUNTS=data_12ab:/data:ext4` — ext4 disk at `/data`
/// - `MSB_DISK_MOUNTS=seed_7f:/seed::ro` — autodetect fstype, read-only
/// - `MSB_DISK_MOUNTS=a_1:/a:ext4;b_2:/b::ro` — two disks
pub const ENV_DISK_MOUNTS: &str = "MSB_DISK_MOUNTS";

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

/// Environment variable carrying the DNS name the guest uses to reach
/// the sandbox host (Docker's `host.docker.internal` equivalent).
///
/// The host-side network stack emits this value via its
/// `guest_env_vars()` method; agentd reads it into
/// [`crate::exec`]-adjacent boot params and writes the mapping into
/// `/etc/hosts`. The value the network stack emits is a fixed
/// protocol constant — today always `host.microsandbox.internal`.
pub const ENV_HOST_ALIAS: &str = "MSB_HOST_ALIAS";

/// Environment variable carrying sandbox-wide resource limits.
///
/// Format: `resource=limit[:hard][;resource=limit[:hard];...]`
///
/// - `resource` — lowercase rlimit name such as `nofile` or `nproc`
/// - `limit` — soft limit
/// - `hard` — hard limit (optional; if omitted, uses the soft limit)
///
/// Examples:
/// - `MSB_RLIMITS=nofile=65535`
/// - `MSB_RLIMITS=nofile=65535:65535;nproc=4096:4096`
///
/// agentd applies these during PID 1 startup so every later guest process
/// inherits the raised baseline instead of having to opt into per-exec rlimits.
pub const ENV_RLIMITS: &str = "MSB_RLIMITS";

/// Separator byte for argv/env entries in handoff-init env vars.
///
/// ASCII Unit Separator (`0x1F`). Argv entries and `KEY=VAL` env pairs
/// are arbitrary user strings, so the `;` separator other MSB_* vars use
/// is unsafe — they collide with realistic shell input. `0x1F` is
/// purpose-built for this and absent from any printable string.
pub const HANDOFF_INIT_SEP: char = '\x1f';

/// String form of [`HANDOFF_INIT_SEP`] for use with `&str`-friendly
/// APIs like `[T]::join`. Avoids per-call `char.to_string()` allocations
/// on the host's encoder side.
pub const HANDOFF_INIT_SEP_STR: &str = "\x1f";

/// Environment variable selecting a guest init binary for PID 1 handoff.
///
/// When set, agentd performs initial setup (mounts, runtime dirs), then
/// forks. The parent execs the binary at this path, becoming the new
/// PID 1. The child stays alive as a normal grandchild process serving
/// host requests over virtio-serial.
///
/// Format: bare absolute path inside the guest rootfs.
///
/// Example:
/// - `MSB_HANDOFF_INIT=/lib/systemd/systemd`
pub const ENV_HANDOFF_INIT: &str = "MSB_HANDOFF_INIT";

/// Argv list for the handoff init binary.
///
/// Format: entries separated by [`HANDOFF_INIT_SEP`] (ASCII `0x1F`).
/// Empty or unset means the init is exec'd with `argv = [program]`.
///
/// Example:
/// - `MSB_HANDOFF_INIT_ARGS=--unit=multi-user.target\x1f--log-level=warning`
pub const ENV_HANDOFF_INIT_ARGS: &str = "MSB_HANDOFF_INIT_ARGS";

/// Extra environment variables for the handoff init binary.
///
/// Format: `KEY=VAL` pairs separated by [`HANDOFF_INIT_SEP`]
/// (ASCII `0x1F`). Each entry must contain at least one `=`. Merged on
/// top of the inherited env.
///
/// Example:
/// - `MSB_HANDOFF_INIT_ENV=container=microsandbox\x1fLANG=C.UTF-8`
pub const ENV_HANDOFF_INIT_ENV: &str = "MSB_HANDOFF_INIT_ENV";

/// Guest-side path to the CA certificate for TLS interception.
///
/// Placed by the sandbox process via the runtime virtiofs mount.
/// agentd checks for this file during init and installs it into the guest
/// trust store.
pub const GUEST_TLS_CA_PATH: &str = "/.msb/tls/ca.pem";

/// Guest-side path to a PEM bundle of the host's extra trusted CAs.
///
/// Placed by the sandbox process via the runtime virtiofs mount when
/// host-CA trust is enabled (default). agentd checks for this file during
/// init and appends it to the guest's trust bundle, so outbound TLS works
/// even behind a corporate MITM proxy whose gateway CA is installed on
/// the host but unknown to the guest.
pub const GUEST_TLS_HOST_CAS_PATH: &str = "/.msb/tls/host-cas.pem";

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
