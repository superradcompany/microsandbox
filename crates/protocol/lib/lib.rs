//! `microsandbox-protocol` defines the shared protocol types used for communication
//! between the host and the guest agent over CBOR-over-virtio-serial.
//!
//! For how the protocol is versioned and evolved while staying backward compatible
//! across independently-upgraded hosts and live sandboxes, see `VERSIONING.md` in
//! this crate.

#![warn(missing_docs)]

mod error;

//--------------------------------------------------------------------------------------------------
// Constants: Host↔Guest Shutdown Timings
//--------------------------------------------------------------------------------------------------

/// Maximum time agentd spends in its handoff-mode poweroff sequence.
///
/// In init-handoff sandboxes (systemd, openrc, …) agentd's shutdown
/// handler signals the new PID 1 with `SIGRTMIN+4`, sleeps for this
/// duration to give the init a chance to act, then falls back to
/// `SIGTERM`. The host's [`SHUTDOWN_FLUSH_TIMEOUT`] must exceed this
/// so the host's fallback exit doesn't cut the sequence short.
pub const HANDOFF_POWEROFF_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How long the host waits after forwarding `core.shutdown` to agentd
/// before triggering its own VMM exit fallback.
///
/// agentd uses this window to `sync()` block-backed root filesystems
/// and power off the kernel cleanly (or run its handoff sequence —
/// see [`HANDOFF_POWEROFF_TIMEOUT`]). On a healthy guest the VMM
/// exits well inside the window and the host fallback is a no-op;
/// the fallback only fires when the guest is wedged.
///
/// Must exceed [`HANDOFF_POWEROFF_TIMEOUT`] plus margin for the
/// init's own signal handling — enforced at compile time below.
pub const SHUTDOWN_FLUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

// Compile-time invariant: the host must wait at least as long as
// agentd's longest internal grace, otherwise the host fallback will
// cut agentd's handoff sequence short and we'll silently strand
// init-handoff sandboxes.
const _: () = assert!(
    SHUTDOWN_FLUSH_TIMEOUT.as_secs() > HANDOFF_POWEROFF_TIMEOUT.as_secs(),
    "SHUTDOWN_FLUSH_TIMEOUT must exceed HANDOFF_POWEROFF_TIMEOUT",
);

//--------------------------------------------------------------------------------------------------
// Constants: Host↔Guest Protocol
//--------------------------------------------------------------------------------------------------

/// Virtio-console port name for the agent channel.
pub const AGENT_PORT_NAME: &str = "agent";

/// Virtiofs tag for the runtime filesystem (scripts, heartbeat).
pub const RUNTIME_FS_TAG: &str = "msb_runtime";

/// Guest-write byte budget for the runtime (`/.msb`) virtiofs mount.
///
/// `/.msb` is a host↔guest control channel, not bulk storage: the only
/// guest-written payload is a ~1 KiB heartbeat (host-written scripts and TLS
/// certs form the mount's baseline and are not charged). This 16 MiB ceiling is
/// therefore almost entirely abuse headroom — it exists so the channel cannot be
/// used to fill the host disk. It is intentionally a fixed constant rather than
/// a user-facing knob.
pub const RUNTIME_FS_QUOTA_BYTES: u64 = 16 * 1024 * 1024;

/// Guest mount point for the runtime filesystem.
pub const RUNTIME_MOUNT_POINT: &str = "/.msb";

/// Guest directory for file mount virtiofs shares.
pub const FILE_MOUNTS_DIR: &str = "/.msb/file-mounts";

/// Guest path for named scripts (added to PATH by agentd).
pub const SCRIPTS_PATH: &str = "/.msb/scripts";

/// Maximum number of simultaneous SDK clients the host relay admits.
pub const AGENT_RELAY_MAX_CLIENTS: u32 = 128;

/// Size of the correlation ID range allocated to each relay client.
pub const AGENT_RELAY_ID_RANGE_STEP: u32 = u32::MAX / AGENT_RELAY_MAX_CLIENTS;

//--------------------------------------------------------------------------------------------------
// Constants: Guest Init Environment Variables
//--------------------------------------------------------------------------------------------------

/// Environment variable carrying the sandbox in-guest security profile.
///
/// Values:
/// - `default` — preserve normal guest-root semantics. Exec sessions do not
///   set `no_new_privs` and keep `CAP_SYS_ADMIN`.
/// - `restricted` — set `no_new_privs` and drop `CAP_SYS_ADMIN` before user
///   exec sessions. Agentd also forces `nosuid,nodev` on user mounts.
///
/// Example:
/// - `MSB_SECURITY_PROFILE=restricted`
pub const ENV_SECURITY_PROFILE: &str = "MSB_SECURITY_PROFILE";

/// Environment variable carrying tmpfs mount specs for guest init.
///
/// - `path` — guest mount path (required, always the first element)
/// - `size=N` — size limit in MiB (optional)
/// - `noexec` — mount with noexec flag (optional)
/// - `nosuid` — mount with nosuid flag (optional)
/// - `nodev` — mount with nodev flag (optional)
/// - `ro` — mount read-only (optional)
/// - `rw` — explicit writable default (optional)
/// - `mode=N` — permission mode as octal integer (optional, e.g. `mode=1777`)
///
/// Format: `path[:opts][;path[:opts];...]`.
///
/// Entries are separated by `;`. Within an entry, the path comes first,
/// followed by an optional colon and comma-separated options. Options compose
/// order-independently (e.g. `:ro,noexec` and `:noexec,ro` are equivalent).
///
/// Examples:
/// - `MSB_TMPFS=/tmp:size=256` — 256 MiB tmpfs at `/tmp`
/// - `MSB_TMPFS=/tmp:size=256;/var/tmp:size=128` — two tmpfs mounts
/// - `MSB_TMPFS=/tmp` — tmpfs at `/tmp` with defaults
/// - `MSB_TMPFS=/tmp:size=256,noexec` — with noexec flag
/// - `MSB_TMPFS=/seed:size=64,ro` — read-only tmpfs
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
/// - `MSB_NET_IPV4=addr=172.16.1.2/30,gw=172.16.1.1,dns=172.16.1.1`
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
/// Format: `tag:guest_path[:opts][;tag:guest_path[:opts];...]`
///
/// - `tag` — virtiofs tag name (required, matches the tag used in `--mount`)
/// - `guest_path` — mount point inside the guest (required)
/// - `ro` / `rw` — access mode option (optional)
/// - `noexec` — disable direct execution from the mount (optional)
/// - `nosuid` — mount with nosuid flag (optional)
/// - `nodev` — mount with nodev flag (optional)
///
/// Entries are separated by `;`.
///
/// Examples:
/// - `MSB_DIR_MOUNTS=data:/data` — mount virtiofs tag `data` at `/data`
/// - `MSB_DIR_MOUNTS=data:/data:ro,noexec` — mount read-only and noexec
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
/// Format: `tag:filename:guest_path[:opts][;tag:filename:guest_path[:opts];...]`
///
/// - `tag` — virtiofs tag name (required, matches the tag used in `--mount`)
/// - `filename` — name of the file inside the virtiofs share (required)
/// - `guest_path` — final file path inside the guest (required)
/// - `ro` / `rw` — access mode option (optional)
/// - `noexec` — disable direct execution from the mount (optional)
/// - `nosuid` — mount with nosuid flag (optional)
/// - `nodev` — mount with nodev flag (optional)
///
/// Entries are separated by `;`.
///
/// Examples:
/// - `MSB_FILE_MOUNTS=fm_config:app.conf:/etc/app.conf`
/// - `MSB_FILE_MOUNTS=fm_config:app.conf:/etc/app.conf:ro,noexec`
/// - `MSB_FILE_MOUNTS=fm_a:a.sh:/usr/bin/a.sh;fm_b:b.sh:/usr/bin/b.sh`
pub const ENV_FILE_MOUNTS: &str = "MSB_FILE_MOUNTS";

/// Environment variable carrying disk-image volume mount specs for guest init.
///
/// Each spec describes one virtio-blk device attached for the sole purpose
/// of being mounted at a guest path by agentd (distinct from the rootfs
/// block device, which is described by [`ENV_BLOCK_ROOT`]).
///
/// Format: `id:guest_path[:opts][;id:guest_path[:opts];...]`
///
/// - `id` — the `virtio_blk_config.serial` value set by the VMM. Agentd
///   resolves it to a device node via `/dev/disk/by-id/virtio-<id>`, or
///   by scanning `/sys/block/*/serial` as a fallback.
/// - `guest_path` — absolute mount path in the guest (required).
/// - `fstype=...` — inner filesystem type (optional). When absent,
///   agentd probes `/proc/filesystems` to find a type that mounts cleanly.
/// - `ro` / `rw` — access mode option (optional).
/// - `noexec` — disable direct execution from the mount (optional).
/// - `nosuid` — mount with nosuid flag (optional).
/// - `nodev` — mount with nodev flag (optional).
///
/// Entries are separated by `;`. Options are comma-separated flags or
/// key-value pairs in the final option block.
///
/// Examples:
/// - `MSB_DISK_MOUNTS=data_12ab:/data:fstype=ext4` — ext4 disk at `/data`
/// - `MSB_DISK_MOUNTS=seed_7f:/seed:ro` — autodetect fstype, read-only
/// - `MSB_DISK_MOUNTS=a_1:/a:fstype=ext4;b_2:/b:ro,noexec` — two disks
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
/// Defaults to a sandbox-name-derived hostname when not explicitly set.
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

/// Environment variable selecting a guest init binary for PID 1 handoff.
///
/// When set, agentd performs initial setup (mounts, runtime dirs), then
/// forks. The parent execs the binary at this path, becoming the new
/// PID 1. The child stays alive as a normal grandchild process serving
/// host requests over virtio-serial.
///
/// Format: bare absolute path inside the guest rootfs, or the literal
/// sentinel [`HANDOFF_INIT_AUTO`] which triggers a candidate probe in
/// agentd (see [`HANDOFF_INIT_AUTO_CANDIDATES`]).
///
/// Examples:
/// - `MSB_HANDOFF_INIT=/lib/systemd/systemd`
/// - `MSB_HANDOFF_INIT=auto`
pub const ENV_HANDOFF_INIT: &str = "MSB_HANDOFF_INIT";

/// Sentinel value for [`ENV_HANDOFF_INIT`] requesting auto-detection.
///
/// The host may resolve this sentinel before boot when an OCI image
/// declares a known init as the first entrypoint token. If the sentinel
/// reaches the guest unchanged, agentd probes [`HANDOFF_INIT_AUTO_CANDIDATES`]
/// in order and uses the first path that exists and is executable. If
/// none match, boot fails with a clear error in `kernel.log` listing the
/// paths it checked.
pub const HANDOFF_INIT_AUTO: &str = "auto";

/// Ordered list of image entrypoint paths that `--init auto` may treat
/// as an explicit handoff init.
///
/// This host-side list is intentionally slightly wider than
/// [`HANDOFF_INIT_AUTO_CANDIDATES`]: `/init` is common in s6-overlay
/// images but too broad to probe blindly inside every guest rootfs.
/// Matching it only when the image declares it as ENTRYPOINT keeps the
/// behavior image-directed.
pub const HANDOFF_INIT_IMAGE_ENTRYPOINT_CANDIDATES: &[&str] = &[
    "/init",
    "/sbin/init",
    "/lib/systemd/systemd",
    "/usr/lib/systemd/systemd",
];

/// Ordered list of init-binary paths agentd probes when
/// [`ENV_HANDOFF_INIT`] is set to [`HANDOFF_INIT_AUTO`].
///
/// Order matters: the first match wins. The list covers the three
/// well-known locations across major distros:
/// - `/sbin/init` — BusyBox (Alpine), sysvinit, OpenRC's wrapper.
///   Usually a symlink to the actual init on systemd distros, so it
///   resolves naturally on Debian/Ubuntu too.
/// - `/lib/systemd/systemd` — Debian, Ubuntu, derivatives.
/// - `/usr/lib/systemd/systemd` — Fedora, RHEL, modern Debian.
pub const HANDOFF_INIT_AUTO_CANDIDATES: &[&str] = &[
    "/sbin/init",
    "/lib/systemd/systemd",
    "/usr/lib/systemd/systemd",
];

/// Argv list for the handoff init binary.
///
/// Format: base64url-no-padding encoded JSON array of strings.
/// Empty or unset means the init is exec'd with `argv = [program]`.
/// This deliberately differs from the delimiter-based `MSB_*` boot env
/// formats because argv entries are arbitrary strings; wrapping JSON in
/// base64url preserves spaces, separators, empty strings, and Unicode
/// without inventing a second escaping language.
///
/// Example:
/// - `MSB_HANDOFF_INIT_ARGS=WyItdW5pdD1tdWx0aS11c2VyLnRhcmdldCJd`
pub const ENV_HANDOFF_INIT_ARGS: &str = "MSB_HANDOFF_INIT_ARGS";

/// Working directory for the handoff init binary.
///
/// Docker applies `WORKDIR` before executing `ENTRYPOINT + CMD`. Init handoff
/// uses this optional path so image-declared init entrypoints receive the same
/// process cwd as they would under container startup.
///
/// Example:
/// - `MSB_HANDOFF_INIT_CWD=/opt/app`
pub const ENV_HANDOFF_INIT_CWD: &str = "MSB_HANDOFF_INIT_CWD";

/// Extra environment variables for the handoff init binary.
///
/// Format: base64url-no-padding encoded JSON array of `[key, value]`
/// pairs. Merged on top of the inherited env.
/// This uses the same structured payload exception as
/// [`ENV_HANDOFF_INIT_ARGS`] so env values can contain the delimiter
/// characters used by older `MSB_*` boot env formats.
///
/// Example:
/// - `MSB_HANDOFF_INIT_ENV=W1siY29udGFpbmVyIiwibWljcm9zYW5kYm94Il1d`
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
pub mod tcp;

pub use error::*;
