"""Frozen dataclasses for all configuration and result types."""

from __future__ import annotations

import enum
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal, TypeAlias

#--------------------------------------------------------------------------------------------------
# Constants
#--------------------------------------------------------------------------------------------------

MiB: int = 1024 * 1024
GiB: int = 1024 * 1024 * 1024

#--------------------------------------------------------------------------------------------------
# Types: Enums
#--------------------------------------------------------------------------------------------------

class PullPolicy(enum.StrEnum):
    ALWAYS = "always"
    IF_MISSING = "if-missing"
    NEVER = "never"


class LogLevel(enum.StrEnum):
    TRACE = "trace"
    DEBUG = "debug"
    INFO = "info"
    WARN = "warn"
    ERROR = "error"


class SecurityProfile(enum.StrEnum):
    DEFAULT = "default"
    RESTRICTED = "restricted"


class SandboxStatus(enum.StrEnum):
    RUNNING = "running"
    STOPPED = "stopped"
    CRASHED = "crashed"
    DRAINING = "draining"
    PAUSED = "paused"


class Action(enum.StrEnum):
    ALLOW = "allow"
    DENY = "deny"

class Direction(enum.StrEnum):
    EGRESS = "egress"
    INGRESS = "ingress"
    ANY = "any"

class Protocol(enum.StrEnum):
    TCP = "tcp"
    UDP = "udp"
    ICMPV4 = "icmpv4"
    ICMPV6 = "icmpv6"

class PortProtocol(enum.StrEnum):
    TCP = "tcp"
    UDP = "udp"

class DestGroup(enum.StrEnum):
    PUBLIC = "public"
    LOOPBACK = "loopback"
    PRIVATE = "private"
    LINK_LOCAL = "link-local"
    METADATA = "metadata"
    MULTICAST = "multicast"
    HOST = "host"

class ViolationAction(enum.StrEnum):
    BLOCK = "block"
    BLOCK_AND_LOG = "block-and-log"
    BLOCK_AND_TERMINATE = "block-and-terminate"
    PASSTHROUGH = "passthrough"

@dataclass(frozen=True, slots=True)
class ViolationPolicy:
    """Secret violation behavior, including optional passthrough hosts."""
    fallback: ViolationAction = ViolationAction.BLOCK_AND_LOG
    passthrough_hosts: tuple[str, ...] = ()
    passthrough_host_patterns: tuple[str, ...] = ()
    passthrough_all_hosts: bool = False

    @classmethod
    def block(cls) -> ViolationPolicy:
        return cls(fallback=ViolationAction.BLOCK)

    @classmethod
    def block_and_log(cls) -> ViolationPolicy:
        return cls(fallback=ViolationAction.BLOCK_AND_LOG)

    @classmethod
    def block_and_terminate(cls) -> ViolationPolicy:
        return cls(fallback=ViolationAction.BLOCK_AND_TERMINATE)

    @classmethod
    def passthrough(
        cls,
        *,
        hosts: Sequence[str] = (),
        host_patterns: Sequence[str] = (),
        all_hosts: bool = False,
    ) -> ViolationPolicy:
        return cls(
            passthrough_hosts=tuple(hosts),
            passthrough_host_patterns=tuple(host_patterns),
            passthrough_all_hosts=all_hosts,
        )

    def _to_dict(self) -> str | dict:
        if (
            not self.passthrough_hosts
            and not self.passthrough_host_patterns
            and not self.passthrough_all_hosts
        ):
            return str(self.fallback)

        passthrough: dict = {}
        if self.passthrough_hosts:
            passthrough["hosts"] = list(self.passthrough_hosts)
        if self.passthrough_host_patterns:
            passthrough["host_patterns"] = list(self.passthrough_host_patterns)
        if self.passthrough_all_hosts:
            passthrough["all_hosts"] = True
        return {"passthrough": passthrough}

class MountKind(enum.StrEnum):
    BIND = "bind"
    NAMED = "named"
    TMPFS = "tmpfs"
    DISK = "disk"

class StatVirtualization(enum.StrEnum):
    """Per-mount stat-virtualization policy for virtiofs-backed mounts."""
    STRICT = "strict"
    RELAXED = "relaxed"
    OFF = "off"

class HostPermissions(enum.StrEnum):
    """Per-mount host-permission policy for virtiofs-backed mounts."""
    PRIVATE = "private"
    MIRROR = "mirror"

class FsEntryKind(enum.StrEnum):
    FILE = "file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    OTHER = "other"

class DiskImageFormat(enum.StrEnum):
    QCOW2 = "qcow2"
    RAW = "raw"
    VMDK = "vmdk"

class RlimitResource(enum.StrEnum):
    CPU = "cpu"
    FSIZE = "fsize"
    DATA = "data"
    STACK = "stack"
    CORE = "core"
    RSS = "rss"
    NPROC = "nproc"
    NOFILE = "nofile"
    MEMLOCK = "memlock"
    AS = "as"
    LOCKS = "locks"
    SIGPENDING = "sigpending"
    MSGQUEUE = "msgqueue"
    NICE = "nice"
    RTPRIO = "rtprio"
    RTTIME = "rttime"

LogSource: TypeAlias = Literal["stdout", "stderr", "output", "system"]
LogReadSource: TypeAlias = Literal["stdout", "stderr", "output", "system", "all"]

#--------------------------------------------------------------------------------------------------
# Types: Size
#--------------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Size:
    """Memory/storage size value type."""
    bytes: int

    @classmethod
    def mib(cls, n: int) -> Size:
        return cls(n * MiB)

    @classmethod
    def gib(cls, n: int) -> Size:
        return cls(n * GiB)

    @property
    def mib_count(self) -> int:
        return self.bytes // MiB

#--------------------------------------------------------------------------------------------------
# Types: ExitStatus
#--------------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class ExitStatus:
    """Process exit status."""
    code: int
    success: bool

#--------------------------------------------------------------------------------------------------
# Types: Rlimit
#--------------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Rlimit:
    """A POSIX resource limit."""
    resource: RlimitResource
    soft: int
    hard: int

    @classmethod
    def nofile(cls, limit: int) -> Rlimit:
        return cls(RlimitResource.NOFILE, limit, limit)

    @classmethod
    def cpu(cls, secs: int) -> Rlimit:
        return cls(RlimitResource.CPU, secs, secs)

    @classmethod
    def as_(cls, *, soft: int, hard: int) -> Rlimit:
        return cls(RlimitResource.AS, soft, hard)

    @classmethod
    def nproc(cls, limit: int) -> Rlimit:
        return cls(RlimitResource.NPROC, limit, limit)

    @classmethod
    def fsize(cls, limit: int) -> Rlimit:
        return cls(RlimitResource.FSIZE, limit, limit)

    @classmethod
    def memlock(cls, limit: int) -> Rlimit:
        return cls(RlimitResource.MEMLOCK, limit, limit)

    @classmethod
    def stack(cls, limit: int) -> Rlimit:
        return cls(RlimitResource.STACK, limit, limit)

    def _to_dict(self) -> dict:
        return {"resource": str(self.resource), "soft": self.soft, "hard": self.hard}

#--------------------------------------------------------------------------------------------------
# Types: Stdin
#--------------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Stdin:
    """Stdin mode for command execution."""
    _mode: str
    _data: bytes | None = None

    @classmethod
    def null(cls) -> Stdin:
        return cls("null")

    @classmethod
    def pipe(cls) -> Stdin:
        return cls("pipe")

    @classmethod
    def bytes(cls, data: bytes) -> Stdin:
        return cls("bytes", data)

#--------------------------------------------------------------------------------------------------
# Types: Init Handoff
#--------------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class InitConfig:
    """Guest init-handoff configuration.

    Pass to ``Sandbox.create(init=...)`` when the init binary takes
    argv or extra env vars. For the simple case, just pass the cmd
    as a bare string: ``init="auto"``.

    ``cmd`` is either an absolute path inside the guest rootfs or the
    literal ``"auto"``. Auto honors a known init at the start of the
    image ENTRYPOINT, preserves attached init-entrypoint commands, then
    probes /sbin/init, /lib/systemd/systemd, and /usr/lib/systemd/systemd
    inside the guest.
    """
    cmd: str
    args: tuple[str, ...] = ()
    env: Mapping[str, str] = field(default_factory=dict)

    def _to_dict(self) -> dict:
        d: dict = {"cmd": self.cmd}
        if self.args:
            d["args"] = list(self.args)
        if self.env:
            d["env"] = dict(self.env)
        return d

#--------------------------------------------------------------------------------------------------
# Types: Mount
#--------------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class MountConfig:
    """Volume mount configuration.

    ``stat_virtualization`` and ``host_permissions`` are only meaningful for
    virtiofs-backed mounts (``BIND`` and ``NAMED``). Setting either on a
    ``TMPFS`` or ``DISK`` mount raises ``ValueError`` at serialization time.
    """
    kind: MountKind
    bind: str | None = None
    named: str | None = None
    named_mode: Literal["existing", "create", "ensure-exists"] | None = None
    named_kind: Literal["dir", "directory", "disk"] | None = None
    quota_mib: int | None = None
    size_mib: int | None = None
    readonly: bool = False
    noexec: bool = False
    nosuid: bool = False
    nodev: bool = False
    disk: str | None = None
    format: DiskImageFormat | str | None = None
    fstype: str | None = None
    stat_virtualization: StatVirtualization | str | None = None
    host_permissions: HostPermissions | str | None = None

    def _to_dict(self) -> dict:
        # Drive emission off `kind` exclusively so a `MountConfig` with
        # contradictory fields (e.g. kind=DISK + bind=...) raises here
        # rather than silently letting the wrong arm of `apply_mount` win.
        d: dict = {
            "readonly": self.readonly,
            "noexec": self.noexec,
            "nosuid": self.nosuid,
            "nodev": self.nodev,
        }
        if self.kind == MountKind.BIND:
            if self.bind is None:
                raise ValueError("MountConfig kind=BIND requires bind=...")
            d["bind"] = self.bind
            if self.quota_mib is not None:
                d["quota_mib"] = self.quota_mib
        elif self.kind == MountKind.NAMED:
            if self.named is None:
                raise ValueError("MountConfig kind=NAMED requires named=...")
            d["named"] = self.named
            if self.named_mode is not None:
                d["named_mode"] = self.named_mode
            if self.named_kind is not None:
                d["named_kind"] = self.named_kind
            if self.size_mib is not None:
                d["size_mib"] = self.size_mib
            if self.quota_mib is not None:
                d["quota_mib"] = self.quota_mib
        elif self.kind == MountKind.TMPFS:
            d["tmpfs"] = True
            if self.size_mib is not None:
                d["size_mib"] = self.size_mib
        elif self.kind == MountKind.DISK:
            if self.disk is None:
                raise ValueError("MountConfig kind=DISK requires disk=...")
            d["disk"] = self.disk
            if self.format is not None:
                d["format"] = _enum_value(self.format)
            if self.fstype is not None:
                d["fstype"] = self.fstype
        else:  # pragma: no cover - StrEnum exhaustive above
            raise ValueError(f"unknown MountKind: {self.kind!r}")

        # Per-mount policies — only valid for virtiofs-backed kinds.
        if self.kind in (MountKind.BIND, MountKind.NAMED):
            if self.stat_virtualization is not None:
                d["stat_virtualization"] = _enum_value(self.stat_virtualization)
            if self.host_permissions is not None:
                d["host_permissions"] = _enum_value(self.host_permissions)
        elif self.stat_virtualization is not None or self.host_permissions is not None:
            raise ValueError(
                f"stat_virtualization/host_permissions are only valid for "
                f"BIND/NAMED mounts (got kind={self.kind.value})"
            )
        return d

def _enum_value(value: enum.Enum | str) -> str:
    return value.value if isinstance(value, enum.Enum) else value

#--------------------------------------------------------------------------------------------------
# Types: Image
#--------------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class ImageSource:
    """Explicit rootfs image source."""
    _type: str
    _path: str | None = None
    _reference: str | None = None
    _upper_size_mib: int | None = None
    _fstype: str | None = None
    _format: DiskImageFormat | None = None

    def _to_image_str(self) -> str:
        """Convert to the string form the Rust SDK expects."""
        if self._type == "oci" and self._reference is not None:
            return self._reference
        if self._type == "bind" and self._path is not None:
            return self._path
        if self._type == "disk" and self._path is not None:
            return self._path
        raise ValueError(f"invalid ImageSource: type={self._type}")

class Image:
    """Factory for explicit image source configuration."""

    @staticmethod
    def oci(reference: str, *, upper_size_mib: int | None = None) -> ImageSource:
        return ImageSource(
            _type="oci",
            _reference=reference,
            _upper_size_mib=upper_size_mib,
        )

    @staticmethod
    def bind(path: str) -> ImageSource:
        return ImageSource(_type="bind", _path=path)

    @staticmethod
    def disk(
        path: str,
        *,
        fstype: str | None = None,
    ) -> ImageSource:
        """Create a disk image rootfs. Format auto-detected from extension."""
        return ImageSource(_type="disk", _path=path, _fstype=fstype)

#--------------------------------------------------------------------------------------------------
# Types: Patch
#--------------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class PatchConfig:
    """A rootfs patch applied before VM startup."""
    kind: str
    path: str | None = None
    content: str | None = None
    src: str | None = None
    dst: str | None = None
    target: str | None = None
    link: str | None = None
    mode: int | None = None
    replace: bool = False

    def _to_dict(self) -> dict:
        d: dict = {"kind": self.kind}
        for f in ("path", "content", "src", "dst", "target", "link", "mode"):
            v = getattr(self, f)
            if v is not None:
                d[f] = v
        if self.replace:
            d["replace"] = True
        return d

class Patch:
    """Factory for rootfs patch configurations."""

    @staticmethod
    def text(
        path: str, content: str, *, mode: int | None = None, replace: bool = False,
    ) -> PatchConfig:
        return PatchConfig(
            kind="text", path=path, content=content, mode=mode, replace=replace,
        )

    @staticmethod
    def mkdir(path: str, *, mode: int | None = None) -> PatchConfig:
        return PatchConfig(kind="mkdir", path=path, mode=mode)

    @staticmethod
    def append(path: str, content: str) -> PatchConfig:
        return PatchConfig(kind="append", path=path, content=content)

    @staticmethod
    def copy_file(
        src: str, dst: str, *, mode: int | None = None, replace: bool = False,
    ) -> PatchConfig:
        return PatchConfig(
            kind="copy_file", src=src, dst=dst, mode=mode, replace=replace,
        )

    @staticmethod
    def copy_dir(src: str, dst: str, *, replace: bool = False) -> PatchConfig:
        return PatchConfig(kind="copy_dir", src=src, dst=dst, replace=replace)

    @staticmethod
    def symlink(target: str, link: str, *, replace: bool = False) -> PatchConfig:
        return PatchConfig(kind="symlink", target=target, link=link, replace=replace)

    @staticmethod
    def remove(path: str) -> PatchConfig:
        return PatchConfig(kind="remove", path=path)

#--------------------------------------------------------------------------------------------------
# Types: Secret
#--------------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class SecretInjection:
    """Where in the HTTP request the secret value can be substituted."""
    headers: bool = True
    basic_auth: bool = True
    query_params: bool = False
    body: bool = False

    def _to_dict(self) -> dict:
        d: dict = {}
        if not self.headers:
            d["headers"] = False
        if not self.basic_auth:
            d["basic_auth"] = False
        if self.query_params:
            d["query_params"] = True
        if self.body:
            d["body"] = True
        return d

@dataclass(frozen=True, slots=True)
class SecretEntry:
    """A secret entry for the secrets array."""
    env_var: str
    value: str
    allow_hosts: tuple[str, ...] = ()
    allow_host_patterns: tuple[str, ...] = ()
    placeholder: str | None = None
    require_tls: bool = True
    on_violation: ViolationAction | ViolationPolicy = ViolationAction.BLOCK_AND_LOG
    injection: SecretInjection = field(default_factory=SecretInjection)

    def _to_dict(self) -> dict:
        d: dict = {"env_var": self.env_var, "value": self.value}
        if self.allow_hosts:
            d["allow_hosts"] = list(self.allow_hosts)
        if self.allow_host_patterns:
            d["allow_host_patterns"] = list(self.allow_host_patterns)
        if self.placeholder is not None:
            d["placeholder"] = self.placeholder
        if not self.require_tls:
            d["require_tls"] = False
        violation = violation_policy_to_dict(self.on_violation)
        if violation != str(ViolationAction.BLOCK_AND_LOG):
            d["on_violation"] = violation
        injection = self.injection._to_dict()
        if injection:
            d["injection"] = injection
        return d

class Secret:
    """Factory for secret entries."""

    @staticmethod
    def env(
        env_var: str,
        *,
        value: str,
        allow_hosts: Sequence[str] = (),
        allow_host_patterns: Sequence[str] = (),
        placeholder: str | None = None,
        require_tls: bool = True,
        on_violation: ViolationAction | ViolationPolicy = ViolationAction.BLOCK_AND_LOG,
        injection: SecretInjection | None = None,
    ) -> SecretEntry:
        return SecretEntry(
            env_var=env_var,
            value=value,
            allow_hosts=tuple(allow_hosts),
            allow_host_patterns=tuple(allow_host_patterns),
            placeholder=placeholder,
            require_tls=require_tls,
            on_violation=on_violation,
            injection=injection if injection is not None else SecretInjection(),
        )

#--------------------------------------------------------------------------------------------------
# Types: Network
#--------------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class NetworkDestination:
    """Typed network policy destination."""
    kind: Literal["any", "ip", "cidr", "domain", "domain_suffix", "group"]
    value: str | None = None

    def _to_dict(self) -> dict:
        d = {"destination_kind": self.kind}
        if self.value is not None:
            d["destination"] = self.value
        return d


class Destination:
    """Factory for typed network policy destinations."""

    @staticmethod
    def any() -> NetworkDestination:
        return NetworkDestination("any")

    @staticmethod
    def ip(ip: str) -> NetworkDestination:
        return NetworkDestination("ip", ip)

    @staticmethod
    def cidr(cidr: str) -> NetworkDestination:
        return NetworkDestination("cidr", cidr)

    @staticmethod
    def domain(domain: str) -> NetworkDestination:
        return NetworkDestination("domain", domain)

    @staticmethod
    def domain_suffix(suffix: str) -> NetworkDestination:
        return NetworkDestination("domain_suffix", suffix)

    @staticmethod
    def group(group: DestGroup | str) -> NetworkDestination:
        return NetworkDestination("group", str(group))


NetworkDestinationLike: TypeAlias = str | NetworkDestination | None


@dataclass(frozen=True, slots=True)
class Rule:
    """A network policy rule."""
    action: Action
    direction: Direction = Direction.EGRESS
    destination: NetworkDestinationLike = None
    protocol: Protocol | None = None
    port: int | str | None = None

    @classmethod
    def allow(
        cls,
        *,
        direction: Direction = Direction.EGRESS,
        protocol: Protocol | None = None,
        port: int | str | None = None,
        destination: NetworkDestinationLike = None,
    ) -> Rule:
        return cls(Action.ALLOW, direction, destination, protocol, port)

    @classmethod
    def deny(
        cls,
        *,
        direction: Direction = Direction.EGRESS,
        protocol: Protocol | None = None,
        port: int | str | None = None,
        destination: NetworkDestinationLike = None,
    ) -> Rule:
        return cls(Action.DENY, direction, destination, protocol, port)

    @classmethod
    def allow_dns(cls) -> tuple[Rule, Rule]:
        """Allow plain DNS (UDP/53 and TCP/53) to the sandbox gateway.

        Returns the pair `(udp_rule, tcp_rule)` since this SDK's
        `Rule` shape is single-protocol. Splat into `NetworkPolicy.rules`
        to open DNS under a deny-by-default policy:

            NetworkPolicy(rules=(*Rule.allow_dns(), ...))

        DoT (TCP/853) is intentionally not included; add an explicit
        `destination=Destination.group(DestGroup.HOST)`,
        `protocol=Protocol.TCP`, `port=853` rule if needed (and pair with
        TLS interception).
        """
        return (
            cls(
                Action.ALLOW,
                Direction.EGRESS,
                Destination.group(DestGroup.HOST),
                Protocol.UDP,
                53,
            ),
            cls(
                Action.ALLOW,
                Direction.EGRESS,
                Destination.group(DestGroup.HOST),
                Protocol.TCP,
                53,
            ),
        )

@dataclass(frozen=True, slots=True)
class NetworkPolicy:
    """Custom network policy with rules.

    Mirrors Rust's `NetworkPolicy { default_egress, default_ingress, rules }`.
    The defaults are asymmetric to preserve today's behavior:
    egress falls through to deny (today's `public_only` reachability when
    paired with the implicit allow-public rule); ingress falls through
    to allow (today's unfiltered published-port behavior).
    """
    default_egress: Action = Action.DENY
    default_ingress: Action = Action.ALLOW
    rules: tuple[Rule, ...] = ()

    def _to_dict(self) -> dict:
        def destination_fields(destination: NetworkDestinationLike) -> dict:
            if destination is None:
                return {}
            if isinstance(destination, NetworkDestination):
                return destination._to_dict()
            return {"destination": str(destination)}

        d: dict = {
            "default_egress": str(self.default_egress),
            "default_ingress": str(self.default_ingress),
        }
        if self.rules:
            d["rules"] = [
                {
                    "action": str(r.action),
                    "direction": str(r.direction),
                    **destination_fields(r.destination),
                    **({"protocol": str(r.protocol)} if r.protocol else {}),
                    **({"port": str(r.port)} if r.port is not None else {}),
                }
                for r in self.rules
            ]
        return d

@dataclass(frozen=True, slots=True)
class TlsConfig:
    """TLS interception configuration."""
    bypass: tuple[str, ...] = ()
    verify_upstream: bool = True
    intercepted_ports: tuple[int, ...] = (443,)
    block_quic: bool = False
    ca_cert: str | None = None
    ca_key: str | None = None
    ca_cn: str | None = None

    def _to_dict(self) -> dict:
        d: dict = {}
        if self.bypass:
            d["bypass"] = list(self.bypass)
        if not self.verify_upstream:
            d["verify_upstream"] = False
        if self.intercepted_ports != (443,):
            d["intercepted_ports"] = list(self.intercepted_ports)
        if self.block_quic:
            d["block_quic"] = True
        if self.ca_cert is not None:
            d["ca_cert"] = self.ca_cert
        if self.ca_key is not None:
            d["ca_key"] = self.ca_key
        if self.ca_cn is not None:
            d["ca_cn"] = self.ca_cn
        return d

@dataclass(frozen=True, slots=True)
class DnsConfig:
    """DNS interception configuration."""
    rebind_protection: bool = True
    """Block DNS responses resolving to private IPs. Default: True."""
    nameservers: tuple[str, ...] = ()
    """Nameservers to forward queries to. Accepts IP, IP:PORT, HOST, or
    HOST:PORT. When set, overrides the host's /etc/resolv.conf."""
    query_timeout_ms: int | None = None
    """Per-DNS-query timeout in milliseconds. Default: 5000."""

    def _to_dict(self) -> dict:
        d: dict = {}
        if not self.rebind_protection:
            d["rebind_protection"] = False
        if self.nameservers:
            d["nameservers"] = list(self.nameservers)
        if self.query_timeout_ms is not None:
            d["query_timeout_ms"] = self.query_timeout_ms
        return d


@dataclass(frozen=True, slots=True)
class PortBinding:
    """Published host-to-guest port with an optional host bind address."""
    host_port: int
    guest_port: int
    bind: str = "127.0.0.1"
    protocol: PortProtocol = PortProtocol.TCP

    @classmethod
    def tcp(cls, host_port: int, guest_port: int, *, bind: str = "127.0.0.1") -> PortBinding:
        return cls(host_port=host_port, guest_port=guest_port, bind=bind, protocol=PortProtocol.TCP)

    @classmethod
    def udp(cls, host_port: int, guest_port: int, *, bind: str = "127.0.0.1") -> PortBinding:
        return cls(host_port=host_port, guest_port=guest_port, bind=bind, protocol=PortProtocol.UDP)

    def _to_dict(self) -> dict:
        return {
            "host_port": self.host_port,
            "guest_port": self.guest_port,
            "bind": self.bind,
            "protocol": self.protocol.value,
        }


@dataclass(frozen=True, slots=True)
class Network:
    """Network configuration for a sandbox."""
    policy: str | NetworkPolicy | None = None
    ports: Mapping[int, int] | Sequence[PortBinding] = field(default_factory=dict)
    deny_domains: tuple[str, ...] = ()
    """Deny egress to these exact domains. Each entry adds a
    `deny Domain("...")` policy rule that fires at DNS resolution
    (NXDOMAIN), TLS first-flight (SNI), and TCP egress (cache fallback).
    Prepended onto the policy so it takes precedence over later allow
    rules."""
    deny_domain_suffixes: tuple[str, ...] = ()
    """Deny egress to all subdomains of these suffixes. Same enforcement
    layers as `deny_domains`."""
    dns: DnsConfig | None = None
    tls: TlsConfig | None = None
    ipv4_pool: str | None = None
    """IPv4 pool used to derive per-sandbox /30 guest subnets. Defaults
    to ``172.16.0.0/12``."""
    ipv6_pool: str | None = None
    """IPv6 pool used to derive per-sandbox /64 guest prefixes. Defaults
    to ``fd42:6d73:62::/48``."""
    max_connections: int | None = None
    on_secret_violation: ViolationAction | ViolationPolicy = ViolationAction.BLOCK_AND_LOG

    @classmethod
    def none(cls) -> Network:
        return cls(policy="none")

    @classmethod
    def public_only(cls) -> Network:
        return cls(policy="public_only")

    @classmethod
    def allow_all(cls) -> Network:
        return cls(policy="allow_all")


    def _to_dict(self) -> dict:
        d: dict = {}
        if isinstance(self.policy, str):
            d["policy"] = self.policy
        elif isinstance(self.policy, NetworkPolicy):
            d["custom_policy"] = self.policy._to_dict()
        if self.ports:
            if isinstance(self.ports, Mapping):
                d["ports"] = dict(self.ports)
            else:
                d["ports"] = [p._to_dict() for p in self.ports]
        if self.deny_domains:
            d["deny_domains"] = list(self.deny_domains)
        if self.deny_domain_suffixes:
            d["deny_domain_suffixes"] = list(self.deny_domain_suffixes)
        if self.dns is not None:
            dns_dict = self.dns._to_dict()
            if dns_dict:
                d["dns"] = dns_dict
        if self.tls is not None:
            d["tls"] = self.tls._to_dict()
        if self.ipv4_pool is not None:
            d["ipv4_pool"] = self.ipv4_pool
        if self.ipv6_pool is not None:
            d["ipv6_pool"] = self.ipv6_pool
        if self.max_connections is not None:
            d["max_connections"] = self.max_connections
        violation = violation_policy_to_dict(self.on_secret_violation)
        if violation != str(ViolationAction.BLOCK_AND_LOG):
            d["on_secret_violation"] = violation
        return d


def violation_policy_to_dict(policy: ViolationAction | ViolationPolicy) -> str | dict:
    if isinstance(policy, ViolationPolicy):
        return policy._to_dict()
    return str(policy)

#--------------------------------------------------------------------------------------------------
# Types: Registry Auth
#--------------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class RegistryAuth:
    """Registry credentials for pulling private images."""
    username: str
    password: str

    @classmethod
    def basic(cls, username: str, password: str) -> RegistryAuth:
        return cls(username=username, password=password)

    def _to_dict(self) -> dict:
        return {"username": self.username, "password": self.password}
