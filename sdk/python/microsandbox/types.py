"""Frozen dataclasses for all configuration and result types."""

from __future__ import annotations

import enum
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

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

class Protocol(enum.StrEnum):
    TCP = "tcp"
    UDP = "udp"
    ICMPV4 = "icmpv4"
    ICMPV6 = "icmpv6"

class PortProtocol(enum.StrEnum):
    TCP = "tcp"
    UDP = "udp"

class DestGroup(enum.StrEnum):
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

class MountKind(enum.StrEnum):
    BIND = "bind"
    NAMED = "named"
    TMPFS = "tmpfs"
    DISK = "disk"

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
# Types: Exec
#--------------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class ExecOptions:
    """Full execution options (passed as second positional to exec/exec_stream)."""
    args: tuple[str, ...] = ()
    cwd: str | None = None
    user: str | None = None
    env: Mapping[str, str] = field(default_factory=dict)
    timeout: float | None = None
    stdin: Stdin = field(default_factory=Stdin.null)
    tty: bool = False
    rlimits: tuple[Rlimit, ...] = ()

    def _to_dict(self) -> dict:
        d: dict = {"args": list(self.args)}
        if self.cwd is not None:
            d["cwd"] = self.cwd
        if self.user is not None:
            d["user"] = self.user
        if self.env:
            d["env"] = dict(self.env)
        if self.timeout is not None:
            d["timeout"] = self.timeout
        if self.tty:
            d["tty"] = True
        if self.stdin._mode != "null":
            d["stdin"] = self.stdin._mode
            if self.stdin._data is not None:
                d["stdin_data"] = self.stdin._data
        if self.rlimits:
            d["rlimits"] = [
                {"resource": str(r.resource), "soft": r.soft, "hard": r.hard}
                for r in self.rlimits
            ]
        return d

#--------------------------------------------------------------------------------------------------
# Types: Attach
#--------------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class AttachOptions:
    """Full options for attach (passed as second positional to attach)."""
    args: tuple[str, ...] = ()
    cwd: str | None = None
    user: str | None = None
    env: Mapping[str, str] = field(default_factory=dict)
    detach_keys: str | None = None

    def _to_dict(self) -> dict:
        d: dict = {"args": list(self.args)}
        if self.cwd is not None:
            d["cwd"] = self.cwd
        if self.user is not None:
            d["user"] = self.user
        if self.env:
            d["env"] = dict(self.env)
        if self.detach_keys is not None:
            d["detach_keys"] = self.detach_keys
        return d

#--------------------------------------------------------------------------------------------------
# Types: Mount
#--------------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class MountConfig:
    """Volume mount configuration."""
    kind: MountKind
    bind: str | None = None
    named: str | None = None
    size_mib: int | None = None
    readonly: bool = False
    disk: str | None = None
    format: DiskImageFormat | None = None
    fstype: str | None = None

    def _to_dict(self) -> dict:
        # Drive emission off `kind` exclusively so a `MountConfig` with
        # contradictory fields (e.g. kind=DISK + bind=...) raises here
        # rather than silently letting the wrong arm of `apply_mount` win.
        d: dict = {"readonly": self.readonly}
        if self.kind == MountKind.BIND:
            if self.bind is None:
                raise ValueError("MountConfig kind=BIND requires bind=...")
            d["bind"] = self.bind
        elif self.kind == MountKind.NAMED:
            if self.named is None:
                raise ValueError("MountConfig kind=NAMED requires named=...")
            d["named"] = self.named
        elif self.kind == MountKind.TMPFS:
            d["tmpfs"] = True
            if self.size_mib is not None:
                d["size_mib"] = self.size_mib
        elif self.kind == MountKind.DISK:
            if self.disk is None:
                raise ValueError("MountConfig kind=DISK requires disk=...")
            d["disk"] = self.disk
            if self.format is not None:
                d["format"] = self.format.value
            if self.fstype is not None:
                d["fstype"] = self.fstype
        else:  # pragma: no cover - StrEnum exhaustive above
            raise ValueError(f"unknown MountKind: {self.kind!r}")
        return d

#--------------------------------------------------------------------------------------------------
# Types: Image
#--------------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class ImageSource:
    """Explicit rootfs image source."""
    _type: str
    _path: str | None = None
    _reference: str | None = None
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
    def oci(reference: str) -> ImageSource:
        return ImageSource(_type="oci", _reference=reference)

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
class SecretEntry:
    """A secret entry for the secrets array."""
    env_var: str
    value: str
    allow_hosts: tuple[str, ...] = ()
    allow_host_patterns: tuple[str, ...] = ()
    placeholder: str | None = None
    require_tls: bool = True
    on_violation: ViolationAction = ViolationAction.BLOCK_AND_LOG

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
        if self.on_violation != ViolationAction.BLOCK_AND_LOG:
            d["on_violation"] = str(self.on_violation)
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
        on_violation: ViolationAction = ViolationAction.BLOCK_AND_LOG,
    ) -> SecretEntry:
        return SecretEntry(
            env_var=env_var,
            value=value,
            allow_hosts=tuple(allow_hosts),
            allow_host_patterns=tuple(allow_host_patterns),
            placeholder=placeholder,
            require_tls=require_tls,
            on_violation=on_violation,
        )

#--------------------------------------------------------------------------------------------------
# Types: Network
#--------------------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Rule:
    """A network policy rule."""
    action: Action
    direction: Direction = Direction.EGRESS
    destination: str | None = None
    protocol: Protocol | None = None
    port: int | str | None = None

    @classmethod
    def allow(cls, *, direction: Direction = Direction.EGRESS, protocol: Protocol | None = None,
              port: int | str | None = None, destination: str | None = None) -> Rule:
        return cls(Action.ALLOW, direction, destination, protocol, port)

    @classmethod
    def deny(cls, *, direction: Direction = Direction.EGRESS, protocol: Protocol | None = None,
             port: int | str | None = None, destination: str | None = None) -> Rule:
        return cls(Action.DENY, direction, destination, protocol, port)

@dataclass(frozen=True, slots=True)
class NetworkPolicy:
    """Custom network policy with rules. Mirrors Rust's NetworkPolicy { default_action, rules }."""
    default_action: Action = Action.ALLOW
    rules: tuple[Rule, ...] = ()

    def _to_dict(self) -> dict:
        d: dict = {"default_action": str(self.default_action)}
        if self.rules:
            d["rules"] = [
                {
                    "action": str(r.action),
                    "direction": str(r.direction),
                    **({"destination": r.destination} if r.destination else {}),
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
    block_domains: tuple[str, ...] = ()
    """Block DNS lookups for exact domains (returns REFUSED)."""
    block_domain_suffixes: tuple[str, ...] = ()
    """Block DNS lookups for all subdomains of a suffix."""
    rebind_protection: bool = True
    """Block DNS responses resolving to private IPs. Default: True."""
    nameservers: tuple[str, ...] = ()
    """Nameservers to forward queries to. Accepts IP, IP:PORT, HOST, or
    HOST:PORT. When set, overrides the host's /etc/resolv.conf."""
    query_timeout_ms: int | None = None
    """Per-DNS-query timeout in milliseconds. Default: 5000."""

    def _to_dict(self) -> dict:
        d: dict = {}
        if self.block_domains:
            d["blocked_domains"] = list(self.block_domains)
        if self.block_domain_suffixes:
            d["blocked_suffixes"] = list(self.block_domain_suffixes)
        if not self.rebind_protection:
            d["rebind_protection"] = False
        if self.nameservers:
            d["nameservers"] = list(self.nameservers)
        if self.query_timeout_ms is not None:
            d["query_timeout_ms"] = self.query_timeout_ms
        return d


@dataclass(frozen=True, slots=True)
class Network:
    """Network configuration for a sandbox."""
    policy: str | NetworkPolicy | None = None
    ports: Mapping[int, int] = field(default_factory=dict)
    dns: DnsConfig | None = None
    tls: TlsConfig | None = None
    max_connections: int | None = None

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
            d["ports"] = dict(self.ports)
        if self.dns is not None:
            dns_dict = self.dns._to_dict()
            if dns_dict:
                d["dns"] = dns_dict
        if self.tls is not None:
            d["tls"] = self.tls._to_dict()
        if self.max_connections is not None:
            d["max_connections"] = self.max_connections
        return d

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
