"""Tests for Python-side types, enums, and dataclasses."""

from microsandbox import (
    Action,
    DestGroup,
    Direction,
    DiskImageFormat,
    ExecOptions,
    ExitStatus,
    FsEntryKind,
    GiB,
    Image,
    LogLevel,
    MiB,
    MountKind,
    Network,
    NetworkPolicy,
    Patch,
    PortProtocol,
    Protocol,
    PullPolicy,
    RegistryAuth,
    Rlimit,
    RlimitResource,
    Rule,
    SandboxStatus,
    Secret,
    Size,
    Stdin,
    TlsConfig,
    ViolationAction,
)
from microsandbox.events import (
    ExitedEvent,
    StartedEvent,
    StderrEvent,
    StdoutEvent,
)


def test_pull_policy_enum():
    assert PullPolicy.ALWAYS == "always"
    assert PullPolicy.IF_MISSING == "if-missing"
    assert PullPolicy.NEVER == "never"


def test_log_level_enum():
    assert LogLevel.DEBUG == "debug"
    assert LogLevel.INFO == "info"


def test_sandbox_status_enum():
    assert SandboxStatus.RUNNING == "running"
    assert SandboxStatus.STOPPED == "stopped"
    assert SandboxStatus.CRASHED == "crashed"
    assert SandboxStatus.DRAINING == "draining"
    assert SandboxStatus.PAUSED == "paused"


def test_action_enum():
    assert Action.ALLOW == "allow"
    assert Action.DENY == "deny"


def test_direction_enum():
    assert Direction.EGRESS == "egress"
    assert Direction.INGRESS == "ingress"


def test_protocol_enum():
    assert Protocol.TCP == "tcp"
    assert Protocol.UDP == "udp"
    assert Protocol.ICMPV4 == "icmpv4"


def test_port_protocol_enum():
    assert PortProtocol.TCP == "tcp"
    assert PortProtocol.UDP == "udp"


def test_dest_group_enum():
    assert DestGroup.LOOPBACK == "loopback"
    assert DestGroup.PRIVATE == "private"
    assert DestGroup.METADATA == "metadata"


def test_violation_action_enum():
    assert ViolationAction.BLOCK == "block"
    assert ViolationAction.BLOCK_AND_LOG == "block-and-log"
    assert ViolationAction.BLOCK_AND_TERMINATE == "block-and-terminate"


def test_mount_kind_enum():
    assert MountKind.BIND == "bind"
    assert MountKind.NAMED == "named"
    assert MountKind.TMPFS == "tmpfs"


def test_fs_entry_kind_enum():
    assert FsEntryKind.FILE == "file"
    assert FsEntryKind.DIRECTORY == "directory"
    assert FsEntryKind.SYMLINK == "symlink"


def test_disk_image_format_enum():
    assert DiskImageFormat.QCOW2 == "qcow2"
    assert DiskImageFormat.RAW == "raw"
    assert DiskImageFormat.VMDK == "vmdk"


def test_rlimit_resource_enum():
    assert RlimitResource.NOFILE == "nofile"
    assert RlimitResource.CPU == "cpu"
    assert RlimitResource.AS == "as"


def test_size():
    assert MiB == 1024 * 1024
    assert GiB == 1024 * 1024 * 1024
    s = Size.mib(512)
    assert s.bytes == 512 * MiB
    assert s.mib_count == 512
    s2 = Size.gib(2)
    assert s2.bytes == 2 * GiB
    assert s2.mib_count == 2048


def test_exit_status():
    s = ExitStatus(code=0, success=True)
    assert s.code == 0
    assert s.success


def test_rlimit_factories():
    r = Rlimit.nofile(1024)
    assert r.resource == RlimitResource.NOFILE
    assert r.soft == 1024
    assert r.hard == 1024

    r2 = Rlimit.as_(soft=512 * MiB, hard=1 * GiB)
    assert r2.resource == RlimitResource.AS
    assert r2.soft == 512 * MiB
    assert r2.hard == 1 * GiB


def test_stdin_modes():
    assert Stdin.null()._mode == "null"
    assert Stdin.pipe()._mode == "pipe"
    b = Stdin.bytes(b"hello")
    assert b._mode == "bytes"
    assert b._data == b"hello"


def test_exec_options():
    opts = ExecOptions(
        args=("compute.py",),
        cwd="/app",
        env={"KEY": "VAL"},
        timeout=30.0,
        tty=True,
    )
    d = opts._to_dict()
    assert d["args"] == ["compute.py"]
    assert d["cwd"] == "/app"
    assert d["env"] == {"KEY": "VAL"}
    assert d["timeout"] == 30.0
    assert d["tty"] is True


def test_exec_options_frozen():
    opts = ExecOptions(args=("a", "b"))
    try:
        opts.args = ("c",)  # type: ignore
        raise AssertionError("should be frozen")
    except AttributeError:
        pass


def test_patch_factories():
    p = Patch.text("/etc/conf", "data")
    assert p.kind == "text"
    assert p.path == "/etc/conf"
    assert p.content == "data"

    p2 = Patch.mkdir("/app", mode=0o755)
    assert p2.kind == "mkdir"
    assert p2.mode == 0o755

    p3 = Patch.copy_file("./src", "/app/src")
    assert p3.kind == "copy_file"
    assert p3.src == "./src"
    assert p3.dst == "/app/src"

    p4 = Patch.symlink("/usr/bin/python3", "/usr/bin/python")
    assert p4.kind == "symlink"

    p5 = Patch.remove("/etc/motd")
    assert p5.kind == "remove"

    p6 = Patch.append("/etc/hosts", "127.0.0.1 local\n")
    assert p6.kind == "append"

    p7 = Patch.copy_dir("./dir", "/app")
    assert p7.kind == "copy_dir"


def test_secret_factory():
    s = Secret.env(
        "OPENAI_API_KEY",
        value="sk-123",
        allow_hosts=["api.openai.com"],
        allow_host_patterns=["*.openai.com"],
    )
    assert s.env_var == "OPENAI_API_KEY"
    assert s.value == "sk-123"
    assert s.allow_hosts == ("api.openai.com",)
    assert s.allow_host_patterns == ("*.openai.com",)
    assert s.on_violation == ViolationAction.BLOCK_AND_LOG


def test_network_presets():
    n = Network.none()
    assert n.policy == "none"
    n2 = Network.public_only()
    assert n2.policy == "public_only"
    n3 = Network.allow_all()
    assert n3.policy == "allow_all"


def test_network_custom():
    n = Network(
        policy=NetworkPolicy(
            default_action=Action.DENY,
            rules=(Rule.allow(protocol=Protocol.TCP, port=443),),
        ),
        block_domains=("evil.com",),
        max_connections=128,
    )
    assert n.block_domains == ("evil.com",)
    assert n.max_connections == 128


def test_rule_factories():
    r = Rule.allow(protocol=Protocol.TCP, port=443)
    assert r.action == Action.ALLOW
    assert r.protocol == Protocol.TCP
    assert r.port == 443

    r2 = Rule.deny(destination="10.0.0.0/8")
    assert r2.action == Action.DENY
    assert r2.destination == "10.0.0.0/8"


def test_tls_config():
    t = TlsConfig(bypass=("pinned.example.com",), block_quic=True)
    assert t.bypass == ("pinned.example.com",)
    assert t.block_quic is True
    assert t.verify_upstream is True


def test_registry_auth():
    a = RegistryAuth.basic("user", "pass")
    assert a.username == "user"
    assert a.password == "pass"


def test_image_factories():
    oci = Image.oci("python:3.12")
    assert oci._type == "oci"
    assert oci._reference == "python:3.12"

    bind = Image.bind("./rootfs")
    assert bind._type == "bind"
    assert bind._path == "./rootfs"

    disk = Image.disk("./ubuntu.qcow2", fstype="ext4", format=DiskImageFormat.QCOW2)
    assert disk._type == "disk"
    assert disk._fstype == "ext4"
    assert disk._format == DiskImageFormat.QCOW2


def test_exec_event_types():
    s = StartedEvent(pid=42)
    assert s.pid == 42

    out = StdoutEvent(data=b"hello")
    assert out.data == b"hello"

    err = StderrEvent(data=b"err")
    assert err.data == b"err"

    ex = ExitedEvent(code=0)
    assert ex.code == 0


def test_exec_events_match():
    """Test that match/case works on exec events."""
    events = [
        StartedEvent(pid=1),
        StdoutEvent(data=b"out"),
        StderrEvent(data=b"err"),
        ExitedEvent(code=0),
    ]
    results = []
    for event in events:
        match event:
            case StartedEvent(pid=p):
                results.append(f"started:{p}")
            case StdoutEvent(data=d):
                results.append(f"stdout:{len(d)}")
            case StderrEvent(data=d):
                results.append(f"stderr:{len(d)}")
            case ExitedEvent(code=c):
                results.append(f"exited:{c}")

    assert results == ["started:1", "stdout:3", "stderr:3", "exited:0"]
