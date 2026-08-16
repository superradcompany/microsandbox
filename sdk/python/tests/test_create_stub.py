"""Unit tests for the explicit sandbox creation stub surface."""

from __future__ import annotations

import ast
from pathlib import Path

STUB_PATH = Path(__file__).parent.parent / "microsandbox" / "_microsandbox.pyi"

EXPECTED_KWARGS = [
    "image",
    "from_snapshot",
    "memory",
    "cpus",
    "max_memory",
    "max_cpus",
    "workdir",
    "shell",
    "security",
    "hostname",
    "user",
    "entrypoint",
    "cmd",
    "init",
    "replace",
    "replace_with_timeout",
    "max_duration",
    "idle_timeout",
    "ephemeral",
    "env",
    "labels",
    "scripts",
    "pull_policy",
    "log_level",
    "registry_auth",
    "registry_insecure",
    "registry_ca_certs",
    "volumes",
    "patches",
    "ports",
    "vsock",
    "network",
    "secrets",
    "on_secret_violation",
    "detached",
]


def _sandbox_class() -> ast.ClassDef:
    tree = ast.parse(STUB_PATH.read_text())
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "Sandbox":
            return node
    raise AssertionError("Sandbox missing from stub")


def _method(name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    for node in _sandbox_class().body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError(f"Sandbox.{name} missing from stub")


def test_create_methods_have_explicit_keyword_only_contracts() -> None:
    create = _method("create")
    create_with_progress = _method("create_with_progress")

    assert isinstance(create, ast.AsyncFunctionDef)
    assert isinstance(create_with_progress, ast.FunctionDef)
    for method in (create, create_with_progress):
        assert method.args.kwarg is None
        assert [arg.arg for arg in method.args.kwonlyargs] == EXPECTED_KWARGS
        assert all(default is not None for default in method.args.kw_defaults)


def test_create_closed_values_are_precisely_typed() -> None:
    create = _method("create")
    annotations = {
        arg.arg: ast.unparse(arg.annotation)
        for arg in create.args.kwonlyargs
        if arg.annotation is not None
    }

    assert annotations["security"] == "SecurityProfile | None"
    assert annotations["init"] == "str | InitConfig | InitOptions | None"
    assert annotations["pull_policy"] == "PullPolicy | None"
    assert annotations["log_level"] == "LogLevel | None"
    assert annotations["registry_auth"] == "RegistryAuth | None"
    assert annotations["registry_insecure"] == "bool"
    assert (
        annotations["registry_ca_certs"]
        == "list[bytes | bytearray | str | os.PathLike[str]] | None"
    )
    assert annotations["volumes"] == "Mapping[str, MountConfig] | None"
    assert annotations["patches"] == "Sequence[PatchConfig] | None"
    assert annotations["network"] == "Network | None"


def test_default_workload_methods_have_explicit_keyword_only_contracts() -> None:
    exec_default = _method("exec_default")
    exec_default_stream = _method("exec_default_stream")
    attach_default = _method("attach_default")

    for method in (exec_default, exec_default_stream, attach_default):
        assert isinstance(method, ast.AsyncFunctionDef)
        assert method.args.kwarg is None
        assert method.args.args[0].arg == "self"

    assert [arg.arg for arg in exec_default.args.kwonlyargs] == [
        "cwd",
        "user",
        "env",
        "timeout",
        "stdin",
        "tty",
        "rlimits",
    ]
    assert [arg.arg for arg in exec_default_stream.args.kwonlyargs] == [
        "cwd",
        "user",
        "env",
        "timeout",
        "stdin",
        "tty",
        "rlimits",
    ]
    assert [arg.arg for arg in attach_default.args.kwonlyargs] == [
        "cwd",
        "user",
        "env",
        "detach_keys",
    ]
