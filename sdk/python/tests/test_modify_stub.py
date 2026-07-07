"""Unit tests for the sandbox modify stub surface."""

from __future__ import annotations

import ast
from pathlib import Path

STUB_PATH = Path(__file__).parent.parent / "microsandbox" / "_microsandbox.pyi"

EXPECTED_KWARGS = [
    "cpus",
    "max_cpus",
    "memory",
    "max_memory",
    "env",
    "env_rm",
    "labels",
    "labels_rm",
    "workdir",
    "secrets",
    "secrets_rm",
    "policy",
    "dry_run",
]


def _class_method(tree: ast.Module, class_name: str, method_name: str) -> ast.AsyncFunctionDef:
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for item in node.body:
                if isinstance(item, ast.AsyncFunctionDef) and item.name == method_name:
                    return item
            raise AssertionError(f"{class_name}.{method_name} missing from stub")
    raise AssertionError(f"class {class_name} missing from stub")


def _stub_tree() -> ast.Module:
    return ast.parse(STUB_PATH.read_text())


def test_secret_modify_spec_stub_keys() -> None:
    tree = _stub_tree()
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "SecretModifySpec":
            keys = [
                item.target.id
                for item in node.body
                if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name)
            ]
            assert keys == ["env", "value", "store", "placeholder", "allowed_hosts"]
            return
    raise AssertionError("SecretModifySpec missing from stub")


def test_sandbox_modify_stub_signature() -> None:
    tree = _stub_tree()
    for class_name in ("Sandbox", "SandboxHandle"):
        method = _class_method(tree, class_name, "modify")
        kwargs = [arg.arg for arg in method.args.kwonlyargs]
        assert kwargs == EXPECTED_KWARGS
        # All modify kwargs are optional.
        assert len(method.args.kw_defaults) == len(kwargs)
        assert all(default is not None for default in method.args.kw_defaults)
        # Returns the parsed plan JSON as a dict.
        assert isinstance(method.returns, ast.Subscript)
        assert isinstance(method.returns.value, ast.Name)
        assert method.returns.value.id == "dict"
