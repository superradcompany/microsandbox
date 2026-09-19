"""Stop's explicit budget remains distinct from indefinite graceful completion."""

import ast
from pathlib import Path

import pytest

from microsandbox import MicrosandboxError, StopTimeoutError


@pytest.mark.parametrize("class_name", ["Sandbox", "SandboxHandle"])
def test_stub_has_indefinite_and_explicit_timeout_methods(class_name):
    source = Path(__file__).parent.parent / "microsandbox" / "_microsandbox.pyi"
    cls = next(node for node in ast.parse(source.read_text()).body
               if isinstance(node, ast.ClassDef) and node.name == class_name)
    methods = {node.name: node for node in cls.body if isinstance(node, ast.AsyncFunctionDef)}
    assert ast.literal_eval(methods["stop"].args.defaults[0]) is None
    assert [arg.arg for arg in methods["stop_with_timeout"].args.args] == ["self", "timeout"]
    assert not methods["stop_with_timeout"].args.defaults


def test_timeout_is_a_distinct_typed_error():
    error = StopTimeoutError("graceful completion expired; no kill requested")
    assert isinstance(error, MicrosandboxError)
    assert isinstance(error, TimeoutError)
    assert error.code == "stop-timeout"
