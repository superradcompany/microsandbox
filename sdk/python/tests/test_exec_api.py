"""Public API checks for Python command execution helpers."""

from __future__ import annotations

import inspect

from microsandbox import Sandbox


def _parameter_kinds(method):
    return {name: param.kind for name, param in inspect.signature(method).parameters.items()}


def test_exec_accepts_positional_args_and_keyword_options():
    kinds = _parameter_kinds(Sandbox.exec)

    assert kinds["cmd"] is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert kinds["args"] is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert kinds["cwd"] is inspect.Parameter.KEYWORD_ONLY
    assert kinds["user"] is inspect.Parameter.KEYWORD_ONLY
    assert kinds["env"] is inspect.Parameter.KEYWORD_ONLY
    assert kinds["timeout"] is inspect.Parameter.KEYWORD_ONLY
    assert kinds["stdin"] is inspect.Parameter.KEYWORD_ONLY
    assert kinds["stdin_data"] is inspect.Parameter.KEYWORD_ONLY
    assert kinds["tty"] is inspect.Parameter.KEYWORD_ONLY
    assert kinds["rlimits"] is inspect.Parameter.KEYWORD_ONLY


def test_exec_stream_accepts_positional_args_and_keyword_options():
    assert _parameter_kinds(Sandbox.exec_stream) == _parameter_kinds(Sandbox.exec)


def test_attach_accepts_positional_args_and_keyword_options():
    kinds = _parameter_kinds(Sandbox.attach)

    assert kinds["cmd"] is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert kinds["args"] is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert kinds["cwd"] is inspect.Parameter.KEYWORD_ONLY
    assert kinds["user"] is inspect.Parameter.KEYWORD_ONLY
    assert kinds["env"] is inspect.Parameter.KEYWORD_ONLY
    assert kinds["detach_keys"] is inspect.Parameter.KEYWORD_ONLY
    assert kinds["rlimits"] is inspect.Parameter.KEYWORD_ONLY
