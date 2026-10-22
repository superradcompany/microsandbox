"""The operation-bound surface keeps existing modification results intact."""

import ast
from pathlib import Path

from microsandbox import ResizeObservation, ResizeOutcome, ResourceKind


def test_operation_types_are_json_compatible():
    import json

    assert json.loads(json.dumps({
        "outcome": ResizeOutcome.PENDING,
        "observation": ResizeObservation.PAUSED,
        "resource": ResourceKind.MEMORY,
    })) == {"outcome": "pending", "observation": "paused", "resource": "memory"}


def test_tracking_stub_preserves_modify_options_and_result():
    path = Path(__file__).parents[1] / "microsandbox" / "_microsandbox.pyi"
    tree = ast.parse(path.read_text())
    for cls in (n for n in tree.body if isinstance(n, ast.ClassDef)
                and n.name in {"Sandbox", "SandboxHandle"}):
        methods = {n.name: n for n in cls.body if isinstance(n, ast.AsyncFunctionDef)}
        original = methods["modify"]
        tracked = methods["modify_with_resize_tracking"]
        assert ast.dump(original.args) == ast.dump(tracked.args)
        assert ast.unparse(original.returns) == "SandboxModificationPlan"
        assert ast.unparse(tracked.returns) == "SandboxModificationResult"
        wait = methods["wait_for_resize_operations"]
        assert [a.arg for a in wait.args.args] == ["self", "operations"]
        assert [a.arg for a in wait.args.kwonlyargs] == ["timeout"]
