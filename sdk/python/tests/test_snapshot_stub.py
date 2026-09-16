"""Verify the typed single-archive and batch snapshot import contracts."""

from __future__ import annotations

import ast
from pathlib import Path


def test_batch_load_preserves_single_load_options_and_returns_handles() -> None:
    stub = Path(__file__).parent.parent / "microsandbox" / "_microsandbox.pyi"
    tree = ast.parse(stub.read_text())
    snapshot = next(
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Snapshot"
    )
    methods = {
        node.name: node for node in snapshot.body if isinstance(node, ast.AsyncFunctionDef)
    }
    single, batch = methods["load"], methods["load_many"]
    assert [arg.arg for arg in batch.args.args] == ["archives"]
    assert ast.unparse(batch.args.args[0].annotation) == "Sequence[str | os.PathLike[str]]"
    assert [arg.arg for arg in batch.args.kwonlyargs] == [
        arg.arg for arg in single.args.kwonlyargs
    ] == ["dest", "base", "group", "set_head"]
    assert [ast.dump(value) for value in batch.args.kw_defaults] == [
        ast.dump(value) for value in single.args.kw_defaults
    ]
    assert ast.unparse(single.returns) == "SnapshotHandle"
    assert ast.unparse(batch.returns) == "list[SnapshotHandle]"
