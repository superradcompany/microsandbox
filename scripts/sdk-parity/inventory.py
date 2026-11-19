#!/usr/bin/env python3
"""Inventory declarations separately from execution evidence; never infer parity from names.

The old source checkout and rustdoc JSON are explicit inputs. The output includes
types and fields so options cannot disappear merely because they are not methods.
Runtime reflection is used for Ruby's generated native API. External Rust exports
remain visible as unexpanded entries rather than silently disappearing.
"""

import argparse
import ast
import csv
import json
import subprocess
from pathlib import Path


def python_inventory(root):
    rows = []
    for file in (root / "sdk/python/microsandbox").glob("*"):
        if file.suffix not in (".py", ".pyi"):
            continue
        tree = ast.parse(file.read_text())

        def visit(nodes, owner="", file=file):
            for node in nodes:
                if isinstance(node, ast.ClassDef):
                    if node.name.startswith("_"):
                        continue
                    name = f"{owner}.{node.name}".strip(".")
                    rows.append(
                        {
                            "symbol": name,
                            "kind": "type",
                            "file": str(file.relative_to(root)),
                            "line": node.lineno,
                        }
                    )
                    visit(node.body, name)
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.name.startswith("_") and node.name not in (
                        "__init__",
                        "__enter__",
                        "__exit__",
                        "__aenter__",
                        "__aexit__",
                        "__aiter__",
                        "__anext__",
                    ):
                        continue
                    rows.append(
                        {
                            "symbol": f"{owner}.{node.name}".strip("."),
                            "kind": "property"
                            if any(
                                isinstance(d, ast.Name) and d.id == "property"
                                for d in node.decorator_list
                            )
                            else "callable",
                            "file": str(file.relative_to(root)),
                            "line": node.lineno,
                        }
                    )
                elif (
                    owner
                    and isinstance(node, ast.AnnAssign)
                    and isinstance(node.target, ast.Name)
                    and not node.target.id.startswith("_")
                ):
                    rows.append(
                        {
                            "symbol": f"{owner}.{node.target.id}",
                            "kind": "property",
                            "file": str(file.relative_to(root)),
                            "line": node.lineno,
                        }
                    )

        visit(tree.body)
    return rows


def rust_inventory(file):
    doc = json.loads(file.read_text())
    index = doc["index"]
    rows = []

    def emit(item, symbol, kind):
        span = item.get("span") or {}
        rows.append(
            {
                "symbol": symbol,
                "kind": kind,
                "file": span.get("filename", ""),
                "line": span.get("begin", [0])[0],
            }
        )

    for key, path in doc["paths"].items():
        if path["crate_id"] != 0:
            continue
        item = index.get(key)
        if not item:
            continue
        symbol = "::".join(path["path"][1:])
        inner = item["inner"]
        if "function" in inner:
            if item["visibility"] == "public":
                emit(item, symbol, "callable")
        elif path["kind"] in ("struct", "enum", "union", "trait", "type_alias"):
            emit(item, symbol, "type")
            definition = inner.get(path["kind"], {})
            for impl_id in definition.get("impls", []):
                impl = index.get(str(impl_id), {}).get("inner", {}).get("impl", {})
                # Standard/derived trait implementations are not extra SDK entry points.
                if impl.get("trait") is not None:
                    continue
                for member_id in impl.get("items", []):
                    member = index[str(member_id)]
                    if member["visibility"] == "public":
                        emit(
                            member,
                            f"{symbol}::{member['name']}",
                            "callable"
                            if "function" in member["inner"]
                            else "associated_value",
                        )
            for member_id in definition.get("items", []):
                member = index[str(member_id)]
                emit(member, f"{symbol}::{member['name']}", "trait_member")
            fields = (
                definition.get("kind", {}).get("plain", {}).get("fields", [])
                if isinstance(definition.get("kind"), dict)
                else []
            )
            for field_id in fields:
                field = index[str(field_id)]
                if field["visibility"] == "public":
                    emit(field, f"{symbol}::{field['name']}", "property")
    for item in index.values():
        use = item["inner"].get("use")
        if use and item["visibility"] == "public" and str(use.get("id")) not in index:
            emit(item, use["source"], "external_reexport_unexpanded")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old-source", type=Path, required=True)
    parser.add_argument("--new-source", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    rows = []
    for phase, root in [("old", args.old_source), ("new", args.new_source)]:
        groups = {
            "Python": python_inventory(root),
            "Rust": rust_inventory(args.evidence / f"rust-{phase}-public.json"),
        }
        groups["TypeScript"] = json.loads(
            subprocess.check_output(
                [
                    "node",
                    str(here / "inventory-ts.mjs"),
                    str(root / "sdk/node-ts"),
                    str(args.new_source / "sdk/node-ts"),
                ]
            )
        )
        groups["Go"] = json.loads(
            subprocess.check_output(
                ["go", "run", str(here / "inventory-go.go"), str(root / "sdk/go")]
            )
        )
        groups["Ruby"] = json.loads(
            (args.evidence / f"ruby-{phase}-public.json").read_text()
        )
        for language, entries in groups.items():
            seen = set()
            for entry in entries:
                key = (entry["symbol"], entry["kind"])
                if key in seen:
                    continue
                seen.add(key)
                rows.append(dict(sdk=language, phase=phase, **entry))
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "public-api.json").write_text(json.dumps(rows, indent=2) + "\n")
    with (args.out / "public-api.csv").open("w") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=["sdk", "phase", "symbol", "kind", "file", "line"]
        )
        writer.writeheader()
        writer.writerows(rows)
    print(
        json.dumps(
            {
                sdk: {
                    phase: sum(r["sdk"] == sdk and r["phase"] == phase for r in rows)
                    for phase in ("old", "new")
                }
                for sdk in sorted({r["sdk"] for r in rows})
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
