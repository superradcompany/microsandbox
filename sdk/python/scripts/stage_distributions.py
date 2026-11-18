"""Build provider wheels from shared wrapper sources and prebuilt native libraries.

No build-time or installation-time runtime download occurs. Native artifacts must
be compiled with provider-package and exactly one backend; the installed loader
validates the ABI, version and capability before constructing resources.
"""

import argparse
import ast
import base64
import csv
import hashlib
import io
import zipfile
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[1]
VERSION = tomllib.loads((ROOT.parents[1] / "Cargo.toml").read_text())["workspace"]["package"][
    "version"
]


def wheel(output, name, files, *, tag="py3-none-any", dependencies=(), entry_points=None):
    normalized = name.replace("-", "_")
    dist = f"{normalized}-{VERSION}.dist-info"
    files = dict(files)
    files[f"{dist}/METADATA"] = (
        f"Metadata-Version: 2.3\nName: {name}\nVersion: {VERSION}\nRequires-Python: >=3.10\n"
        + "".join(f"Requires-Dist: {dependency}\n" for dependency in dependencies)
        + "\n"
    ).encode()
    files[f"{dist}/WHEEL"] = (
        "Wheel-Version: 1.0\nGenerator: microsandbox-provider-staging\n"
        f"Root-Is-Purelib: {str(tag == 'py3-none-any').lower()}\nTag: {tag}\n"
    ).encode()
    if entry_points:
        files[f"{dist}/entry_points.txt"] = entry_points.encode()
    record = io.StringIO(newline="")
    writer = csv.writer(record)
    for path, data in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        writer.writerow((path, f"sha256={digest}", len(data)))
    writer.writerow((f"{dist}/RECORD", "", ""))
    files[f"{dist}/RECORD"] = record.getvalue().encode()
    destination = output / f"{normalized}-{VERSION}-{tag}.whl"
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, data in sorted(files.items()):
            info = zipfile.ZipInfo(path)
            # Preserve runtime executability in the optional full wheel. Lean
            # providers never contain this directory or console entry points.
            info.external_attr = (0o100755 if "/_bundled/bin/" in path else 0o100644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    return destination


def core_files():
    files = {}
    for source in (ROOT / "microsandbox").rglob("*"):
        if source.suffix not in (".py", ".pyi") and source.name != "py.typed":
            continue
        relative = source.relative_to(ROOT / "microsandbox")
        if any(part.startswith("__pycache__") or part == "_bundled" for part in relative.parts):
            continue
        if relative.name in ("_cli.py", "_runtime.py"):
            continue
        text = source.read_text()
        if relative.name == "__init__.py" and len(relative.parts) == 1:
            # Package discovery belongs to the full distribution, not the common
            # API. Remove only these known statements; keep all public exports.
            tree = ast.parse(text)
            lines = text.splitlines(keepends=True)
            removals = []
            for node in tree.body:
                if isinstance(node, ast.ImportFrom) and any(
                    alias.asname in ("_set_packaged_msb_path", "_msb_path") for alias in node.names
                ):
                    removals.append((node.lineno - 1, node.end_lineno))
                if isinstance(node, ast.Assign) and any(
                    isinstance(target, ast.Name) and target.id == "_bundled_msb"
                    for target in node.targets
                ):
                    removals.append((node.lineno - 1, node.end_lineno))
                if isinstance(node, ast.If) and "_bundled_msb" in ast.unparse(node.test):
                    removals.append((node.lineno - 1, node.end_lineno))
            for start, end in reversed(removals):
                del lines[start:end]
            text = "".join(lines)
        text = text.replace("microsandbox.", "microsandbox_core.").replace(
            "from microsandbox import", "from microsandbox_core import"
        )
        text = text.replace("._microsandbox", "._native").replace(
            "import _microsandbox", "import _native"
        )
        if relative.name == "_microsandbox.pyi":
            relative = relative.with_name("_native.pyi")
        files[f"microsandbox_core/{relative}"] = text.encode()
    tree = ast.parse((ROOT / "microsandbox/_microsandbox.pyi").read_text())
    classes = {
        node.name: [
            method.name
            for method in node.body
            if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
            and method.name.startswith("__")
            and method.name not in ("__init__", "__new__", "__repr__")
        ]
        for node in tree.body
        if isinstance(node, ast.ClassDef)
    }
    functions = [
        node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    functions += ["set_runtime_libkrunfw_path"]
    files["microsandbox_core/_schema.py"] = (
        f"VERSION = {VERSION!r}\nCLASSES = {classes!r}\nFUNCTIONS = {functions!r}\n".encode()
    )
    files["microsandbox_core/_native.py"] = (ROOT / "provider_core/native.py").read_bytes()
    return files


def full_wrapper_files():
    files = {}
    for source in (ROOT / "microsandbox").glob("*.py"):
        if source.name == "__init__.py":
            continue
        text = (
            source.read_text()
            if source.name in ("_runtime.py", "_cli.py")
            else f"from microsandbox_core.{source.stem} import *\n"
        )
        if source.stem == "inspection":
            # The full native extension resolves the decoder through this wrapper.
            text += "from microsandbox_core.inspection import _decode_config\n"
        if source.stem == "jobs":
            # Native full bindings use these private decoders too. A wildcard
            # import alone omits them, breaking successful job responses.
            text += (
                "from microsandbox_core.jobs import _decode_info, _decode_exit, "
                "_decode_log, _decode_logs, _decode_page, _decode_event\n"
            )
        files[f"microsandbox/{source.name}"] = text.encode()
    files["microsandbox/__init__.py"] = (
        "from microsandbox_core import *\nfrom microsandbox_core import __all__\n"
        "from microsandbox_core._native import register_full_provider as _register\n"
        f"_register('microsandbox._microsandbox', {VERSION!r})\n"
        "from ._runtime import msb_path as _msb_path\n"
        "from ._microsandbox import set_packaged_msb_path as _set_packaged\n"
        "_set_packaged(str(_msb_path()))\n"
    ).encode()
    files["microsandbox/__init__.pyi"] = b"from microsandbox_core import *\n"
    files["microsandbox/py.typed"] = b""
    files["microsandbox/_bundled/__init__.py"] = b""
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--local-binding", type=Path)
    parser.add_argument("--remote-binding", type=Path)
    parser.add_argument("--full-binding", type=Path)
    parser.add_argument(
        "--full-runtime-dir",
        type=Path,
        help="Complete runtime bin/lib directory for the existing full distribution",
    )
    parser.add_argument(
        "--platform", help="Wheel platform tag matching the supplied native artifacts"
    )
    args = parser.parse_args()
    if (args.local_binding or args.remote_binding or args.full_binding) and not args.platform:
        parser.error("--platform is required with native artifacts")
    if bool(args.full_binding) != bool(args.full_runtime_dir):
        parser.error("--full-binding and --full-runtime-dir must be supplied together")
    args.out.mkdir(parents=True, exist_ok=True)
    print(wheel(args.out, "microsandbox-core", core_files()))
    for kind in ("local", "remote"):
        artifact = getattr(args, f"{kind}_binding")
        if artifact is None:
            continue
        package = f"microsandbox_{kind}"
        module = f"_microsandbox_{kind}"
        extension = ".pyd" if args.platform.startswith("win") else ".abi3.so"
        files = {
            f"{package}/__init__.py": (
                f"from microsandbox_core import *\nfrom microsandbox_core import __all__\n"
                f"from microsandbox_core._native import register_provider as _register\n"
                f"_register({kind!r}, {f'{package}.{module}'!r}, {VERSION!r})\n"
            ).encode(),
            f"{package}/__init__.pyi": b"from microsandbox_core import *\n",
            f"{package}/py.typed": b"",
            f"{package}/{module}{extension}": artifact.read_bytes(),
        }
        print(
            wheel(
                args.out,
                f"microsandbox-{kind}",
                files,
                tag=f"cp310-abi3-{args.platform}",
                dependencies=(f"microsandbox-core=={VERSION}",),
            )
        )
    if args.full_binding:
        runtime = args.full_runtime_dir
        executable = "msb.exe" if args.platform.startswith("win") else "msb"
        if not (runtime / "bin" / executable).is_file() or not any(
            (runtime / "lib").glob("*krunfw*")
        ):
            parser.error("full runtime directory must include msb and libkrunfw")
        files = full_wrapper_files()
        extension = ".pyd" if args.platform.startswith("win") else ".abi3.so"
        files[f"microsandbox/_microsandbox{extension}"] = args.full_binding.read_bytes()
        for source in [runtime / "bin" / executable, *(runtime / "lib").glob("*krunfw*")]:
            if source.is_file():
                files[f"microsandbox/_bundled/{source.relative_to(runtime)}"] = source.read_bytes()
        print(
            wheel(
                args.out,
                "microsandbox",
                files,
                tag=f"cp310-abi3-{args.platform}",
                dependencies=(f"microsandbox-core=={VERSION}",),
                entry_points=(
                    "[console_scripts]\nmicrosandbox = microsandbox._cli:main\n"
                    "msb = microsandbox._cli:main\n"
                ),
            )
        )


if __name__ == "__main__":
    main()
