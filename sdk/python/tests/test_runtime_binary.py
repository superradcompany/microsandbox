"""Exercise native pair resolution and the wheel CLI in isolated processes."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from microsandbox import _microsandbox as native

MSB = "msb.exe" if os.name == "nt" else "msb"
LIBRARY = (
    "libkrunfw.5.dylib"
    if sys.platform == "darwin"
    else "libkrunfw.dll"
    if os.name == "nt"
    else "libkrunfw.so.5.6.1"
)


def pair(root: Path, marker: str = "runtime") -> Path:
    (root / "bin").mkdir(parents=True, exist_ok=True)
    (root / "lib").mkdir(parents=True, exist_ok=True)
    msb = root / "bin" / MSB
    msb.write_text(f"#!/bin/sh\nprintf '{marker}:%s\\n' \"$*\"\n")
    msb.chmod(0o755)
    (root / "lib" / LIBRARY).write_bytes(b"fixture library")
    return msb


@pytest.fixture
def runtime_fixture(tmp_path):
    # Copy the Python layer but reuse the freshly built extension. Each child
    # imports a real wheel layout, so package auto-registration is exercised.
    import microsandbox

    package = tmp_path / "microsandbox"
    shutil.copytree(
        Path(microsandbox.__file__).parent,
        package,
        ignore=shutil.ignore_patterns("*.so", "*.pyd", "__pycache__", "_bundled"),
    )
    (package / Path(native.__file__).name).symlink_to(native.__file__)
    bundled = pair(package / "_bundled", "package")
    env = os.environ.copy()
    for name in ("MSB_PATH", "MSB_LIBKRUNFW_PATH", "MSB_HOME", "MSB_CONFIG_PATH"):
        env.pop(name, None)
    env.update(HOME=str(tmp_path), USERPROFILE=str(tmp_path), PYTHONPATH=str(tmp_path))
    return tmp_path, package, bundled, env


def resolve(root, env, before=""):
    script = (
        "from microsandbox import _microsandbox as native; "
        + before
        + "print(native.resolved_cli_msb_path())"
    )
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


@pytest.mark.parametrize("home_mode", ["default", "empty", "custom", "configured"])
def test_home_precedes_wheel(runtime_fixture, home_mode):
    root, _, _, env = runtime_fixture
    home = root / ".microsandbox"
    if home_mode == "custom":
        home = root / "custom"
        env["MSB_HOME"] = str(home)
    elif home_mode == "empty":
        env["MSB_HOME"] = ""
    elif home_mode == "configured":
        home = root / "configured"
        config = root / "config.json"
        config.write_text(json.dumps({"home": str(home)}))
        env["MSB_CONFIG_PATH"] = str(config)
    expected = pair(home, "older")
    result = resolve(root, env)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(expected)


def test_absent_home_uses_wheel_without_installing(runtime_fixture):
    root, _, bundled, env = runtime_fixture
    result = resolve(root, env)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(bundled)
    assert not (root / ".microsandbox").exists()


@pytest.mark.parametrize("missing", ["bin", "lib"])
def test_partial_home_does_not_fall_back(runtime_fixture, missing):
    root, _, _, env = runtime_fixture
    home = root / ".microsandbox"
    pair(home)
    (home / missing / (MSB if missing == "bin" else LIBRARY)).unlink()
    result = resolve(root, env)
    assert result.returncode != 0
    assert "expected both" in result.stderr


@pytest.mark.parametrize("override", ["environment", "setter", "configuration"])
def test_explicit_paths_win(runtime_fixture, override):
    root, _, _, env = runtime_fixture
    pair(root / ".microsandbox")
    expected = pair(root / "explicit")
    before = ""
    if override == "environment":
        env["MSB_PATH"] = str(expected)
    elif override == "setter":
        before = f"native.set_runtime_msb_path({str(expected)!r}); "
    else:
        config = root / "config.json"
        config.write_text(json.dumps({"paths": {"msb": str(expected)}}))
        env["MSB_CONFIG_PATH"] = str(config)
    result = resolve(root, env, before)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(expected)


def test_invalid_explicit_path_does_not_fall_back(runtime_fixture):
    root, _, _, env = runtime_fixture
    pair(root / ".microsandbox")
    env["MSB_PATH"] = str(root / "missing")
    result = resolve(root, env)
    assert result.returncode != 0


@pytest.mark.skipif(os.name == "nt", reason="fixture executable is a POSIX shell script")
def test_cli_executes_home_with_wheel_present(runtime_fixture):
    root, _, _, env = runtime_fixture
    pair(root / ".microsandbox", "home")
    result = subprocess.run(
        [sys.executable, "-c", "from microsandbox._cli import main; main()", "--version"],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "home:--version\n"


def run_setup(root, env, script):
    result = subprocess.run(
        [sys.executable, "-c", "import asyncio, json; import microsandbox as sdk; " + script],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_public_setup_surface(runtime_fixture):
    root, _, _, env = runtime_fixture
    result = run_setup(
        root,
        env,
        "print(json.dumps(["
        "all(callable(getattr(sdk, n)) for n in "
        "['resolve_runtime', 'is_runtime_installed', 'install_runtime', 'ensure_runtime']),"
        "hasattr(sdk, 'install'), hasattr(sdk, 'is_installed')]))",
    )
    assert result == [True, False, False]


def test_public_ensure_reuses_selected_pair(runtime_fixture):
    root, _, _, env = runtime_fixture
    home = root / "chosen"
    pair(home)
    result = run_setup(
        root,
        env,
        f"config = sdk.RuntimeConfig(home={str(home)!r}); "
        "resolved = sdk.resolve_runtime(config); "
        "ensured = asyncio.run(sdk.ensure_runtime(config, "
        "sdk.InstallOptions(source='directory', source_path='/absent', force=True))); "
        "print(json.dumps([resolved == ensured, resolved.msb_path, "
        "resolved.libkrunfw_path, resolved.origin]))",
    )
    assert result == [True, str(home / "bin" / MSB), str(home / "lib" / LIBRARY), "home"]


@pytest.mark.parametrize("operation", ["install_runtime", "ensure_runtime"])
def test_public_install_returns_pair(runtime_fixture, operation):
    root, package, _, env = runtime_fixture
    source = root / "source"
    pair(source)
    shutil.copyfile(source / "bin" / MSB, source / MSB)
    shutil.copyfile(source / "lib" / LIBRARY, source / LIBRARY)
    if operation == "ensure_runtime":
        (package / "_bundled" / "bin" / MSB).unlink()
    home = root / "destination"
    result = run_setup(
        root,
        env,
        f"runtime = asyncio.run(sdk.{operation}("
        f"sdk.RuntimeConfig(home={str(home)!r}), "
        f"sdk.InstallOptions(source='directory', source_path={str(source)!r}, "
        "verify=False))); "
        "print(json.dumps([runtime.msb_path, runtime.libkrunfw_path, runtime.origin]))",
    )
    assert result == [str(home / "bin" / MSB), str(home / "lib" / LIBRARY), "installed"]


def test_public_resolve_is_read_only_and_ensure_rejects_partial(runtime_fixture):
    root, package, _, env = runtime_fixture
    (package / "_bundled" / "bin" / MSB).unlink()
    home = root / "absent"
    result = run_setup(
        root,
        env,
        f"print(json.dumps(sdk.is_runtime_installed(sdk.RuntimeConfig(home={str(home)!r}))))",
    )
    assert result is False
    assert not home.exists()
    pair(home)
    (home / "lib" / LIBRARY).unlink()
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import asyncio; import microsandbox as sdk; "
            f"asyncio.run(sdk.ensure_runtime(sdk.RuntimeConfig(home={str(home)!r})))",
        ],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode != 0
    assert "expected both" in result.stderr
    assert not (home / "lib" / LIBRARY).exists()
