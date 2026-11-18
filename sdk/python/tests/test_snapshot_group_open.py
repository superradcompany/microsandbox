"""Group paths retain call-time cwd and never fall back to a same-name history."""

import asyncio
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def test_group_open() -> None:
    result = subprocess.run(
        [sys.executable, str(Path(__file__).resolve())], capture_output=True, text=True, timeout=90
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PYTHON_GROUP_OPEN_OK" in result.stdout


async def exercise(root: Path) -> None:
    os.environ["MSB_HOME"] = str(root / "home")
    os.environ["MSB_CONFIG_PATH"] = str(root / "absent.json")
    from microsandbox import BackendKind, Snapshot, set_default_backend

    set_default_backend(BackendKind.LOCAL)
    first, second, target = root / "first", root / "second", root / "target"
    for path in (
        first,
        second,
        target / "child",
        target / "history",
        root / "home" / "snapshots" / "history",
    ):
        path.mkdir(parents=True, exist_ok=True)
    metadata = '{"schema":"microsandbox.snapshot-group/1","head":null}'
    external = target / "history"
    default = root / "home" / "snapshots" / "history"
    for path in (external, default):
        (path / "group.json").write_text(metadata)
    (first / "link").symlink_to(target / "child", target_is_directory=True)
    for selector in (str(external), "link/../history"):
        os.chdir(first)
        future = Snapshot.open(selector)
        os.chdir(second)
        history = await future
        assert history.name == "history"
        assert Path((await history.inspect())["path"]).resolve() == external.resolve()
        assert await history.head() is None
        assert await history.checkpoints() == []
    for selector in ("", "./missing"):
        try:
            await Snapshot.open(selector)
        except Exception:
            pass
        else:
            raise AssertionError(f"invalid group accepted: {selector!r}")
    assert not (second / "missing").exists()
    named = await Snapshot.get("history")
    assert Path((await named.inspect())["path"]).resolve() == default.resolve()
    await history.remove()
    assert not external.exists()
    assert (default / "group.json").read_text() == metadata
    print("PYTHON_GROUP_OPEN_OK")


if __name__ == "__main__":
    original = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="msb-group-open-python-") as directory:
        try:
            asyncio.run(exercise(Path(directory).resolve()))
        finally:
            os.chdir(original)
