"""Opt-in real capture paths stay tied to the caller's cwd before scheduling."""

import asyncio
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import pytest


@pytest.mark.skipif(not os.environ.get("MSB_TEST_CAPTURE_SANDBOX"), reason="requires a disposable running sandbox")
def test_snapshot_capture_admission() -> None:
    result = subprocess.run([sys.executable, str(Path(__file__).resolve())], capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PYTHON_CAPTURE_ADMISSION_OK" in result.stdout


async def exercise(root: Path) -> None:
    from microsandbox import Sandbox

    first, second = root / "first", root / "second"
    first.mkdir()
    second.mkdir()
    # A symlink followed by '..' must retain filesystem traversal semantics.
    (root / "target" / "child").mkdir(parents=True)
    (first / "link").symlink_to(root / "target" / "child", target_is_directory=True)
    handle = await Sandbox.get(os.environ["MSB_TEST_CAPTURE_SANDBOX"])
    running = await handle.connect()
    for index, receiver in enumerate((handle, running)):
        for ordinal, destination in enumerate(("not-created/store", "link/../store", str(root / "absolute"))):
            os.chdir(first)
            expected = (first / destination).resolve()
            future = receiver.snapshot(f"path-py-{index}-{ordinal}", dest_dir=destination)
            os.chdir(second)
            result = await future
            try:
                path = Path(result.checkpoint.path)
                assert path.parent.parent.resolve() == expected, (path, expected)
                assert (path / "snapshot.json").is_file()
                assert not (second / "not-created").exists()
            finally:
                await result.snapshot.remove()
    print("PYTHON_CAPTURE_ADMISSION_OK")


if __name__ == "__main__":
    original = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="msb-capture-python-") as directory:
        try:
            asyncio.run(exercise(Path(directory).resolve()))
        finally:
            os.chdir(original)
