import os
import subprocess
import sys
from pathlib import Path

import microsandbox


def test_explicit_contexts_are_independent() -> None:
    remote = microsandbox.RemoteContext(url="http://127.0.0.1:9", api_key="fixture")
    local = microsandbox.LocalContext()
    assert remote.kind == "remote"
    assert local.kind == "local"
    for name in (
        "set_default_backend",
        "backend_scope",
        "default_backend_info",
        "default_backend_kind",
    ):
        assert not hasattr(microsandbox, name)


def test_backend_diagnostics_report_prohibited_selection(tmp_path: Path) -> None:
    # Requires an unmanaged host; the subprocess retains system policy. See DEVELOPMENT.md.
    config = tmp_path / "config.json"
    config.write_text('{"allowed_backends":["cloud"]}')
    env = {key: value for key, value in os.environ.items() if not key.startswith("MSB_")}
    env.update(MSB_CONFIG_PATH=str(config), MSB_HOME=str(tmp_path / "runtime"))
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
from microsandbox import InvalidConfigError, LocalContext
for diagnostic in (LocalContext,):
    try:
        diagnostic()
    except InvalidConfigError as error:
        assert "local backend" in str(error) and "disabled" in str(error), str(error)
    else:
        raise AssertionError("prohibited backend reported as usable")
""",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "runtime").exists()
