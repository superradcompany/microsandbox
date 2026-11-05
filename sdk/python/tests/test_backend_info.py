import os
import subprocess
import sys
from pathlib import Path

from microsandbox import default_backend_info, default_backend_kind


def test_default_backend_info_is_structured_and_secret_safe() -> None:
    info = default_backend_info()

    assert info.kind in {"local", "cloud"}
    assert info.kind == default_backend_kind()
    assert not hasattr(info, "api_key")
    if info.kind == "cloud":
        assert info.api_url.startswith(("http://", "https://"))
    else:
        assert info.api_url is None


def test_backend_diagnostics_report_prohibited_selection(tmp_path: Path) -> None:
    # Requires an unmanaged host; the subprocess retains system policy. See DEVELOPMENT.md.
    config = tmp_path / "config.json"
    config.write_text('{"allowed_backends":["cloud"]}')
    env = {key: value for key, value in os.environ.items() if not key.startswith("MSB_")}
    env.update(MSB_CONFIG_PATH=str(config), MSB_HOME=str(tmp_path / "runtime"))
    result = subprocess.run(
        [sys.executable, "-c", """
from microsandbox import InvalidConfigError, default_backend_info, default_backend_kind
for diagnostic in (default_backend_info, default_backend_kind):
    try:
        diagnostic()
    except InvalidConfigError as error:
        assert "local backend" in str(error) and "disabled" in str(error), str(error)
    else:
        raise AssertionError("prohibited backend reported as usable")
"""],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "runtime").exists()
