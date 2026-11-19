"""Build a source-only Functions deployment zip, excluding all private config."""

import argparse
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    output = parser.parse_args().output
    source = Path(__file__).parent
    # An explicit allowlist prevents local settings, keys, logs, or build caches
    # from entering a deployment when this directory is used by an operator.
    files = ["function_app.py", "host.json", "requirements.txt", "clients.py", "controller.py", "models.py",
             "bootstrap.ps1", "prepare.ps1", "stage-jit.ps1", "RunnerLauncher.cs"]
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        for name in files:
            archive.write(source / name, name)
        archive.write(source.parent / "windows-whp-preflight.ps1", "windows-whp-preflight.ps1")
    print("Controller source package created; no configuration or credentials included")


if __name__ == "__main__":
    main()
