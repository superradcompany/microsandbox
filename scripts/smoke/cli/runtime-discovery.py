#!/usr/bin/env python3
"""Check CLI runtime discovery through each platform's installer layout.

Uses doctor without --fix; no VM, image download, or host setup is required.
Pass the candidate msb binary and its matching libkrunfw library. Unix checks
the command symlinks; Windows checks the copied microsandbox.exe alias.
"""

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


def diagnose(command, home, env):
    result = subprocess.run(
        [str(command), "doctor"], cwd=home, env=env,
        capture_output=True, text=True, encoding="utf-8", timeout=30,
    )
    output = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout + result.stderr)
    print(f"$ {command} doctor (exit {result.returncode})\n{output}", flush=True)
    # Doctor also checks host virtualization. Hosted runners need not pass
    # those checks, but a crash or unexpected exit must never count as success.
    if result.returncode not in (0, 1):
        raise RuntimeError(f"doctor exited unexpectedly: {result.returncode}")
    checks = re.findall(r"^\s*([✓✗])\s+(msb|libkrunfw)\s+(.+)$", output, re.MULTILINE)
    if len(checks) != 2 or {label for _, label, _ in checks} != {"msb", "libkrunfw"}:
        raise RuntimeError("doctor did not report exactly one check for each runtime file")
    return result.returncode, {label: (state, value) for state, label, value in checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--msb", required=True, type=Path)
    parser.add_argument("--libkrunfw", required=True, type=Path)
    args = parser.parse_args()
    if sys.platform not in ("darwin", "linux", "win32"):
        parser.error("supported platforms: macOS, Linux, Windows")
    sys.stdout.reconfigure(encoding="utf-8")
    windows = sys.platform == "win32"
    binary = args.msb.resolve(strict=True)
    firmware = args.libkrunfw.resolve(strict=True)

    with tempfile.TemporaryDirectory(prefix="msb-runtime-discovery-") as temporary:
        home = Path(temporary).resolve()
        install = home / ".microsandbox"
        bin_dir = install / "bin"
        lib_dir = install / "lib"
        launchers = home / ".local/bin"
        for directory in (bin_dir, lib_dir, launchers):
            directory.mkdir(parents=True)
        installed_msb = bin_dir / ("msb.exe" if windows else "msb")
        installed_firmware = lib_dir / firmware.name
        shutil.copy2(binary, installed_msb)
        installed_msb.chmod(0o755)
        shutil.copy2(firmware, installed_firmware)
        commands = [(installed_msb, installed_msb)]
        if windows:
            # install.ps1 copies the alias; it does not require symlink privileges.
            alias = bin_dir / "microsandbox.exe"
            shutil.copy2(installed_msb, alias)
            commands.append((alias, alias))
        else:
            (bin_dir / "microsandbox").symlink_to("msb")
            (launchers / "msb").symlink_to(installed_msb)
            (launchers / "microsandbox").symlink_to(bin_dir / "microsandbox")
            commands.extend((launchers / name, installed_msb) for name in ("msb", "microsandbox"))

        # Prevent an inherited runtime override from hiding the regression, and
        # isolate user configuration and the clone probe from the real home.
        env = {key: value for key, value in os.environ.items() if not key.upper().startswith("MSB_")}
        env.update(HOME=str(home), MSB_HOME=str(install),
                   XDG_CONFIG_HOME=str(home / ".config"), NO_COLOR="1", TERM="dumb")
        if windows:
            env.update(USERPROFILE=str(home), APPDATA=str(home / "AppData/Roaming"),
                       LOCALAPPDATA=str(home / "AppData/Local"))
        for command, expected_msb in commands:
            _, checks = diagnose(command, home, env)
            for label, expected in (("msb", expected_msb), ("libkrunfw", installed_firmware)):
                state, value = checks[label]
                # Windows may report a verbatim (\\?\) path. Compare file identity,
                # not spelling, so prefixes and equivalent symlinks are accepted.
                if state != "✓" or not Path(value).samefile(expected):
                    raise RuntimeError(f"{command}: {label} did not resolve to {expected}")

        # Prove we inspect runtime discovery, not just a successful CLI launch.
        installed_firmware.unlink()
        for command, _ in commands:
            status, checks = diagnose(command, home, env)
            if status != 1 or any(state != "✗" for state, _ in checks.values()):
                raise RuntimeError("doctor did not reject the incomplete runtime pair")
    print(f"Runtime discovery smoke passed on {sys.platform} (all launchers and missing firmware).")


if __name__ == "__main__":
    main()
