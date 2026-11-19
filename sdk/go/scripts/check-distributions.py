#!/usr/bin/env python3
"""Exercise real module ZIP resolution, tidy, vendor and offline builds."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile

BASE = "github.com/superradcompany/microsandbox/sdk/go"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--staged", type=Path, required=True)
    args = parser.parse_args()
    staged = args.staged.resolve()
    version = (staged / "local/go.mod").read_text().split("require ")[1].split()[1]
    with tempfile.TemporaryDirectory(prefix="msb-go-modules-") as temp:
        root = Path(temp)
        proxy = root / "proxy"
        modules = {"core": BASE + "/core", "local": BASE + "/local", "remote": BASE + "/remote"}
        if (staged / "full").exists():
            modules["full"] = BASE
        for kind, module in modules.items():
            directory = staged / kind
            files = [file for file in directory.rglob("*") if file.is_file()]
            if kind != "full":
                for file in files:
                    if file.suffix in (".so", ".dylib", ".dll", ".node", ".a") or "bundles" in file.parts:
                        raise AssertionError(f"native payload in thin module: {file}")
            release = proxy / module / "@v"
            release.mkdir(parents=True)
            (release / f"{version}.mod").write_bytes((directory / "go.mod").read_bytes())
            (release / f"{version}.info").write_text(json.dumps({"Version": version, "Time": "2026-11-16T00:00:00Z"}))
            (release / "list").write_text(version + "\n")
            with zipfile.ZipFile(release / f"{version}.zip", "w", zipfile.ZIP_DEFLATED) as archive:
                for file in files:
                    archive.write(file, f"{module}@{version}/{file.relative_to(directory).as_posix()}")
        app = root / "consumer"
        app.mkdir()
        requires = "\n".join(f" {module} {version}" for module in modules.values())
        (app / "go.mod").write_text(f"module providerconsumer\n\ngo 1.22\n\nrequire (\n{requires}\n)\n")
        full_import = f'full "{BASE}"' if "full" in modules else ""
        full_identity = "var same *full.Sandbox = resource; _ = same; _ = full.SandboxLocal; _ = full.SandboxRemote; _ = full.VolumeLocal; _ = full.VolumeRemote; _ = full.SnapshotLocal; _ = full.SnapshotRemote" if "full" in modules else ""
        (app / "providers_test.go").write_text(f'''package providerconsumer
import (
 "testing"
 "time"
 core "{BASE}/core"
 "{BASE}/local"
 "{BASE}/remote"
 {full_import}
)
func TestSharedTypesAndMissingProvider(t *testing.T) {{
 var _ core.JobState = core.JobStateRunning
 var _ core.SnapshotStateKind = core.SnapshotStateFile
 _ = core.NamedVolumeOptions{{Mode: core.NamedVolumeEnsureExists, Kind: core.VolumeKindDir}}
 _ = core.JobLogOptions{{Sources: []core.JobOutputSource{{core.JobOutputStdout, core.JobOutputPTY}}}}
 var resource *core.Sandbox
 {full_identity}
 _ = core.SandboxLocal; _ = core.SandboxRemote
 _ = core.VolumeLocal; _ = core.VolumeRemote
 _ = core.SnapshotLocal; _ = core.SnapshotRemote
 _ = local.NewContext
 var hosted func(string, string) (*core.RemoteContext, error) = remote.NewContext
 var explicit func(string, string, string) (*core.RemoteContext, error) = remote.NewContextWithURL
 var coreHosted func(string) (*core.RemoteContext, error) = core.NewRemoteContext
 var coreExplicit func(string, string) (*core.RemoteContext, error) = core.NewRemoteContextWithURL
 var _ func(string, ...core.RemoteContextOption) (*core.RemoteContext, error) = remote.NewContextWithOptions
 var _ func(...core.RemoteContextOption) (*core.RemoteContext, error) = core.NewRemoteContextWithOptions
 _, _, _, _ = hosted, explicit, coreHosted, coreExplicit
 var selected *core.RemoteContext
 if _, err := selected.WithOptions(core.WithRemoteURL("https://example.com"), core.WithRemoteAPIKey("fixture"), core.WithRemoteRequestTimeout(time.Second), core.WithRemoteUserAgent("consumer")); err == nil {{ t.Fatal("nil derived context accepted") }}
 if _, err := core.InstalledNativeProvider(core.ContextRemote, t.TempDir()); err == nil {{ t.Fatal("missing provider unexpectedly loaded") }}
}}
''')
        env = {**os.environ, "GOWORK": "off", "GOPROXY": proxy.as_uri(), "GOSUMDB": "off", "GOMODCACHE": str(root / "cache")}
        for command in (["go", "mod", "download"], ["go", "mod", "tidy"], ["go", "mod", "vendor"], ["go", "test", "-mod=vendor", "./..."]):
            subprocess.run(command, cwd=app, env=env, check=True)
        # A second build needs neither a proxy nor the downloaded module cache.
        env.update(GOPROXY="off", GOMODCACHE=str(root / "empty-cache"))
        subprocess.run(["go", "test", "-count=1", "-mod=vendor", "./..."], cwd=app, env=env, check=True)
        print("Go module ZIP, tidy, vendor, offline build, shared types and missing-provider checks passed")


if __name__ == "__main__":
    main()
