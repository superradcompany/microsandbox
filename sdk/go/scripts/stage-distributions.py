#!/usr/bin/env python3
"""Stage independent Go modules from the single wrapper source of truth."""
import argparse
from pathlib import Path
import re
import shutil
import subprocess

SOURCE = Path(__file__).resolve().parents[1]
BASE = "github.com/superradcompany/microsandbox/sdk/go"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--full", action="store_true")
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() and any(out.iterdir()):
        raise SystemExit("staging destination must be empty")
    version = re.search(r'const sdkVersion = "([^"]+)"', (SOURCE / "setup.go").read_text())[1]
    core = out / "core"
    core.mkdir(parents=True)
    for file in SOURCE.glob("*.go"):
        if file.name.endswith("_test.go"):
            continue
        text = file.read_text().replace(BASE + "/internal/", BASE + "/core/internal/")
        if file.name == "setup.go":
            # Core never installs the full package's bundled-native loader.
            start = text.index("// init wires")
            end = text.index("// SDKVersion returns")
            text = text[:start] + text[end:]
            start = text.index("// materializeFFI extracts")
            end = text.index("// wrapDlopenErr decorates")
            text = text[:start] + text[end:]
            text = text.replace('\n\t"sync"', '').replace(f'\n\t"{BASE}/core/internal/bundle"', '')
        (core / file.name).write_text(text)
    shutil.copytree(SOURCE / "internal/ffi", core / "internal/ffi", ignore=shutil.ignore_patterns("*_test.go"))
    for file in (core / "internal").rglob("*.go"):
        file.write_text(file.read_text().replace(BASE + "/internal/", BASE + "/core/internal/"))
    command = core / "cmd/ffi-setup"
    command.mkdir(parents=True)
    (command / "main.go").write_text((SOURCE / "cmd/ffi-setup/main.go").read_text().replace(f'"{BASE}"', f'"{BASE}/core"'))
    (core / "go.mod").write_text(f"module {BASE}/core\n\ngo 1.22\n")
    for kind in ("local", "remote"):
        directory = out / kind
        directory.mkdir()
        (directory / "go.mod").write_text(f"module {BASE}/{kind}\n\ngo 1.22\n\nrequire {BASE}/core v{version}\n")
        selected = kind.title()
        parameters = "options core.LocalOptions" if kind == "local" else "apiKey string"
        arguments = "options" if kind == "local" else "apiKey"
        (directory / "provider.go").write_text(f'''// Package {kind} selects the {kind}-only native build. It never downloads on import or use.
package {kind}
import core "{BASE}/core"
// Load selects an explicitly provisioned trusted library, or the verified install cache when path is empty.
func Load(path string) (*core.NativeProvider, error) {{
 if path == "" {{ return core.InstalledNativeProvider(core.Context{selected}, "") }}
 return core.LoadNativeProvider(path, core.Context{selected})
}}
// NewContext captures the loaded provider for all derived resources.
func NewContext(path string, {parameters}) (*core.{selected}Context, error) {{
 provider, err := Load(path)
 if err != nil {{ return nil, err }}
 return provider.New{selected}Context({arguments})
}}
''')
        if kind == "remote":
            # Keep the generated lean module aligned with the shared core constructors.
            with (directory / "provider.go").open("a") as stream:
                stream.write('''
// NewContextWithOptions captures explicit settings and environment defaults.
func NewContextWithOptions(path string, options ...core.RemoteContextOption) (*core.RemoteContext, error) {
 provider, err := Load(path)
 if err != nil { return nil, err }
 return provider.NewRemoteContextWithOptions(options...)
}

// NewContextWithURL captures an explicit endpoint on the selected provider.
func NewContextWithURL(path, url, apiKey string) (*core.RemoteContext, error) {
 provider, err := Load(path)
 if err != nil { return nil, err }
 return provider.NewRemoteContextWithURL(url, apiKey)
}
''')
    if args.full:
        full = out / "full"
        full.mkdir()
        aliases = subprocess.check_output(["go", "run", str(SOURCE / "scripts/export-aliases.go"), str(SOURCE)], text=True)
        (full / "aliases.go").write_text(aliases)
        # The full package keeps its existing embedded FFI materialization only.
        text = (SOURCE / "setup.go").read_text()
        text = text.replace(f'"{BASE}/internal/ffi"', f'core "{BASE}/core"')
        text = text.replace("ffi.SetAutoLoader", "core.RegisterFullNativeLoader").replace("ffi.Load(", "core.LoadFullNative(").replace("ffi.Version()", "core.RuntimeVersion()").replace("wrapFFI(err)", "err")
        (full / "setup.go").write_text(text)
        shutil.copytree(SOURCE / "internal/bundle", full / "internal/bundle")
        (full / "go.mod").write_text(f"module {BASE}\n\ngo 1.22\n\nrequire {BASE}/core v{version}\n")
    subprocess.run(["gofmt", "-w", str(out)], check=True)
    print(out)


if __name__ == "__main__":
    main()
