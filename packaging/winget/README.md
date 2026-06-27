# Windows Package Manager draft

This directory keeps the source draft for publishing microsandbox to the Windows Package Manager Community Repository.

The official winget package does not live in this repository. The ready-to-submit `0.6.0` manifests are staged under:

```text
packaging/winget/manifests/s/SuperRadCompany/Microsandbox/0.6.0/
```

Copy that directory into a fork of `microsoft/winget-pkgs` under the matching community repository path:

```text
manifests/s/SuperRadCompany/Microsandbox/<version>/
```

The package uses winget's zip + portable installer shape because the microsandbox Windows release bundle contains `msb.exe` next to `libkrunfw.dll`. The manifest sets `ArchiveBinariesDependOnPath: true` so the archive directory is placed on `PATH` and `msb.exe` can load its adjacent DLL.

## Submit 0.6.0

1. Fork and clone `microsoft/winget-pkgs`.
2. Copy the staged manifests into the fork:

```powershell
$version = "0.6.0"
$src = "C:\src\microsandbox\packaging\winget\manifests\s\SuperRadCompany\Microsandbox\$version"
$dst = "C:\src\winget-pkgs\manifests\s\SuperRadCompany\Microsandbox\$version"
New-Item -ItemType Directory -Force -Path $dst | Out-Null
Copy-Item "$src\*.yaml" $dst
```

3. Validate and smoke-test from the `winget-pkgs` checkout on Windows:

```powershell
winget validate $dst
winget install --manifest $dst --accept-package-agreements --accept-source-agreements
msb doctor
winget uninstall SuperRadCompany.Microsandbox
```

4. Commit the copied files in the `winget-pkgs` fork and open a pull request against `microsoft/winget-pkgs`.

The local staged manifests are based on GitHub release `v0.6.0`, published on `2026-06-27`, with SHA256 values from the release `checksums.sha256` asset.

## Render a release manifest

1. Wait for a release that includes:
   - `microsandbox-windows-x86_64.zip`
   - `microsandbox-windows-aarch64.zip`
   - `checksums.sha256`
2. Copy the template files into the winget-pkgs path:

```powershell
$version = "0.5.9"
$tag = "v$version"
$dst = "C:\src\winget-pkgs\manifests\s\SuperRadCompany\Microsandbox\$version"
New-Item -ItemType Directory -Force -Path $dst | Out-Null
Copy-Item packaging\winget\SuperRadCompany.Microsandbox\*.yaml $dst
```

3. Replace template markers:
   - `{{VERSION}}` with the semver package version, for example `0.5.9`
   - `{{TAG}}` with the GitHub release tag, for example `v0.5.9`
   - `{{RELEASE_DATE}}` with the release date in `YYYY-MM-DD`
   - `{{SHA256_X64}}` with the checksum for `microsandbox-windows-x86_64.zip`
   - `{{SHA256_ARM64}}` with the checksum for `microsandbox-windows-aarch64.zip`

The checksums are available from the release asset:

```powershell
gh release download $tag --repo superradcompany/microsandbox --pattern checksums.sha256 --dir $env:TEMP --clobber
Select-String -Path "$env:TEMP\checksums.sha256" -Pattern "microsandbox-windows"
```

4. Validate and smoke-test from the winget-pkgs checkout:

```powershell
winget validate $dst
winget install --manifest $dst --accept-package-agreements --accept-source-agreements
msb doctor
winget uninstall SuperRadCompany.Microsandbox
```

5. Submit the rendered files as a PR to `microsoft/winget-pkgs`.

Do not submit these templates directly. The community repository requires concrete release URLs and SHA256 hashes.
