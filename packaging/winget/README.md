# Windows Package Manager draft

This directory keeps the source draft for publishing microsandbox to the Windows Package Manager Community Repository.

The official winget package does not live in this repository. When a Windows release is ready, copy the rendered manifests from here into a fork of `microsoft/winget-pkgs` under:

```text
manifests/s/SuperRadCompany/Microsandbox/<version>/
```

The package uses winget's zip + portable installer shape because the microsandbox Windows release bundle contains `msb.exe` next to `libkrunfw.dll`. The manifest sets `ArchiveBinariesDependOnPath: true` so the archive directory is placed on `PATH` and `msb.exe` can load its adjacent DLL.

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
