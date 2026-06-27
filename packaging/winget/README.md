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

## How submission works

The **first** version must be submitted to `microsoft/winget-pkgs` by hand using the staged `0.6.0` manifests (see [Submit 0.6.0](#submit-060) below). Komac, which the release automation uses, refuses to open a PR for a package that does not yet exist in the community repository.

After that first version lands, **subsequent releases are automated**. The `update-winget` job in [`.github/workflows/release.yml`](../../.github/workflows/release.yml) runs on every `v*` tag: it invokes [`winget-releaser`](https://github.com/vedantmgoyal9/winget-releaser) (Komac), which copies the previously published manifests, bumps the version, rewrites the installer URLs and SHA256 hashes from the release's `microsandbox-windows-*.zip` assets, and opens a PR against `microsoft/winget-pkgs`.

One-time setup for the automation:

- Add a `WINGET_TOKEN` repository secret: a classic PAT with `public_repo` scope whose owner has a fork of `microsoft/winget-pkgs`. The submit step is skipped when this secret is absent.
- If that fork lives under an account other than `superradcompany`, set a `WINGET_FORK_USER` repository variable to the fork owner's username.

Prerelease tags (`-rc`, `-alpha`, `-beta`, `-dev`) are skipped, matching the release job's prerelease detection. The manual [Render a release manifest](#render-a-release-manifest) flow below remains as a fallback if the automation is ever unavailable.

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
