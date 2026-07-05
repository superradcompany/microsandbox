#Requires -Version 5.1
<#
.SYNOPSIS
Installs microsandbox on Windows.

.DESCRIPTION
Downloads the latest Windows release bundle from GitHub, verifies its SHA256 checksum, installs
msb.exe and libkrunfw.dll under $env:MSB_HOME or %USERPROFILE%\.microsandbox, and adds the bin
directory to the current user's PATH when it is not already present.

Usage:
  irm https://github.com/superradcompany/microsandbox/releases/latest/download/install.ps1 | iex

Environment overrides:
  MSB_HOME                 Install root. Defaults to %USERPROFILE%\.microsandbox.
  MSB_INSTALL_VERSION      Release tag to install, such as v0.5.7. Defaults to latest release.
  MSB_INSTALL_BASE_URL     Release asset base URL. Defaults to the selected GitHub release URL.
  MSB_INSTALL_NO_PATH=1    Do not add the install bin directory to user PATH.
  MSB_INSTALL_NO_DOCTOR=1  Do not run the post-install doctor check.
  MSB_INSTALL_NO_FIX=1     Do not offer to run msb doctor --fix after a failed doctor check.
  MSB_INSTALL_ASSUME_YES=1 Run the setup fix without prompting if the doctor check fails.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

#--------------------------------------------------------------------------------------------------
# Constants
#--------------------------------------------------------------------------------------------------

$GitHubRepo = "superradcompany/microsandbox"
$LatestReleaseApiUrl = "https://api.github.com/repos/$GitHubRepo/releases/latest"

#--------------------------------------------------------------------------------------------------
# Functions
#--------------------------------------------------------------------------------------------------

function Write-Info {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "info " -ForegroundColor Cyan -NoNewline
    Write-Host $Message
}

function Write-Success {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "done " -ForegroundColor Green -NoNewline
    Write-Host $Message
}

function Write-WarningMessage {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "warn " -ForegroundColor Yellow -NoNewline
    Write-Host $Message
}

function Resolve-InstallRoot {
    if (-not [string]::IsNullOrWhiteSpace($env:MSB_HOME)) {
        return [System.IO.Path]::GetFullPath($env:MSB_HOME)
    }

    if ([string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        throw "USERPROFILE is not set; set MSB_HOME to choose an install directory"
    }

    return [System.IO.Path]::GetFullPath((Join-Path $env:USERPROFILE ".microsandbox"))
}

function Resolve-Architecture {
    try {
        $architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
        if ($null -ne $architecture) {
            return [string]$architecture
        }
    } catch {
        # Some Windows PowerShell/.NET Framework combinations do not expose
        # RuntimeInformation.OSArchitecture even though the rest of the
        # installer can run normally.
    }

    if (-not [string]::IsNullOrWhiteSpace($env:PROCESSOR_ARCHITEW6432)) {
        return $env:PROCESSOR_ARCHITEW6432
    }

    if (-not [string]::IsNullOrWhiteSpace($env:PROCESSOR_ARCHITECTURE)) {
        return $env:PROCESSOR_ARCHITECTURE
    }

    try {
        $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($null -ne $operatingSystem -and -not [string]::IsNullOrWhiteSpace($operatingSystem.OSArchitecture)) {
            return [string]$operatingSystem.OSArchitecture
        }
    } catch {
    }

    throw "could not determine Windows architecture"
}

function Resolve-Target {
    $architecture = Resolve-Architecture
    switch -Regex ($architecture.ToUpperInvariant()) {
        "^(ARM64|AARCH64)$" { return "windows-aarch64" }
        "^(X64|AMD64|X86_64|64-BIT)$" { return "windows-x86_64" }
        default { throw "unsupported Windows architecture: $architecture" }
    }
}

function Resolve-Version {
    if (-not [string]::IsNullOrWhiteSpace($env:MSB_INSTALL_VERSION)) {
        return $env:MSB_INSTALL_VERSION
    }

    Write-Info "Resolving latest release..."
    $release = Invoke-RestMethod -Uri $LatestReleaseApiUrl -Headers @{ "User-Agent" = "microsandbox-installer" }
    if ([string]::IsNullOrWhiteSpace($release.tag_name)) {
        throw "could not determine latest release version"
    }

    return [string]$release.tag_name
}

function Resolve-BaseUrl {
    param([Parameter(Mandatory = $true)][string]$Version)

    if (-not [string]::IsNullOrWhiteSpace($env:MSB_INSTALL_BASE_URL)) {
        return $env:MSB_INSTALL_BASE_URL.TrimEnd("/")
    }

    return "https://github.com/$GitHubRepo/releases/download/$Version"
}

function Invoke-Download {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    Write-Info "Downloading $(Split-Path -Leaf $Destination)..."
    Invoke-WebRequest -Uri $Url -OutFile $Destination -Headers @{ "User-Agent" = "microsandbox-installer" }
}

function Read-ExpectedHash {
    param(
        [Parameter(Mandatory = $true)][string]$ChecksumsPath,
        [Parameter(Mandatory = $true)][string]$BundleName
    )

    foreach ($line in Get-Content -LiteralPath $ChecksumsPath) {
        if ($line -match "^\s*([A-Fa-f0-9]{64})\s+\*?$([regex]::Escape($BundleName))\s*$") {
            return $matches[1].ToUpperInvariant()
        }
    }

    throw "checksums file does not contain an entry for $BundleName"
}

function Test-Checksum {
    param(
        [Parameter(Mandatory = $true)][string]$BundlePath,
        [Parameter(Mandatory = $true)][string]$ChecksumsPath
    )

    $bundleName = Split-Path -Leaf $BundlePath
    $expected = Read-ExpectedHash -ChecksumsPath $ChecksumsPath -BundleName $bundleName
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $BundlePath).Hash.ToUpperInvariant()
    if ($actual -ne $expected) {
        throw "checksum verification failed for $bundleName"
    }

    Write-Success "Checksum verified."
}

function Copy-InstalledFile {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    $destinationDir = Split-Path -Parent $Destination
    New-Item -ItemType Directory -Force -Path $destinationDir | Out-Null

    $tempDestination = "$Destination.tmp"
    Copy-Item -LiteralPath $Source -Destination $tempDestination -Force
    Move-Item -LiteralPath $tempDestination -Destination $Destination -Force
}

function Install-Bundle {
    param(
        [Parameter(Mandatory = $true)][string]$ExtractDir,
        [Parameter(Mandatory = $true)][string]$BinDir,
        [Parameter(Mandatory = $true)][string]$LibDir
    )

    $msbSource = Join-Path $ExtractDir "msb.exe"
    $libkrunfwSource = Join-Path $ExtractDir "libkrunfw.dll"

    if (-not (Test-Path -LiteralPath $msbSource -PathType Leaf)) {
        throw "release bundle is missing msb.exe"
    }
    if (-not (Test-Path -LiteralPath $libkrunfwSource -PathType Leaf)) {
        throw "release bundle is missing libkrunfw.dll"
    }

    $msbDestination = Join-Path $BinDir "msb.exe"
    $microsandboxDestination = Join-Path $BinDir "microsandbox.exe"
    $libkrunfwDestination = Join-Path $LibDir "libkrunfw.dll"

    Copy-InstalledFile -Source $msbSource -Destination $msbDestination
    Copy-InstalledFile -Source $msbSource -Destination $microsandboxDestination
    Copy-InstalledFile -Source $libkrunfwSource -Destination $libkrunfwDestination

    Write-Success "Installed msb to $msbDestination"
    Write-Success "Installed microsandbox alias to $microsandboxDestination"
    Write-Success "Installed libkrunfw to $libkrunfwDestination"

    return $msbDestination
}

function Normalize-PathSegment {
    param([Parameter(Mandatory = $true)][string]$Path)

    return $Path.Trim().TrimEnd("\", "/")
}

function Add-UserPath {
    param([Parameter(Mandatory = $true)][string]$BinDir)

    if ($env:MSB_INSTALL_NO_PATH -eq "1") {
        Write-WarningMessage "Skipped PATH update because MSB_INSTALL_NO_PATH=1."
        return
    }

    $normalizedBinDir = Normalize-PathSegment -Path ([System.IO.Path]::GetFullPath($BinDir))
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $segments = @()
    if (-not [string]::IsNullOrWhiteSpace($userPath)) {
        $segments = $userPath -split ";" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    }

    # Keep the installed msb first so an older msb.exe elsewhere in PATH does
    # not shadow a freshly-installed release in new shells.
    $filteredSegments = @()
    foreach ($segment in $segments) {
        if ((Normalize-PathSegment -Path $segment) -ine $normalizedBinDir) {
            $filteredSegments += $segment
        }
    }

    $nextSegments = @($BinDir) + @($filteredSegments)
    $nextUserPath = ($nextSegments | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ";"
    [Environment]::SetEnvironmentVariable("Path", $nextUserPath, "User")

    $currentSegments = $env:Path -split ";" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    $currentFilteredSegments = @()
    foreach ($segment in $currentSegments) {
        if ((Normalize-PathSegment -Path $segment) -ine $normalizedBinDir) {
            $currentFilteredSegments += $segment
        }
    }
    $env:Path = (@($BinDir) + @($currentFilteredSegments)) -join ";"

    Write-Success "Placed $BinDir first in the user PATH."
    Write-WarningMessage "Open a new terminal if this shell does not pick up the updated PATH."
}

function Invoke-Doctor {
    param([Parameter(Mandatory = $true)][string]$MsbPath)

    if ($env:MSB_INSTALL_NO_DOCTOR -eq "1") {
        Write-WarningMessage "Skipped doctor check because MSB_INSTALL_NO_DOCTOR=1."
        return
    }

    Write-Info "Running msb doctor..."
    & $MsbPath doctor
    if ($LASTEXITCODE -eq 0) {
        return
    }

    Write-WarningMessage "msb doctor reported setup work remains."
    Invoke-SetupFixPrompt -MsbPath $MsbPath
}

function Invoke-SetupFixPrompt {
    param([Parameter(Mandatory = $true)][string]$MsbPath)

    if ($env:MSB_INSTALL_NO_FIX -eq "1") {
        Write-WarningMessage "Skipped setup fix prompt because MSB_INSTALL_NO_FIX=1. Run 'msb doctor --fix' later."
        return
    }

    $shouldRunFix = $env:MSB_INSTALL_ASSUME_YES -eq "1"
    if (-not $shouldRunFix) {
        if (-not [Environment]::UserInteractive -or [Console]::IsInputRedirected) {
            Write-WarningMessage "Run 'msb doctor --fix' from an interactive terminal to enable Windows Hypervisor Platform."
            return
        }

        Write-Host ""
        Write-Host "Windows Hypervisor Platform may need to be enabled before local sandboxes can start."
        Write-Host "This opens an elevated PowerShell prompt and may require a reboot."
        $answer = Read-Host "Run 'msb doctor --fix' now? [Y/n]"
        $shouldRunFix = [string]::IsNullOrWhiteSpace($answer) -or $answer -match "^(y|yes)$"
    }

    if (-not $shouldRunFix) {
        Write-WarningMessage "Skipped setup fix. Run 'msb doctor --fix' later if local sandboxes fail to start."
        return
    }

    Write-Info "Opening setup fix..."
    & $MsbPath doctor --fix
    if ($LASTEXITCODE -ne 0) {
        Write-WarningMessage "Setup fix did not complete cleanly. A reboot may still be required; rerun 'msb doctor' after reboot."
    }
}

#--------------------------------------------------------------------------------------------------
# Main
#--------------------------------------------------------------------------------------------------

Write-Host ""
Write-Host "  Microsandbox Installer"
Write-Host ""

$target = Resolve-Target
$version = Resolve-Version
$baseUrl = Resolve-BaseUrl -Version $version
$installRoot = Resolve-InstallRoot
$binDir = Join-Path $installRoot "bin"
$libDir = Join-Path $installRoot "lib"
$bundleName = "microsandbox-$target.zip"
$checksumsName = "checksums.sha256"

Write-Info "Detected platform: $target"
Write-Info "Selected version: $version"
Write-Info "Install root: $installRoot"

$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("microsandbox-install-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null

try {
    $bundlePath = Join-Path $tempDir $bundleName
    $checksumsPath = Join-Path $tempDir $checksumsName
    $extractDir = Join-Path $tempDir "bundle"

    Invoke-Download -Url "$baseUrl/$bundleName" -Destination $bundlePath
    Invoke-Download -Url "$baseUrl/$checksumsName" -Destination $checksumsPath
    Test-Checksum -BundlePath $bundlePath -ChecksumsPath $checksumsPath

    Write-Info "Extracting..."
    Expand-Archive -LiteralPath $bundlePath -DestinationPath $extractDir -Force

    $msbPath = Install-Bundle -ExtractDir $extractDir -BinDir $binDir -LibDir $libDir
    Add-UserPath -BinDir $binDir
    Invoke-Doctor -MsbPath $msbPath

    Write-Success "Installation complete. Run 'msb --help' to get started."
    Write-Host ""
} finally {
    Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}
