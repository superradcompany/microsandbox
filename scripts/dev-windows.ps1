#Requires -Version 5.1
<#
.SYNOPSIS
Windows development helper used by just recipes.

.DESCRIPTION
Builds and installs local Windows development artifacts for microsandbox. The justfile is the intended entry point; this script keeps the Windows-specific Visual Studio, libkrunfw, and install-layout logic in one place.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("setup", "install-dev-deps", "build-deps", "build-agentd", "build-libkrunfw", "ensure-libkrunfw", "build-msb", "build", "install", "uninstall", "clean")]
    [string] $Command,

    [ValidateSet("debug", "release")]
    [string] $Mode = "debug"
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

#--------------------------------------------------------------------------------------------------
# Constants
#--------------------------------------------------------------------------------------------------

$LibkrunfwAbi = "5"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BuildDir = Join-Path $RepoRoot "build"

#--------------------------------------------------------------------------------------------------
# Functions: Output
#--------------------------------------------------------------------------------------------------

function Write-Info {
    param([Parameter(Mandatory = $true)][string] $Message)
    Write-Host "==> $Message"
}

function Write-Done {
    param([Parameter(Mandatory = $true)][string] $Message)
    Write-Host "done " -ForegroundColor Green -NoNewline
    Write-Host $Message
}

function Write-Warn {
    param([Parameter(Mandatory = $true)][string] $Message)
    Write-Host "warn " -ForegroundColor Yellow -NoNewline
    Write-Host $Message
}

#--------------------------------------------------------------------------------------------------
# Functions: Paths
#--------------------------------------------------------------------------------------------------

function Resolve-InstallRoot {
    if (-not [string]::IsNullOrWhiteSpace($env:MSB_HOME)) {
        return [System.IO.Path]::GetFullPath($env:MSB_HOME)
    }

    if ([string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        throw "USERPROFILE is not set; set MSB_HOME to choose an install directory"
    }

    return [System.IO.Path]::GetFullPath((Join-Path $env:USERPROFILE ".microsandbox"))
}

function Assert-PathInside {
    param(
        [Parameter(Mandatory = $true)][string] $Parent,
        [Parameter(Mandatory = $true)][string] $Child
    )

    $parentFull = [System.IO.Path]::GetFullPath($Parent).TrimEnd([char[]]@("\", "/"))
    $childFull = [System.IO.Path]::GetFullPath($Child).TrimEnd([char[]]@("\", "/"))
    $parentPrefix = "$parentFull\"
    if ($childFull -ine $parentFull -and -not $childFull.StartsWith($parentPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "refusing to operate outside ${parentFull}: $childFull"
    }
}

function Remove-KnownPath {
    param([Parameter(Mandatory = $true)][string] $Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    Remove-Item -LiteralPath $Path -Recurse -Force
}

function Copy-InstalledFile {
    param(
        [Parameter(Mandatory = $true)][string] $Source,
        [Parameter(Mandatory = $true)][string] $Destination
    )

    $destinationDir = Split-Path -Parent $Destination
    New-Item -ItemType Directory -Force -Path $destinationDir | Out-Null

    # Replace via a temporary sibling so interrupted installs do not leave a partially-written file.
    $tempDestination = "$Destination.tmp"
    Copy-Item -LiteralPath $Source -Destination $tempDestination -Force
    Move-Item -LiteralPath $tempDestination -Destination $Destination -Force
}

function Normalize-PathSegment {
    param([Parameter(Mandatory = $true)][string] $Path)
    return ([System.IO.Path]::GetFullPath($Path)).Trim().TrimEnd([char[]]@("\", "/"))
}

function Add-UserPath {
    param([Parameter(Mandatory = $true)][string] $BinDir)

    $normalizedBinDir = Normalize-PathSegment -Path $BinDir
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $segments = @()
    if (-not [string]::IsNullOrWhiteSpace($userPath)) {
        $segments = $userPath -split ";" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    }

    # Keep the installed msb first in the persistent user PATH so a previously-added target/
    # directory does not shadow the installed development binary in new shells.
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
    Write-Done "Placed $BinDir first in the persistent user PATH."
    Write-Info "Open a new terminal, or run this in the current PowerShell tab:"
    Write-Host "    `$env:Path = `"$BinDir;`$env:Path`""
}

#--------------------------------------------------------------------------------------------------
# Functions: Toolchain
#--------------------------------------------------------------------------------------------------

function Resolve-WindowsTarget {
    $architecture = if (-not [string]::IsNullOrWhiteSpace($env:MSB_WINDOWS_TARGET_ARCH)) {
        $env:MSB_WINDOWS_TARGET_ARCH
    } else {
        $null
    }

    if ([string]::IsNullOrWhiteSpace($architecture)) {
        try {
            # Some Windows package managers currently install x64 just.exe on ARM64 Windows. In that
            # case .NET and environment variables can describe the emulated process. WMI/CIM reports
            # the native CPU architecture, which is the target we want for local development builds.
            $processor = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1
            switch ([int] $processor.Architecture) {
                9 { $architecture = "AMD64" }
                12 { $architecture = "ARM64" }
            }
        } catch {
            $architecture = $null
        }
    }

    if ([string]::IsNullOrWhiteSpace($architecture)) {
        if (-not [string]::IsNullOrWhiteSpace($env:PROCESSOR_ARCHITEW6432)) {
            $architecture = $env:PROCESSOR_ARCHITEW6432
        } elseif (-not [string]::IsNullOrWhiteSpace($env:PROCESSOR_ARCHITECTURE)) {
            $architecture = $env:PROCESSOR_ARCHITECTURE
        } else {
            $architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        }
    }

    switch ($architecture.ToUpperInvariant()) {
        "ARM64" {
            return @{
                RustTarget = "aarch64-pc-windows-msvc"
                MsvcArch = "arm64"
                HostArch = "arm64"
            }
        }
        { $_ -eq "AMD64" -or $_ -eq "X64" } {
            return @{
                RustTarget = "x86_64-pc-windows-msvc"
                MsvcArch = "amd64"
                HostArch = "amd64"
            }
        }
        default {
            throw "unsupported Windows architecture: $architecture"
        }
    }
}

function Resolve-VsDevCmd {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path -LiteralPath $vswhere) {
        $installPath = & $vswhere -latest -products * -property installationPath
        if (-not [string]::IsNullOrWhiteSpace($installPath)) {
            $candidate = Join-Path $installPath "Common7\Tools\VsDevCmd.bat"
            if (Test-Path -LiteralPath $candidate) {
                return $candidate
            }
        }
    }

    $known = @(
        "$env:ProgramFiles\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat",
        "$env:ProgramFiles\Microsoft Visual Studio\18\BuildTools\Common7\Tools\VsDevCmd.bat",
        "$env:ProgramFiles\Microsoft Visual Studio\17\Community\Common7\Tools\VsDevCmd.bat",
        "$env:ProgramFiles\Microsoft Visual Studio\17\BuildTools\Common7\Tools\VsDevCmd.bat"
    )

    foreach ($candidate in $known) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    throw "Visual Studio developer command prompt was not found. Install Visual Studio Build Tools with MSVC, Windows SDK, and C++ Clang tools."
}

function Invoke-MsvcCommand {
    param([Parameter(Mandatory = $true)][string] $CommandLine)

    $target = Resolve-WindowsTarget
    $devCmd = Resolve-VsDevCmd
    $cmdLine = "call `"$devCmd`" -arch=$($target.MsvcArch) -host_arch=$($target.HostArch) >nul && cd /d `"$RepoRoot`" && $CommandLine"
    cmd.exe /c $cmdLine
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

function Test-MsvcTools {
    $target = Resolve-WindowsTarget
    $devCmd = Resolve-VsDevCmd
    $cmdLine = "call `"$devCmd`" -arch=$($target.MsvcArch) -host_arch=$($target.HostArch) >nul && where cl.exe >nul && where link.exe >nul && where clang.exe >nul"
    cmd.exe /c $cmdLine
    if ($LASTEXITCODE -ne 0) {
        throw "Visual Studio toolchain is incomplete. Install MSVC, Windows SDK, and C++ Clang tools, then retry from a new shell."
    }
}

function Require-Command {
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][string] $Hint
    )

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "$Name was not found. $Hint"
    }
}

function Resolve-PreCommitCommand {
    $candidates = @("pre-commit.exe", "pre-commit")
    foreach ($candidate in $candidates) {
        $command = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($command) {
            return $command.Source
        }
    }

    return $null
}

#--------------------------------------------------------------------------------------------------
# Functions: Commands
#--------------------------------------------------------------------------------------------------

function Invoke-InstallDevDeps {
    Write-Info "Checking Windows development prerequisites..."
    Require-Command -Name "git.exe" -Hint "Install Git for Windows and add it to PATH."
    Require-Command -Name "cargo.exe" -Hint "Install Rust from https://rustup.rs/."
    Require-Command -Name "rustup.exe" -Hint "Install Rust from https://rustup.rs/."
    $null = Resolve-VsDevCmd
    Test-MsvcTools

    if (-not (Resolve-PreCommitCommand)) {
        Write-Warn "pre-commit was not found; setup will skip Git hook installation. Install it with pip install pre-commit."
    }

    $libkrunfwKernel = Join-Path $RepoRoot "vendor\libkrunfw\kernel.c"
    if (-not (Test-Path -LiteralPath $libkrunfwKernel) -and -not (Get-Command "docker.exe" -ErrorAction SilentlyContinue)) {
        throw "docker.exe was not found. Docker Desktop is required when vendor/libkrunfw/kernel.c has not already been generated."
    }

    Write-Done "Windows development prerequisites are available."
}

function Invoke-BuildAgentd {
    Write-Info "Using prebuilt agentd for Windows development builds."
    Write-Done "agentd is embedded by the filesystem crate during cargo build."
}

function Invoke-BuildLibkrunfw {
    Write-Info "Building libkrunfw.dll..."
    $submodule = Join-Path $RepoRoot "vendor\libkrunfw"
    $script = Join-Path $submodule "scripts\build-windows.ps1"
    if (-not (Test-Path -LiteralPath $script)) {
        throw "vendor/libkrunfw is not initialized. Run: git submodule update --init --recursive vendor/libkrunfw"
    }

    $target = Resolve-WindowsTarget
    Push-Location $submodule
    try {
        & $script -AbiVersion $LibkrunfwAbi -Architecture $target.MsvcArch -HostArchitecture $target.HostArch -Output "libkrunfw.dll" -ImportLibrary "libkrunfw.lib"
        if ($LASTEXITCODE -ne 0) {
            exit $LASTEXITCODE
        }
    } finally {
        Pop-Location
    }

    New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
    Copy-Item -LiteralPath (Join-Path $submodule "libkrunfw.dll") -Destination (Join-Path $BuildDir "libkrunfw.dll") -Force
    Write-Done "Built $BuildDir\libkrunfw.dll"
}

function Invoke-EnsureLibkrunfw {
    $installed = Join-Path (Resolve-InstallRoot) "lib\libkrunfw.dll"
    $built = Join-Path $BuildDir "libkrunfw.dll"
    if (Test-Path -LiteralPath $built) {
        Write-Done "Found libkrunfw.dll in build/"
        return
    }
    if (Test-Path -LiteralPath $installed) {
        New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
        Copy-Item -LiteralPath $installed -Destination $built -Force
        Write-Done "Found libkrunfw.dll in $installed and staged it in build/"
        return
    }

    Write-Info "libkrunfw.dll not found; building from source..."
    Invoke-BuildLibkrunfw
}

function Invoke-BuildMsb {
    Write-Info "Building msb.exe ($Mode)..."
    $target = Resolve-WindowsTarget
    rustup.exe target add $target.RustTarget
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    $profileArg = if ($Mode -eq "release") { "--release" } else { "" }
    Invoke-MsvcCommand -CommandLine "cargo build -p microsandbox-cli --target $($target.RustTarget) $profileArg"

    $profile = if ($Mode -eq "release") { "release" } else { "debug" }
    $msbSource = Join-Path $RepoRoot "target\$($target.RustTarget)\$profile\msb.exe"
    if (-not (Test-Path -LiteralPath $msbSource)) {
        throw "msb.exe was not produced at $msbSource"
    }

    New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
    Copy-Item -LiteralPath $msbSource -Destination (Join-Path $BuildDir "msb.exe") -Force
    Write-Done "Built $BuildDir\msb.exe"
}

function Invoke-BuildDeps {
    Invoke-BuildAgentd
    Invoke-BuildLibkrunfw
}

function Invoke-Build {
    Invoke-BuildMsb
    Invoke-EnsureLibkrunfw
}

function Invoke-Install {
    $msbSource = Join-Path $BuildDir "msb.exe"
    $libSource = Join-Path $BuildDir "libkrunfw.dll"
    if (-not (Test-Path -LiteralPath $msbSource)) {
        throw "build/msb.exe not found. Run 'just build' first."
    }
    if (-not (Test-Path -LiteralPath $libSource)) {
        throw "build/libkrunfw.dll not found. Run 'just build-deps' first."
    }

    $installRoot = Resolve-InstallRoot
    $binDir = Join-Path $installRoot "bin"
    $libDir = Join-Path $installRoot "lib"
    Copy-InstalledFile -Source $msbSource -Destination (Join-Path $binDir "msb.exe")
    Copy-InstalledFile -Source $msbSource -Destination (Join-Path $binDir "microsandbox.exe")
    Copy-InstalledFile -Source $libSource -Destination (Join-Path $libDir "libkrunfw.dll")
    Add-UserPath -BinDir $binDir
    Write-Done "Installed msb and libkrunfw under $installRoot"
}

function Invoke-Uninstall {
    $installRoot = Resolve-InstallRoot
    $binDir = Join-Path $installRoot "bin"
    $libDir = Join-Path $installRoot "lib"
    Assert-PathInside -Parent $installRoot -Child $binDir
    Assert-PathInside -Parent $installRoot -Child $libDir
    Remove-KnownPath -Path (Join-Path $binDir "msb.exe")
    Remove-KnownPath -Path (Join-Path $binDir "microsandbox.exe")
    Remove-KnownPath -Path (Join-Path $libDir "libkrunfw.dll")
    Write-Done "Removed installed msb and libkrunfw from $installRoot"
}

function Invoke-Clean {
    Assert-PathInside -Parent $RepoRoot -Child $BuildDir
    Remove-KnownPath -Path $BuildDir

    $submodule = Join-Path $RepoRoot "vendor\libkrunfw"
    $generatedLibkrunfwFiles = @("libkrunfw.dll", "libkrunfw.lib", "libkrunfw.exp", "libkrunfw.pdb", "kernel.obj")
    foreach ($file in $generatedLibkrunfwFiles) {
        $path = Join-Path $submodule $file
        Assert-PathInside -Parent $submodule -Child $path
        Remove-KnownPath -Path $path
    }

    Write-Done "Removed build/ and Windows libkrunfw link artifacts."
}

function Invoke-Setup {
    Invoke-InstallDevDeps

    Write-Info "Initializing submodules..."
    git.exe submodule update --init --recursive
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    Write-Info "Building dependencies..."
    Invoke-BuildDeps

    Write-Info "Building microsandbox..."
    Invoke-Build

    Write-Info "Installing..."
    Invoke-Install

    Write-Info "Setting up pre-commit hooks..."
    $preCommit = Resolve-PreCommitCommand
    if ($preCommit) {
        & $preCommit install
        if ($LASTEXITCODE -ne 0) {
            exit $LASTEXITCODE
        }
    } else {
        Write-Warn "Skipping pre-commit hooks because pre-commit is not installed."
    }

    Write-Done "Setup complete."
}

#--------------------------------------------------------------------------------------------------
# Main
#--------------------------------------------------------------------------------------------------

Push-Location $RepoRoot
try {
    switch ($Command) {
        "setup" { Invoke-Setup }
        "install-dev-deps" { Invoke-InstallDevDeps }
        "build-deps" { Invoke-BuildDeps }
        "build-agentd" { Invoke-BuildAgentd }
        "build-libkrunfw" { Invoke-BuildLibkrunfw }
        "ensure-libkrunfw" { Invoke-EnsureLibkrunfw }
        "build-msb" { Invoke-BuildMsb }
        "build" { Invoke-Build }
        "install" { Invoke-Install }
        "uninstall" { Invoke-Uninstall }
        "clean" { Invoke-Clean }
    }
} finally {
    Pop-Location
}
