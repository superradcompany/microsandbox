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

function Assert-ExecutableNotRunning {
    param([Parameter(Mandatory = $true)][string] $Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    $extension = [System.IO.Path]::GetExtension($Path)
    if ($extension -ine ".exe") {
        return
    }

    $target = Normalize-PathSegment -Path $Path
    $name = [System.IO.Path]::GetFileName($Path)
    $processes = Get-CimInstance Win32_Process -Filter "name = '$name'" -ErrorAction SilentlyContinue |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace($_.ExecutablePath) -and
                (Normalize-PathSegment -Path $_.ExecutablePath) -ieq $target
        }

    if ($processes) {
        $ids = ($processes | ForEach-Object { $_.ProcessId }) -join ", "
        throw "cannot replace $Path because it is still running (pid: $ids). Stop the active sandboxes or msb processes, then rerun just install."
    }
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
    Assert-ExecutableNotRunning -Path $Destination
    Copy-Item -LiteralPath $Source -Destination $tempDestination -Force
    Remove-KnownPath -Path $Destination
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

    throw "Visual Studio developer command prompt was not found. Install Visual Studio Build Tools with MSVC and Windows SDK."
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
    $cmdLine = "call `"$devCmd`" -arch=$($target.MsvcArch) -host_arch=$($target.HostArch) >nul && where cl.exe >nul 2>nul && where link.exe >nul 2>nul && where rc.exe >nul 2>nul"
    cmd.exe /c $cmdLine
    if ($LASTEXITCODE -ne 0) {
        throw "Visual Studio toolchain is incomplete. Install MSVC and Windows SDK, then retry from a new shell."
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
# Functions: Linux Build Backend
#--------------------------------------------------------------------------------------------------

function Resolve-WslDistro {
    if (-not [string]::IsNullOrWhiteSpace($env:MSB_WSL_DISTRO)) {
        return $env:MSB_WSL_DISTRO
    }

    return "Ubuntu"
}

function Get-DockerOsType {
    $docker = Get-Command docker.exe -ErrorAction SilentlyContinue
    if (-not $docker) {
        return $null
    }

    $osType = & docker.exe info --format "{{.OSType}}" 2>$null
    if ($LASTEXITCODE -ne 0) {
        return $null
    }

    return ($osType | Select-Object -First 1).Trim().ToLowerInvariant()
}

function Test-DockerLinuxContainers {
    return (Get-DockerOsType) -eq "linux"
}

function Test-WslAvailable {
    $wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
    if (-not $wsl) {
        return $false
    }

    $distro = Resolve-WslDistro
    & wsl.exe -d $distro -- true 2>$null
    return $LASTEXITCODE -eq 0
}

function Resolve-LinuxBuildBackend {
    $requested = if ([string]::IsNullOrWhiteSpace($env:MSB_WINDOWS_LINUX_BUILD_BACKEND)) {
        "auto"
    } else {
        $env:MSB_WINDOWS_LINUX_BUILD_BACKEND.ToLowerInvariant()
    }

    if ($requested -notin @("auto", "docker", "wsl")) {
        throw "MSB_WINDOWS_LINUX_BUILD_BACKEND must be one of: auto, docker, wsl"
    }

    if ($requested -eq "docker") {
        if (Test-DockerLinuxContainers) {
            return "docker"
        }

        $dockerOs = Get-DockerOsType
        if ([string]::IsNullOrWhiteSpace($dockerOs)) {
            throw "Docker Linux containers are required, but docker.exe is unavailable or not running."
        }

        throw "Docker is running $dockerOs containers. Switch Docker to Linux containers or set MSB_WINDOWS_LINUX_BUILD_BACKEND=wsl."
    }

    if ($requested -eq "wsl") {
        if (Test-WslAvailable) {
            return "wsl"
        }

        throw "WSL distro '$(Resolve-WslDistro)' is not available. Install Ubuntu with `wsl --install -d Ubuntu`, or set MSB_WSL_DISTRO."
    }

    if (Test-DockerLinuxContainers) {
        return "docker"
    }

    $dockerOs = Get-DockerOsType
    if ($dockerOs -eq "windows") {
        Write-Warn "docker.exe is running Windows containers; Linux build steps will use WSL."
    }

    if (Test-WslAvailable) {
        return "wsl"
    }

    throw "No Linux build backend is available. Install Docker Desktop with Linux containers, or install Ubuntu WSL and set MSB_WINDOWS_LINUX_BUILD_BACKEND=wsl."
}

function Resolve-AgentdLinuxTarget {
    $target = Resolve-WindowsTarget
    if ($target.MsvcArch -eq "arm64") {
        return "aarch64-unknown-linux-musl"
    }

    return "x86_64-unknown-linux-musl"
}

function Quote-Bash {
    param([Parameter(Mandatory = $true)][string] $Value)
    return "'" + $Value.Replace("'", "'\''") + "'"
}

function ConvertTo-WslPath {
    param(
        [Parameter(Mandatory = $true)][string] $Distro,
        [Parameter(Mandatory = $true)][string] $Path
    )

    # wsl.exe treats backslashes as Linux-side escapes when forwarding argv.
    # Double them so wslpath receives a real Windows path like C:\Users\...
    $wslPathInput = $Path.Replace('\', '\\')
    $converted = & wsl.exe -d $Distro -- wslpath -a $wslPathInput
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($converted)) {
        throw "failed to convert Windows path for WSL: $Path"
    }

    return ($converted | Select-Object -First 1).Trim()
}

function ConvertTo-WslBashCommand {
    param([Parameter(Mandatory = $true)][string] $Command)

    # PowerShell here-strings use CRLF on Windows, but Bash treats the CR as
    # part of tokens such as pipefail. Normalize before passing through wsl.exe.
    return $Command.Replace("`r`n", "`n").Replace("`r", "`n")
}

function Test-WslBash {
    param(
        [Parameter(Mandatory = $true)][string] $Distro,
        [Parameter(Mandatory = $true)][string] $Command
    )

    $commandText = ConvertTo-WslBashCommand -Command $Command
    & wsl.exe -d $Distro -- bash -lc $commandText
    return $LASTEXITCODE -eq 0
}

function Invoke-WslBash {
    param(
        [Parameter(Mandatory = $true)][string] $Distro,
        [Parameter(Mandatory = $true)][string] $Command
    )

    $commandText = ConvertTo-WslBashCommand -Command $Command
    & wsl.exe -d $Distro -- bash -lc $commandText
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

function Invoke-WslBashScript {
    param(
        [Parameter(Mandatory = $true)][string] $Distro,
        [Parameter(Mandatory = $true)][string] $Script,
        [string[]] $Arguments = @()
    )

    $scriptPath = Join-Path ([System.IO.Path]::GetTempPath()) "msb-wsl-$([System.Guid]::NewGuid().ToString("N")).sh"
    try {
        $scriptText = ConvertTo-WslBashCommand -Command $Script
        [System.IO.File]::WriteAllText($scriptPath, $scriptText, [System.Text.Encoding]::ASCII)
        $scriptWsl = ConvertTo-WslPath -Distro $Distro -Path $scriptPath
        & wsl.exe -d $Distro -- bash $scriptWsl @Arguments
        if ($LASTEXITCODE -ne 0) {
            exit $LASTEXITCODE
        }
    } finally {
        Remove-KnownPath -Path $scriptPath
    }
}

function Get-WslBuildPackages {
    return "build-essential musl-tools flex bison libelf-dev libssl-dev bc python3 python3-pyelftools curl xz-utils patch"
}

function Test-WslAgentdBuildTools {
    $distro = Resolve-WslDistro
    $command = "source `"`$HOME/.cargo/env`" 2>/dev/null || true; command -v cargo >/dev/null && command -v rustup >/dev/null && command -v musl-gcc >/dev/null && command -v gcc >/dev/null"

    if (-not (Test-WslBash -Distro $distro -Command $command)) {
        throw "WSL distro '$distro' is missing Rust or musl build tools. Install Rust and Ubuntu packages: sudo apt update && sudo apt install -y $(Get-WslBuildPackages)"
    }
}

function Test-WslLibkrunfwBuildTools {
    $distro = Resolve-WslDistro
    $command = "command -v make >/dev/null && command -v python3 >/dev/null && command -v gcc >/dev/null && command -v flex >/dev/null && command -v bison >/dev/null && command -v bc >/dev/null && command -v curl >/dev/null && command -v tar >/dev/null && command -v xz >/dev/null && command -v patch >/dev/null && test -e /usr/include/libelf.h && test -e /usr/include/openssl/ssl.h && python3 -c 'import elftools' >/dev/null"

    if (-not (Test-WslBash -Distro $distro -Command $command)) {
        throw "WSL distro '$distro' is missing kernel build tools. Install Ubuntu packages: sudo apt update && sudo apt install -y $(Get-WslBuildPackages)"
    }
}

function Test-WslBuildTools {
    Test-WslAgentdBuildTools
    Test-WslLibkrunfwBuildTools
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

    $backend = Resolve-LinuxBuildBackend
    if ($backend -eq "docker") {
        Require-Command -Name "docker.exe" -Hint "Install Docker Desktop and make sure Linux containers are enabled."
    } else {
        Test-WslBuildTools
    }

    Write-Done "Windows development prerequisites are available. Linux build backend: $backend."
}

function Invoke-BuildAgentdWithDocker {
    Write-Info "Building agentd via Docker..."
    Require-Command -Name "docker.exe" -Hint "Install Docker Desktop and make sure it is running."

    docker.exe build -f Dockerfile.agentd -t microsandbox-agentd-build .
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
    $containerId = $null
    try {
        $containerId = docker.exe create microsandbox-agentd-build /dev/null
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($containerId)) {
            throw "docker create failed while staging agentd"
        }

        $agentdPath = Join-Path $BuildDir "agentd"
        Remove-KnownPath -Path $agentdPath
        docker.exe cp "${containerId}:/agentd" $agentdPath
        if ($LASTEXITCODE -ne 0) {
            exit $LASTEXITCODE
        }
    } finally {
        if (-not [string]::IsNullOrWhiteSpace($containerId)) {
            docker.exe rm $containerId | Out-Null
        }
    }

    Write-Done "Built $BuildDir\agentd"
}

function Invoke-BuildAgentdWithWsl {
    Test-WslAgentdBuildTools

    $distro = Resolve-WslDistro
    $repo = ConvertTo-WslPath -Distro $distro -Path $RepoRoot
    $repoQuoted = Quote-Bash $repo
    $linuxTarget = Resolve-AgentdLinuxTarget

    Write-Info "Building agentd via WSL ($distro)..."
    $command = @"
set -euo pipefail
source "`$HOME/.cargo/env" 2>/dev/null || true
cd $repoQuoted
rustup target add $linuxTarget
cargo build --release --manifest-path crates/agentd/Cargo.toml --target-dir target --target $linuxTarget
mkdir -p build
cp target/$linuxTarget/release/agentd build/agentd
touch build/agentd
"@
    Invoke-WslBash -Distro $distro -Command $command
    Write-Done "Built $BuildDir\agentd"
}

function Invoke-BuildAgentd {
    $backend = Resolve-LinuxBuildBackend
    if ($backend -eq "docker") {
        Invoke-BuildAgentdWithDocker
    } else {
        Invoke-BuildAgentdWithWsl
    }
}

function Invoke-BuildLibkrunfwKernelBundleWithDocker {
    param([Parameter(Mandatory = $true)][string] $Submodule)

    Write-Info "Building libkrunfw kernel bundle via Docker..."
    Require-Command -Name "docker.exe" -Hint "Install Docker Desktop and make sure Linux containers are enabled."

    # Docker Desktop bind mounts on Windows are fine for source snapshots and final
    # artifacts, but extracting the full Linux tree there can fail partway through.
    # Build inside the container filesystem and copy only the generated C bundle out.
    $makeJobs = [Math]::Max(1, [Environment]::ProcessorCount)
    $buildScript = @'
set -euo pipefail
dnf install -y 'dnf-command(builddep)' python3-pyelftools curl
dnf builddep -y kernel

build_dir=/tmp/libkrunfw-build
rm -rf "$build_dir"
mkdir -p "$build_dir"
cleanup() {
    rm -rf "$build_dir"
}
trap cleanup EXIT

cd /work
tar --exclude='.git' \
    --exclude='./.git' \
    --exclude='kernel.c' \
    --exclude='./kernel.c' \
    --exclude='qboot.c' \
    --exclude='./qboot.c' \
    --exclude='initrd.c' \
    --exclude='./initrd.c' \
    --exclude='linux-*' \
    --exclude='./linux-*' \
    --exclude='*.dll' \
    --exclude='./*.dll' \
    --exclude='*.lib' \
    --exclude='./*.lib' \
    --exclude='*.exp' \
    --exclude='./*.exp' \
    --exclude='*.pdb' \
    --exclude='./*.pdb' \
    --exclude='*.obj' \
    --exclude='./*.obj' \
    -cf - . | tar -xf - -C "$build_dir"

cd "$build_dir"
make clean
make -j__MSB_MAKE_JOBS__ kernel.c
cp kernel.c /work/kernel.c
if [ -d tarballs ]; then
    mkdir -p /work/tarballs
    cp -a tarballs/. /work/tarballs/
fi
'@
    $buildScript = $buildScript.Replace("__MSB_MAKE_JOBS__", $makeJobs.ToString())
    $buildScript = $buildScript.Replace("`r`n", "`n").Replace("`r", "`n")
    docker.exe run --rm -v "${Submodule}:/work" -w /work fedora:latest bash -lc $buildScript
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

function Invoke-BuildLibkrunfwKernelBundleWithWsl {
    param([Parameter(Mandatory = $true)][string] $Submodule)

    Test-WslLibkrunfwBuildTools

    $distro = Resolve-WslDistro
    $submoduleWsl = ConvertTo-WslPath -Distro $distro -Path $Submodule

    Write-Info "Building libkrunfw kernel bundle via WSL ($distro)..."
    $script = @'
set -euo pipefail
source_dir="$1"
home_dir="${HOME:-}"
if [ -z "$home_dir" ] || [ ! -d "$home_dir" ] || [ ! -w "$home_dir" ]; then
    echo "error: WSL home directory is not writable: $home_dir" >&2
    exit 1
fi

work_root="$home_dir/.cache/microsandbox/libkrunfw"
cache_dir="$work_root/cache"
build_parent="$work_root/tmp"
mkdir -p "$cache_dir/tarballs" "$build_parent"
build_dir="$(mktemp -d "$build_parent/build.XXXXXX")"

cleanup() {
    rm -rf "$build_dir"
}
trap cleanup EXIT

echo "Using WSL libkrunfw cache: $cache_dir"
echo "Using WSL libkrunfw build directory: $build_dir"

if [ -d "$source_dir/tarballs" ]; then
    cp -a "$source_dir/tarballs/." "$cache_dir/tarballs/" 2>/dev/null || true
fi

cd "$source_dir"
tar --exclude='.git' \
    --exclude='./.git' \
    --exclude='kernel.c' \
    --exclude='./kernel.c' \
    --exclude='linux-*' \
    --exclude='./linux-*' \
    --exclude='tarballs' \
    --exclude='./tarballs' \
    --exclude='*.dll' \
    --exclude='./*.dll' \
    --exclude='*.lib' \
    --exclude='./*.lib' \
    --exclude='*.exp' \
    --exclude='./*.exp' \
    --exclude='*.pdb' \
    --exclude='./*.pdb' \
    --exclude='kernel.obj' \
    --exclude='./kernel.obj' \
    -cf - . | tar -xf - -C "$build_dir"

mkdir -p "$build_dir/tarballs"
cp -a "$cache_dir/tarballs/." "$build_dir/tarballs/" 2>/dev/null || true

cd "$build_dir"
make -j"$(nproc)" kernel.c
cp -a "$build_dir/tarballs/." "$cache_dir/tarballs/" 2>/dev/null || true
cp kernel.c "$source_dir/kernel.c"
'@
    Invoke-WslBashScript -Distro $distro -Script $script -Arguments @($submoduleWsl)
}

function Invoke-BuildLibkrunfwKernelBundle {
    param([Parameter(Mandatory = $true)][string] $Submodule)

    $backend = Resolve-LinuxBuildBackend
    if ($backend -eq "docker") {
        Invoke-BuildLibkrunfwKernelBundleWithDocker -Submodule $Submodule
    } else {
        Invoke-BuildLibkrunfwKernelBundleWithWsl -Submodule $Submodule
    }

    $kernelBundle = Join-Path $Submodule "kernel.c"
    if (-not (Test-Path -LiteralPath $kernelBundle)) {
        throw "libkrunfw kernel bundle was not produced at $kernelBundle"
    }
}

function New-LibkrunfwDefFile {
    param([Parameter(Mandatory = $true)][string] $Submodule)

    New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
    $defPath = Join-Path $BuildDir "libkrunfw.def"
    $exports = Select-String -Path (Join-Path $Submodule "*.c") -Pattern "^\s*[A-Za-z_][A-Za-z0-9_\s\*]*\s+(krunfw_[A-Za-z0-9_]+)\s*\(" |
        ForEach-Object { $_.Matches[0].Groups[1].Value } |
        Sort-Object -Unique

    if (-not $exports) {
        $exports = @("krunfw_get_kernel", "krunfw_get_version")
    }

    $lines = @("LIBRARY libkrunfw", "EXPORTS") + ($exports | ForEach-Object { "    $_" })
    Set-Content -LiteralPath $defPath -Encoding ASCII -Value $lines
    return $defPath
}

function Get-LibkrunfwKernelMetadata {
    param([Parameter(Mandatory = $true)][string] $Submodule)

    $kernelBundle = Join-Path $Submodule "kernel.c"
    if (-not (Test-Path -LiteralPath $kernelBundle)) {
        throw "libkrunfw kernel bundle is missing at $kernelBundle"
    }

    $loadAddr = $null
    $entryAddr = $null
    foreach ($line in [System.IO.File]::ReadLines($kernelBundle, [System.Text.Encoding]::ASCII)) {
        if ($null -eq $loadAddr -and $line -match "\*load_addr\s*=\s*([^;]+);") {
            $loadAddr = $Matches[1].Trim()
        } elseif ($null -eq $entryAddr -and $line -match "\*entry_addr\s*=\s*([^;]+);") {
            $entryAddr = $Matches[1].Trim()
        }

        if ($null -ne $loadAddr -and $null -ne $entryAddr) {
            break
        }
    }

    if ($null -eq $loadAddr -or $null -eq $entryAddr) {
        throw "failed to read libkrunfw kernel load metadata from $kernelBundle"
    }

    return @{
        LoadAddr = $loadAddr
        EntryAddr = $entryAddr
    }
}

function New-LibkrunfwKernelBinary {
    param([Parameter(Mandatory = $true)][string] $Submodule)

    $kernelBundle = Join-Path $Submodule "kernel.c"
    if (-not (Test-Path -LiteralPath $kernelBundle)) {
        throw "libkrunfw kernel bundle is missing at $kernelBundle"
    }

    New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
    $kernelBinary = Join-Path $BuildDir "libkrunfw-kernel.bin"
    if ((Test-Path -LiteralPath $kernelBinary) -and
        ((Get-Item -LiteralPath $kernelBinary).LastWriteTimeUtc -ge (Get-Item -LiteralPath $kernelBundle).LastWriteTimeUtc)) {
        return $kernelBinary
    }

    Write-Info "Extracting libkrunfw kernel bytes from generated bundle..."
    $reader = [System.IO.StreamReader]::new($kernelBundle, [System.Text.Encoding]::ASCII)
    $writer = [System.IO.File]::Open($kernelBinary, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    $buffer = [byte[]]::new(65536)
    $count = 0
    $total = 0
    try {
        while ($null -ne ($line = $reader.ReadLine())) {
            $matches = [regex]::Matches($line, "\\x([0-9a-fA-F]{1,2})")
            foreach ($match in $matches) {
                $buffer[$count] = [Convert]::ToByte($match.Groups[1].Value, 16)
                $count += 1
                $total += 1
                if ($count -eq $buffer.Length) {
                    $writer.Write($buffer, 0, $count)
                    $count = 0
                }
            }
        }

        if ($count -gt 0) {
            $writer.Write($buffer, 0, $count)
        }
    } finally {
        $writer.Dispose()
        $reader.Dispose()
    }

    if ($total -eq 0) {
        throw "failed to extract libkrunfw kernel bytes from $kernelBundle"
    }

    return $kernelBinary
}

function ConvertTo-RcString {
    param([Parameter(Mandatory = $true)][string] $Value)

    return '"' + $Value.Replace('\', '\\').Replace('"', '\"') + '"'
}

function New-WindowsLibkrunfwLinkSources {
    param([Parameter(Mandatory = $true)][string] $Submodule)

    $metadata = Get-LibkrunfwKernelMetadata -Submodule $Submodule
    $kernelBinary = New-LibkrunfwKernelBinary -Submodule $Submodule
    $resourceId = 101
    $resourceRc = Join-Path $BuildDir "libkrunfw-kernel.rc"
    $resourceRes = Join-Path $BuildDir "libkrunfw-kernel.res"
    $wrapper = Join-Path $BuildDir "libkrunfw-windows.c"
    $kernelBinaryRc = ConvertTo-RcString -Value $kernelBinary

    $resourceLines = @(
        "#define IDR_LIBKRUNFW_KERNEL $resourceId",
        "IDR_LIBKRUNFW_KERNEL RCDATA $kernelBinaryRc"
    )
    Set-Content -LiteralPath $resourceRc -Encoding ASCII -Value $resourceLines

    $wrapperSource = @"
#define WIN32_LEAN_AND_MEAN
#include <stddef.h>
#include <windows.h>

#define IDR_LIBKRUNFW_KERNEL $resourceId

static char *KERNEL_BUNDLE = NULL;
static size_t KERNEL_BUNDLE_SIZE = 0;

static int krunfw_load_kernel_bundle(void)
{
    HMODULE module = NULL;
    HRSRC resource = NULL;
    HGLOBAL loaded = NULL;
    DWORD resource_size = 0;
    void *resource_data = NULL;

    if (KERNEL_BUNDLE != NULL) {
        return 1;
    }

    if (!GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)&krunfw_load_kernel_bundle,
            &module)) {
        return 0;
    }

    resource = FindResourceA(module, MAKEINTRESOURCEA(IDR_LIBKRUNFW_KERNEL), RT_RCDATA);
    if (resource == NULL) {
        return 0;
    }

    resource_size = SizeofResource(module, resource);
    loaded = LoadResource(module, resource);
    resource_data = LockResource(loaded);
    if (resource_size == 0 || loaded == NULL || resource_data == NULL) {
        return 0;
    }

    KERNEL_BUNDLE = (char *)VirtualAlloc(NULL, resource_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (KERNEL_BUNDLE == NULL) {
        return 0;
    }

    CopyMemory(KERNEL_BUNDLE, resource_data, resource_size);
    KERNEL_BUNDLE_SIZE = (size_t)resource_size;
    return 1;
}

char * krunfw_get_kernel(size_t *load_addr, size_t *entry_addr, size_t *size)
{
    if (load_addr != NULL) {
        *load_addr = $($metadata.LoadAddr);
    }
    if (entry_addr != NULL) {
        *entry_addr = $($metadata.EntryAddr);
    }
    if (size != NULL) {
        *size = 0;
    }

    if (!krunfw_load_kernel_bundle()) {
        return NULL;
    }

    if (size != NULL) {
        *size = KERNEL_BUNDLE_SIZE;
    }
    return KERNEL_BUNDLE;
}

int krunfw_get_version()
{
    return ABI_VERSION;
}
"@
    Set-Content -LiteralPath $wrapper -Encoding ASCII -Value $wrapperSource

    return @{
        ResourceRc = $resourceRc
        ResourceRes = $resourceRes
        Wrapper = $wrapper
    }
}

function Invoke-LinkLibkrunfwDll {
    param([Parameter(Mandatory = $true)][string] $Submodule)

    $kernelBundle = Join-Path $Submodule "kernel.c"
    if (-not (Test-Path -LiteralPath $kernelBundle)) {
        throw "libkrunfw kernel bundle is missing at $kernelBundle"
    }

    $defPath = New-LibkrunfwDefFile -Submodule $Submodule
    $sources = New-WindowsLibkrunfwLinkSources -Submodule $Submodule
    Write-Info "Linking libkrunfw.dll with cl.exe..."
    Invoke-MsvcCommand -CommandLine "cd /d `"$Submodule`" && rc.exe /nologo /fo`"$($sources.ResourceRes)`" `"$($sources.ResourceRc)`" && cl.exe /nologo /LD /DABI_VERSION=$LibkrunfwAbi /Fo:libkrunfw.obj /Fe:libkrunfw.dll `"$($sources.Wrapper)`" `"$($sources.ResourceRes)`" /link /DEF:`"$defPath`" /IMPLIB:libkrunfw.lib"
}

function Invoke-BuildLibkrunfw {
    Write-Info "Building libkrunfw.dll..."
    $submodule = Join-Path $RepoRoot "vendor\libkrunfw"
    $script = Join-Path $submodule "scripts\build-windows.ps1"
    if (-not (Test-Path -LiteralPath $submodule)) {
        throw "vendor/libkrunfw is not initialized. Run: git submodule update --init --recursive vendor/libkrunfw"
    }

    if (Test-Path -LiteralPath $script) {
        $backend = Resolve-LinuxBuildBackend
        if ($backend -eq "wsl") {
            # The libkrunfw helper compiles the generated kernel C bundle
            # directly, which can exhaust MSVC heap on x64. Build kernel.c via
            # WSL, then link a small Windows wrapper that embeds the kernel as
            # a resource so cl.exe never has to parse the full byte array.
            Invoke-BuildLibkrunfwKernelBundleWithWsl -Submodule $submodule
            Invoke-LinkLibkrunfwDll -Submodule $submodule
        } else {
            $target = Resolve-WindowsTarget
            Push-Location $submodule
            try {
                $scriptArgs = @{
                    AbiVersion = $LibkrunfwAbi
                    Architecture = $target.MsvcArch
                    HostArchitecture = $target.HostArch
                    Output = "libkrunfw.dll"
                    ImportLibrary = "libkrunfw.lib"
                }

                if (Test-Path -LiteralPath (Join-Path $submodule "kernel.c")) {
                    $scriptArgs.SkipKernelBundle = $true
                }

                & $script @scriptArgs
                if ($LASTEXITCODE -ne 0) {
                    exit $LASTEXITCODE
                }
            } finally {
                Pop-Location
            }
        }
    } else {
        Invoke-BuildLibkrunfwKernelBundle -Submodule $submodule
        Invoke-LinkLibkrunfwDll -Submodule $submodule
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
    $previousRustflags = $env:RUSTFLAGS
    if ($Mode -eq "release") {
        # Match release CI so installed Windows builds do not require a separate VC++ runtime.
        $env:RUSTFLAGS = (@($previousRustflags, "-C target-feature=+crt-static") | Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            }) -join " "
    }

    try {
        Invoke-MsvcCommand -CommandLine "cargo build -p microsandbox-cli --target $($target.RustTarget) $profileArg"
    } finally {
        $env:RUSTFLAGS = $previousRustflags
    }

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
} catch {
    Write-Host "error: " -ForegroundColor Red -NoNewline
    Write-Host $_.Exception.Message
    exit 1
} finally {
    Pop-Location
}
