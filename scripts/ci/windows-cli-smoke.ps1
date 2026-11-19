#requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Binary,
    [Parameter(Mandatory)][string]$PrivateLogDirectory
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Binary = (Resolve-Path -LiteralPath $Binary).Path
$PrivateLogDirectory = [IO.Path]::GetFullPath($PrivateLogDirectory)
New-Item -ItemType Directory -Force -Path $PrivateLogDirectory | Out-Null

function Invoke-Msb {
    param([string]$Stage, [string[]]$Arguments, [int]$TimeoutSeconds = 120)

    $start = [Diagnostics.ProcessStartInfo]::new($Binary)
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.RedirectStandardInput = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw "$Stage could not start" }
        $process.StandardInput.Close()
        # Drain both streams concurrently so a failing child cannot fill a pipe
        # and deadlock the test. Raw output stays in a private local directory.
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill($true)
            throw "$Stage exceeded its deadline"
        }
        if (-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout, $stderr), 10000)) {
            throw "$Stage retained an output pipe after exit"
        }
        [IO.File]::WriteAllText((Join-Path $PrivateLogDirectory "$Stage.stdout.log"), $stdout.Result)
        [IO.File]::WriteAllText((Join-Path $PrivateLogDirectory "$Stage.stderr.log"), $stderr.Result)
        if ($process.ExitCode -ne 0) { throw "$Stage failed with exit code $($process.ExitCode)" }
        return $stdout.Result.Trim()
    } finally {
        $process.Dispose()
    }
}

$root = Join-Path ([IO.Path]::GetTempPath()) ('msb-windows-cli-' + [Guid]::NewGuid().ToString('N'))
$shared = Join-Path $root 'shared files'
$outside = Join-Path $root 'outside'
$junction = Join-Path $shared 'escape'
$name = 'windows-cli-' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
$previousHome = $env:MSB_HOME
New-Item -ItemType Directory -Path $shared, $outside | Out-Null
[IO.File]::WriteAllText((Join-Path $shared 'host.txt'), 'host-fixture')
[IO.File]::WriteAllText((Join-Path $outside 'sentinel.txt'), 'outside-fixture')
New-Item -ItemType Junction -Path $junction -Target $outside | Out-Null
$env:MSB_HOME = Join-Path $root 'state'
$attempted = $false
$failure = $null
$removed = $false

try {
    $attempted = $true
    Invoke-Msb 'create' @(
        'create', 'mirror.gcr.io/library/alpine:3.22', '--name', $name,
        '--cpus', '1', '--memory', '512', '--quiet',
        '--mount-dir', "${shared}:/work", '--mount-dir', "${shared}:/readonly:ro"
    ) | Out-Null
    $guest = @'
set -eu
test "$(cat /work/host.txt)" = host-fixture
test "$(ls -1 /work)" = host.txt
test ! -e /work/escape/sentinel.txt
printf guest-fixture > /work/guest.txt
if printf forbidden > /readonly/forbidden.txt 2>/dev/null; then exit 1; fi
printf windows-cli-ready
'@
    # Git checkouts on Windows may use CRLF; the Linux shell needs LF.
    $guest = $guest.Replace("`r`n", "`n")
    $output = Invoke-Msb 'exec' @('exec', $name, '--no-stdin', '--timeout', '30s', '--', 'sh', '-c', $guest)
    if ($output -ne 'windows-cli-ready') { throw 'CLI guest returned unexpected output' }
    if ([IO.File]::ReadAllText((Join-Path $shared 'guest.txt')) -ne 'guest-fixture') {
        throw 'CLI bind mount did not preserve the guest write'
    }
    if (Test-Path -LiteralPath (Join-Path $shared 'forbidden.txt')) { throw 'CLI read-only mount accepted a write' }
    if ([IO.File]::ReadAllText((Join-Path $outside 'sentinel.txt')) -ne 'outside-fixture') {
        throw 'CLI junction changed a file outside the bind root'
    }
    Invoke-Msb 'stop' @('stop', '--timeout', '30', '--quiet', $name) 60 | Out-Null
    Invoke-Msb 'remove' @('remove', '--quiet', $name) 60 | Out-Null
    $removed = $true
    Write-Output 'PASS: Windows CLI boot, exec, mounts, confinement, stop, and remove'
} catch {
    $failure = $_
    throw
} finally {
    try {
        if ($attempted -and -not $removed) {
            try {
                Invoke-Msb 'cleanup' @('remove', '--force', '--quiet', $name) 60 | Out-Null
            } catch {
                if ($null -eq $failure) { throw }
                Write-Warning 'CLI cleanup also failed; preserve the original test failure'
            }
        }
    } finally {
        $env:MSB_HOME = $previousHome
        # Unlink the junction explicitly before recursively deleting our fixture.
        # Cleanup must never traverse the synthetic outside-directory link.
        try {
            if (Test-Path -LiteralPath $junction) { [IO.Directory]::Delete($junction) }
            Remove-Item -LiteralPath $root -Recurse -Force
        } catch {
            if ($null -eq $failure) { throw }
            Write-Warning 'CLI fixture cleanup also failed; preserve the original test failure'
        }
    }
}
