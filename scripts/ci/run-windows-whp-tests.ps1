#requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ArtifactDirectory,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$Revision
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$privateRoot = Join-Path ([IO.Path]::GetTempPath()) ('windows-whp-' + [Guid]::NewGuid().ToString('N'))
$stage = 'artifact'
$failureClass = 'infrastructure'

function Invoke-Stage {
    param([string]$Program, [string[]]$Arguments, [int]$TimeoutSeconds)

    $start = [Diagnostics.ProcessStartInfo]::new($Program)
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.RedirectStandardInput = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw 'Process could not start' }
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill($true)
            throw 'Stage exceeded its deadline'
        }
        if (-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout, $stderr), 10000)) {
            throw 'Stage retained an output pipe after exit'
        }
        # Never upload raw output: runtime diagnostics can contain host paths or
        # network details. Only the allowlisted stage results reach public CI.
        [IO.File]::WriteAllText((Join-Path $privateRoot "$stage.stdout.log"), $stdout.Result)
        [IO.File]::WriteAllText((Join-Path $privateRoot "$stage.stderr.log"), $stderr.Result)
        if ($process.ExitCode -ne 0) { throw 'Stage exited unsuccessfully' }
        return $stdout.Result
    } finally {
        $process.Dispose()
    }
}

$previous = @{}
foreach ($name in @('MSB_HOME', 'MSB_PATH', 'MSB_LIBKRUNFW_PATH', 'MSB_TEST_ISOLATE_HOME')) {
    $previous[$name] = [Environment]::GetEnvironmentVariable($name)
}
$exitCode = 1
try {
    $ArtifactDirectory = (Resolve-Path -LiteralPath $ArtifactDirectory).Path
    New-Item -ItemType Directory -Path $privateRoot | Out-Null
    $manifest = Get-Content -LiteralPath (Join-Path $ArtifactDirectory 'revision.json') -Raw | ConvertFrom-Json
    if ($manifest.revision -cne $Revision) { throw 'Artifact revision mismatch' }
    foreach ($file in @('msb.exe', 'libkrunfw.dll', 'filesystem-tests.exe', 'sdk-tests.exe', 'windows-whp-preflight.ps1', 'windows-cli-smoke.ps1')) {
        if (-not (Test-Path -LiteralPath (Join-Path $ArtifactDirectory $file) -PathType Leaf)) {
            throw 'Artifact is incomplete'
        }
    }
    $env:MSB_PATH = Join-Path $ArtifactDirectory 'msb.exe'
    $env:MSB_LIBKRUNFW_PATH = Join-Path $ArtifactDirectory 'libkrunfw.dll'
    $env:MSB_HOME = Join-Path $privateRoot 'sdk-state'
    # This executable contains exactly one test. Give its process an isolated
    # home directly, without depending on a previously installed host runtime.
    $env:MSB_TEST_ISOLATE_HOME = $null
    $pwsh = (Get-Process -Id $PID).Path

    $stage = 'whp-preflight'
    Invoke-Stage $pwsh @('-NoProfile', '-NonInteractive', '-File', (Join-Path $ArtifactDirectory 'windows-whp-preflight.ps1')) 30 | Out-Null
    Write-Output 'PASS: Windows nested WHP execution'
    $osVersion = (Get-CimInstance Win32_OperatingSystem).Version
    if ($osVersion -notmatch '^\d+\.\d+\.\d+$') { throw 'Unexpected OS version format' }
    Write-Output ("INFO: Windows $osVersion; revision $Revision")

    $failureClass = 'test'
    $stage = 'filesystem'
    $output = Invoke-Stage (Join-Path $ArtifactDirectory 'filesystem-tests.exe') @('--test-threads=1') 180
    if ($output -notmatch 'test result: ok\. ([1-9][0-9]*) passed; 0 failed; 0 ignored;') {
        throw 'Filesystem suite did not run successfully'
    }
    Write-Output ("PASS: Windows filesystem suite ($($Matches[1]) tests)")

    $stage = 'cli'
    Invoke-Stage $pwsh @('-NoProfile', '-NonInteractive', '-File', (Join-Path $ArtifactDirectory 'windows-cli-smoke.ps1'), '-Binary', $env:MSB_PATH, '-PrivateLogDirectory', (Join-Path $privateRoot 'cli')) 300 | Out-Null
    Write-Output 'PASS: Windows CLI lifecycle and bind confinement'

    $stage = 'sdk'
    $output = Invoke-Stage (Join-Path $ArtifactDirectory 'sdk-tests.exe') @('--ignored', '--exact', 'windows_whp_lifecycle_and_bind_confinement', '--test-threads=1') 180
    if ($output -notmatch 'test result: ok\. 1 passed; 0 failed; 0 ignored;') {
        throw 'SDK test did not run successfully'
    }
    Write-Output 'PASS: Windows Rust SDK lifecycle and bind confinement'
    $exitCode = 0
} catch {
    # Do not print the exception: child diagnostics and local paths are private.
    Write-Output ("FAIL: $failureClass stage '$stage'")
} finally {
    foreach ($name in $previous.Keys) {
        [Environment]::SetEnvironmentVariable($name, $previous[$name])
    }
    # The runner lifecycle owns VM and disk destruction, including cancellation.
    # These private logs stay on that disposable disk for local diagnosis only.
}
exit $exitCode
