#requires -Version 7.2
[CmdletBinding()]
param([Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$Revision)

$ErrorActionPreference = 'Stop'
$target = 'x86_64-pc-windows-msvc'
$bundle = Join-Path $PWD 'build/windows-whp'
New-Item -ItemType Directory -Force -Path $bundle | Out-Null

function Build-Test {
    param([string]$Name, [string[]]$Arguments)

    $messages = Join-Path $env:TEMP ("windows-whp-build-$Name.jsonl")
    try {
        & cargo +stable test --locked --profile ci --no-run --target $target --message-format=json @Arguments > $messages
        if ($LASTEXITCODE -ne 0) { throw "Could not build $Name tests" }
        $executables = @(Get-Content $messages | ForEach-Object {
            $message = $_ | ConvertFrom-Json
            if ($message.reason -eq 'compiler-artifact' -and $message.profile.test -and $message.executable) {
                $message.executable
            }
        } | Select-Object -Unique)
        if ($executables.Count -ne 1) { throw "Expected one $Name test executable" }
        Copy-Item -LiteralPath $executables[0] -Destination (Join-Path $bundle "$Name.exe")
    } finally {
        Remove-Item -LiteralPath $messages -Force -ErrorAction SilentlyContinue
    }
}

# Disable release downloads: the runtime, firmware, and guest agent must all
# come from the current workflow revision, including on an unreleased branch.
Build-Test 'filesystem-tests' @('-p', 'microsandbox-filesystem', '--lib', '--no-default-features', '--features', 'embed-binaries')
Build-Test 'sdk-tests' @('-p', 'microsandbox', '--test', 'windows_whp', '--no-default-features', '--features', 'local,net,keyring')
Copy-Item build/msb.exe, build/libkrunfw.dll -Destination $bundle
Copy-Item scripts/ci/windows-whp-preflight.ps1, scripts/ci/windows-cli-smoke.ps1, scripts/ci/run-windows-whp-tests.ps1 -Destination $bundle
@{ revision = $Revision } | ConvertTo-Json | Set-Content (Join-Path $bundle 'revision.json')
