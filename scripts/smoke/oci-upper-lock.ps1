# Set isolated MSB_HOME and matching MSB_PATH, MSB_AGENTD_PATH, MSB_LIBKRUNFW_PATH
# before invoking this script from the repository root in a Rust build environment.
param(
    [string]$Target = 'aarch64-pc-windows-msvc',
    [string]$Profile = 'ci'
)
$ErrorActionPreference = 'Stop'
foreach ($name in @('MSB_HOME', 'MSB_PATH', 'MSB_AGENTD_PATH', 'MSB_LIBKRUNFW_PATH')) {
    if (-not [Environment]::GetEnvironmentVariable($name)) {
        throw "Set $name before running the live OCI upper qualification"
    }
}

# Cargo contains tests in a kill-on-close Job Object without breakaway permission.
# Build under Cargo, but let PowerShell start the executable outside that Job Object.
$artifacts = & cargo test --locked --profile $Profile --target $Target -p microsandbox `
    --no-default-features --features local,net --test oci_upper_lock_live `
    --no-run --message-format=json
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$executables = @($artifacts | ForEach-Object {
    $artifact = $_ | ConvertFrom-Json
    if ($artifact.reason -eq 'compiler-artifact' -and
        $artifact.target.name -eq 'oci_upper_lock_live' -and $artifact.executable) {
        $artifact.executable
    }
})
if ($executables.Count -ne 1) { throw 'Expected exactly one live test executable' }
& $executables[0] --ignored --nocapture
exit $LASTEXITCODE
